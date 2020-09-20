#!/usr/bin/env python3
"""tcp/udp port scanner with service detection"""

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

TOP_100 = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110,
    111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444,
    445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873,
    990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720,
    1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306,
    3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432,
    5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009,
    8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153,
    49154, 49155, 49156, 49157,
]


def get_service(port, proto="tcp"):
    """lookup service name for a port"""
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return None


def check_tcp(host, port, timeout=1):
    """check if a tcp port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except OSError:
        return False


def check_udp(host, port, timeout=2):
    """check if a udp port is open (unreliable without probes)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x00", (host, port))
        try:
            sock.recvfrom(1024)
            return True
        except socket.timeout:
            return True  # no response could mean open|filtered
    except OSError:
        return False
    finally:
        sock.close()


def grab_banner(host, port, timeout=2):
    """try to grab service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # some services send banner immediately
        sock.settimeout(1)
        try:
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            if banner:
                sock.close()
                return banner
        except socket.timeout:
            pass

        # try http probe
        if port in (80, 8080, 8000, 8443, 443):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            sock.close()
            for line in banner.split("\r\n"):
                if line.lower().startswith("server:"):
                    return line
            return banner.split("\r\n")[0] if banner else None

        sock.close()
        return None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_port(host, port, proto="tcp", timeout=1, banner=False):
    """scan a single port and return result"""
    if proto == "udp":
        is_open = check_udp(host, port, timeout)
    else:
        is_open = check_tcp(host, port, timeout)

    if not is_open:
        return None

    service = get_service(port, proto)
    result = {
        "port": port,
        "proto": proto,
        "state": "open",
        "service": service or "unknown",
    }

    if banner and proto == "tcp":
        result["banner"] = grab_banner(host, port, timeout)

    return result


def scan(host, ports, proto="tcp", threads=100, timeout=1, banner=False):
    """scan multiple ports concurrently"""
    results = []

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(scan_port, host, p, proto, timeout, banner): p
            for p in ports
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    results.sort(key=lambda r: r["port"])
    return results


def print_results(host, results):
    """display scan results"""
    print(f"\n{'port':<12} {'state':<10} {'service':<16} {'banner'}")
    print("-" * 60)

    for r in results:
        banner = (r.get("banner") or "")[:40]
        print(f"{r['port']}/{r['proto']:<8} {r['state']:<10} "
              f"{r['service']:<16} {banner}")

    print(f"\n{len(results)} open ports on {host}")


def main():
    parser = argparse.ArgumentParser(description="tcp/udp port scanner")
    parser.add_argument("host", help="target host or ip")
    parser.add_argument("start", nargs="?", type=int, default=1,
                        help="start port (default: 1)")
    parser.add_argument("end", nargs="?", type=int, default=1024,
                        help="end port (default: 1024)")
    parser.add_argument("-u", "--udp", action="store_true",
                        help="udp scan")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="threads (default: 100)")
    parser.add_argument("-T", "--top", type=int, choices=[100, 1000],
                        help="scan top N ports")
    parser.add_argument("-b", "--banner", action="store_true",
                        help="grab service banners")
    parser.add_argument("-o", "--output", type=str,
                        help="save results to json file")
    parser.add_argument("--timeout", type=float, default=1,
                        help="timeout per port (default: 1)")
    parser.add_argument("--slow", action="store_true",
                        help="slow host mode: higher timeouts and fewer threads")

    args = parser.parse_args()

    if args.slow:
        args.timeout = max(args.timeout, 3)
        args.threads = min(args.threads, 20)

    # resolve hostname
    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"could not resolve {args.host}", file=sys.stderr)
        sys.exit(1)

    proto = "udp" if args.udp else "tcp"

    if args.top == 100:
        ports = TOP_100
    elif args.top == 1000:
        ports = list(range(1, 1001))
    else:
        ports = list(range(args.start, args.end + 1))

    print(f"scanning {args.host} ({ip}) - {proto}, "
          f"{len(ports)} ports, {args.threads} threads")

    start = time.time()
    results = scan(ip, ports, proto, args.threads, args.timeout, args.banner)
    elapsed = time.time() - start

    print_results(args.host, results)
    print(f"completed in {elapsed:.1f}s")

    if args.output:
        data = {
            "host": args.host,
            "ip": ip,
            "proto": proto,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "elapsed": round(elapsed, 2),
            "ports": results,
        }
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2)
        print(f"saved to {args.output}")


if __name__ == "__main__":
    main()
