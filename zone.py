#!/usr/bin/env python3
"""dns reconnaissance and zone analysis"""

import argparse
import json
import platform
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]

# dns record type codes
DNS_TYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15,
    "TXT": 16, "AAAA": 28, "SRV": 33,
}


def _has_command(name):
    """check if a command is available on the system"""
    try:
        subprocess.run(
            ["which", name] if platform.system() != "Windows" else ["where", name],
            capture_output=True, timeout=5
        )
        return True
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        return False


def _build_dns_query(domain, rtype):
    """build a raw dns query packet"""
    tid = struct.pack("!H", 0x1234)
    flags = struct.pack("!H", 0x0100)  # standard query, recursion desired
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    qname = b""
    for label in domain.split("."):
        qname += struct.pack("B", len(label)) + label.encode()
    qname += b"\x00"
    qtype = struct.pack("!H", DNS_TYPES.get(rtype, 1))
    qclass = struct.pack("!H", 1)  # IN class
    return tid + flags + counts + qname + qtype + qclass


def _parse_dns_name(data, offset):
    """parse a dns name from response data handling compression"""
    labels = []
    jumped = False
    original_offset = offset
    max_jumps = 20
    jumps = 0
    while jumps < max_jumps:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            offset = pointer
            jumped = True
            jumps += 1
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    name = ".".join(labels)
    return name, original_offset if jumped else offset


def _parse_dns_response(data, rtype):
    """parse dns response and extract answers"""
    if len(data) < 12:
        return []
    ancount = struct.unpack("!H", data[4:6])[0]
    offset = 12
    # skip question section
    while offset < len(data) and data[offset] != 0:
        if (data[offset] & 0xC0) == 0xC0:
            offset += 2
            break
        offset += data[offset] + 1
    else:
        offset += 1
    offset += 4  # skip qtype and qclass

    results = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        _, offset = _parse_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        atype, aclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength

        type_code = DNS_TYPES.get(rtype, 1)
        if atype == type_code:
            if rtype == "A" and len(rdata) == 4:
                results.append(socket.inet_ntoa(rdata))
            elif rtype == "AAAA" and len(rdata) == 16:
                results.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif rtype == "MX" and len(rdata) > 2:
                pref = struct.unpack("!H", rdata[:2])[0]
                mx_name, _ = _parse_dns_name(data, offset - rdlength + 2)
                results.append(f"{pref} {mx_name}")
            elif rtype in ("NS", "CNAME"):
                name, _ = _parse_dns_name(data, offset - rdlength)
                results.append(name)
            elif rtype == "TXT":
                txt = ""
                pos = 0
                while pos < len(rdata):
                    tlen = rdata[pos]
                    txt += rdata[pos + 1:pos + 1 + tlen].decode("utf-8", errors="replace")
                    pos += 1 + tlen
                results.append(txt)
            elif rtype == "SOA":
                mname, new_off = _parse_dns_name(data, offset - rdlength)
                rname, new_off = _parse_dns_name(data, new_off)
                results.append(f"{mname} {rname}")
    return results


def socket_dns_query(domain, rtype, server="8.8.8.8", timeout=5):
    """query dns using raw udp socket (cross-platform)"""
    try:
        query = _build_dns_query(domain, rtype)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (server, 53))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return _parse_dns_response(data, rtype)
    except (socket.timeout, OSError):
        return []


def dig_query(domain, rtype, server=None, timeout=5, retries=2):
    """query dns records using dig with retry on failure"""
    cmd = ["dig", "+short", "+time={}".format(timeout), domain, rtype]
    if server:
        cmd.insert(1, f"@{server}")

    for attempt in range(retries + 1):
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout + 2
            )
            lines = [line.strip() for line in result.stdout.strip().split("\n")
                     if line.strip()]
            if lines or attempt == retries:
                return lines
            time.sleep(1)
        except (subprocess.TimeoutExpired, OSError):
            if attempt == retries:
                return []
            time.sleep(1)
    return []


def dns_query(domain, rtype, server=None, timeout=5):
    """query dns using best available method for the platform"""
    if _has_command("dig"):
        return dig_query(domain, rtype, server, timeout)
    dns_server = server or "8.8.8.8"
    return socket_dns_query(domain, rtype, dns_server, timeout)


def enumerate_records(domain, server=None):
    """enumerate all dns record types for a domain"""
    records = {}
    for rtype in RECORD_TYPES:
        results = dns_query(domain, rtype, server)
        if results:
            records[rtype] = results
    return records


def attempt_zone_transfer(domain, nameserver):
    """try axfr zone transfer"""
    try:
        result = subprocess.run(
            ["dig", f"@{nameserver}", domain, "AXFR", "+time=10"],
            capture_output=True, text=True, timeout=15
        )
        if "Transfer failed" in result.stdout or "REFUSED" in result.stdout:
            return None
        lines = result.stdout.strip().split("\n")
        records = [line for line in lines if line and not line.startswith(";")]
        return records if records else None
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        return None


def reverse_lookup(ip):
    """reverse dns lookup"""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def brute_subdomains(domain, wordlist, threads=20, server=None):
    """brute force subdomain discovery"""
    found = []

    def check_subdomain(sub):
        fqdn = f"{sub}.{domain}"
        results = dns_query(fqdn, "A", server, timeout=3)
        if results:
            return fqdn, results
        return None, None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(check_subdomain, word): word
            for word in wordlist
        }
        for future in as_completed(futures):
            fqdn, ips = future.result()
            if fqdn:
                found.append({"subdomain": fqdn, "ips": ips})
                print(f"  {fqdn} -> {', '.join(ips)}")

    return found


def load_wordlist(filename):
    """load subdomain wordlist"""
    try:
        with open(filename, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []


def whois_lookup(domain):
    """basic whois information (requires whois command)"""
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=10
        )
        info = {}
        for line in result.stdout.split("\n"):
            line = line.strip()
            for field in ["Registrar:", "Creation Date:", "Updated Date:",
                          "Name Server:", "DNSSEC:"]:
                if line.startswith(field):
                    key = field.rstrip(":").lower().replace(" ", "_")
                    value = line.split(":", 1)[1].strip()
                    if key in info:
                        if isinstance(info[key], list):
                            info[key].append(value)
                        else:
                            info[key] = [info[key], value]
                    else:
                        info[key] = value
        return info
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        return {}


def socket_whois(domain):
    """whois lookup using raw socket (cross-platform fallback)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("whois.iana.org", 43))
        sock.sendall((domain + "\r\n").encode())
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        text = response.decode("utf-8", errors="replace")

        # find the registrar whois server and query it
        for line in text.split("\n"):
            if line.lower().startswith("refer:"):
                whois_server = line.split(":", 1)[1].strip()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((whois_server, 43))
                sock.sendall((domain + "\r\n").encode())
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                sock.close()
                text = response.decode("utf-8", errors="replace")
                break

        info = {}
        for line in text.split("\n"):
            line = line.strip()
            for field in ["Registrar:", "Creation Date:", "Updated Date:",
                          "Name Server:", "DNSSEC:"]:
                if line.startswith(field):
                    key = field.rstrip(":").lower().replace(" ", "_")
                    value = line.split(":", 1)[1].strip()
                    if key in info:
                        if isinstance(info[key], list):
                            info[key].append(value)
                        else:
                            info[key] = [info[key], value]
                    else:
                        info[key] = value
        return info
    except (socket.timeout, OSError):
        return {}


def do_whois(domain):
    """whois lookup using best available method"""
    if _has_command("whois"):
        return whois_lookup(domain)
    return socket_whois(domain)


def default_scan():
    """run a default dns scan on localhost"""
    print("no domain specified, running local dns reconnaissance")
    print(f"platform: {platform.system()}\n")

    hostname = socket.gethostname()
    print(f"hostname: {hostname}")

    try:
        local_ip = socket.gethostbyname(hostname)
        print(f"local ip: {local_ip}")
    except socket.gaierror:
        local_ip = "127.0.0.1"
        print(f"local ip: {local_ip} (fallback)")

    reverse = reverse_lookup(local_ip)
    if reverse:
        print(f"reverse dns: {reverse}")

    print("\nresolving common dns servers...")
    test_domains = ["dns.google", "one.one.one.one", "resolver1.opendns.com"]
    for domain in test_domains:
        try:
            ip = socket.gethostbyname(domain)
            print(f"  {domain} -> {ip}")
        except socket.gaierror:
            print(f"  {domain} -> unresolvable")

    print("\nlocal dns resolution test:")
    test_hosts = ["localhost", "google.com", "github.com"]
    for host in test_hosts:
        try:
            ip = socket.gethostbyname(host)
            print(f"  {host} -> {ip}")
        except socket.gaierror:
            print(f"  {host} -> failed")


def main():
    parser = argparse.ArgumentParser(description="dns reconnaissance")
    parser.add_argument("domain", nargs="?", default=None,
                        help="target domain (default: local dns scan)")
    parser.add_argument("-s", "--server", type=str,
                        help="dns server to query")
    parser.add_argument("-w", "--wordlist", type=str,
                        help="subdomain wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=20,
                        help="threads for subdomain brute force")
    parser.add_argument("--axfr", action="store_true",
                        help="attempt zone transfer")
    parser.add_argument("--whois", action="store_true",
                        help="whois lookup")
    parser.add_argument("-o", "--output", type=str,
                        help="save results to json")

    args = parser.parse_args()

    if args.domain is None:
        default_scan()
        sys.exit(0)

    # reduce threads on windows
    if platform.system() == "Windows":
        args.threads = min(args.threads, 15)

    results = {"domain": args.domain, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")}

    # enumerate dns records
    print(f"enumerating dns records for {args.domain}...\n")
    records = enumerate_records(args.domain, args.server)
    results["records"] = records

    for rtype, values in records.items():
        print(f"  {rtype}:")
        for v in values:
            print(f"    {v}")

    # zone transfer
    if args.axfr and "NS" in records:
        if not _has_command("dig"):
            print("\nzone transfer requires dig (not available on this platform)")
        else:
            print("\nattempting zone transfers...")
            for ns in records["NS"]:
                ns = ns.rstrip(".")
                print(f"  trying {ns}...")
                zone = attempt_zone_transfer(args.domain, ns)
                if zone:
                    print(f"  zone transfer successful from {ns}!")
                    results["zone_transfer"] = {"server": ns, "records": zone}
                    for line in zone[:20]:
                        print(f"    {line}")
                    break
                else:
                    print("  failed (transfer refused or timeout)")

    # subdomain brute force
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        if not wordlist:
            wordlist = [
                "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2",
                "webmail", "remote", "admin", "blog", "dev", "staging",
                "api", "app", "cdn", "vpn", "test", "portal", "git",
            ]
        print(f"\nbrute forcing subdomains ({len(wordlist)} words)...")
        subdomains = brute_subdomains(
            args.domain, wordlist, args.threads, args.server
        )
        results["subdomains"] = subdomains
        print(f"\n{len(subdomains)} subdomains found")

    # whois
    if args.whois:
        print(f"\nwhois {args.domain}:")
        info = do_whois(args.domain)
        results["whois"] = info
        for k, v in info.items():
            print(f"  {k}: {v}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nsaved to {args.output}")


if __name__ == "__main__":
    main()


def export_dns_csv(records, filename):
    """export dns records to csv file"""
    import csv
    if not records:
        return
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "name", "value", "ttl"])
        for rec in records:
            writer.writerow([
                rec.get("type", ""),
                rec.get("name", ""),
                rec.get("value", ""),
                rec.get("ttl", ""),
            ])
    print(f"exported {len(records)} records to {filename}")
