#!/usr/bin/env python3
__version__ = "1.1.0"
"""vulnerability scanner - correlate services with cve database"""

import argparse
import json
import platform
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# known vulnerable versions (simplified local db)
VULN_DB = {
    "openssh": {
        "7.4": ["CVE-2017-15906", "CVE-2018-15473"],
        "7.6": ["CVE-2018-15473"],
        "8.0": ["CVE-2019-6111"],
        "8.2": ["CVE-2020-14145"],
        "8.3": ["CVE-2020-14145"],
    },
    "apache": {
        "2.4.29": ["CVE-2018-1312", "CVE-2017-15715"],
        "2.4.41": ["CVE-2020-1934", "CVE-2020-1927"],
        "2.4.46": ["CVE-2020-11984"],
        "2.4.49": ["CVE-2021-41773", "CVE-2021-42013"],
        "2.4.50": ["CVE-2021-42013"],
    },
    "nginx": {
        "1.14.0": ["CVE-2018-16843", "CVE-2018-16844"],
        "1.16.0": ["CVE-2019-9511", "CVE-2019-9513"],
        "1.17.0": ["CVE-2019-9511"],
    },
    "vsftpd": {
        "2.3.4": ["CVE-2011-2523"],
        "3.0.2": ["CVE-2015-1419"],
    },
    "proftpd": {
        "1.3.5": ["CVE-2015-3306"],
    },
}

# cve severity reference (simplified)
CVE_SEVERITY = {
    "CVE-2021-41773": {"score": 7.5, "severity": "high",
                       "desc": "path traversal in apache 2.4.49"},
    "CVE-2021-42013": {"score": 9.8, "severity": "critical",
                       "desc": "rce via path traversal in apache 2.4.49/50"},
    "CVE-2018-15473": {"score": 5.3, "severity": "medium",
                       "desc": "openssh user enumeration"},
    "CVE-2020-14145": {"score": 5.9, "severity": "medium",
                       "desc": "openssh mitm vulnerability"},
    "CVE-2011-2523": {"score": 10.0, "severity": "critical",
                      "desc": "vsftpd 2.3.4 backdoor command execution"},
    "CVE-2019-9511": {"score": 7.5, "severity": "high",
                      "desc": "http/2 dos via data dribble"},
}


def grab_banner(host, port, timeout=3):
    """get service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        sock.settimeout(2)
        try:
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            if banner:
                sock.close()
                return banner
        except socket.timeout:
            pass

        if port in (80, 8080, 8000, 8888):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            resp = sock.recv(4096).decode("utf-8", errors="replace")
            sock.close()
            return resp

        sock.close()
        return None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def get_ssl_version(host, port, timeout=3):
    """get tls version and cipher"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        wrapped = ctx.wrap_socket(sock, server_hostname=host)
        wrapped.connect((host, port))
        version = wrapped.version()
        cipher = wrapped.cipher()
        wrapped.close()
        return {"version": version, "cipher": cipher[0] if cipher else None}
    except (ssl.SSLError, socket.timeout, OSError):
        return None


def parse_version(banner):
    """extract product and version from banner"""
    patterns = [
        (r"OpenSSH[_\s]([\d.p]+)", "openssh"),
        (r"Apache/([\d.]+)", "apache"),
        (r"nginx/([\d.]+)", "nginx"),
        (r"vsftpd\s+([\d.]+)", "vsftpd"),
        (r"ProFTPD\s+([\d.]+)", "proftpd"),
        (r"Server:\s*Apache/([\d.]+)", "apache"),
        (r"Server:\s*nginx/([\d.]+)", "nginx"),
    ]
    for pattern, product in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return product, match.group(1)
    return None, None


def check_vulns(product, version):
    """check version against local vulnerability database"""
    if not product or not version:
        return []

    product = product.lower()
    if product not in VULN_DB:
        return []

    # check exact and partial version matches
    vulns = []
    base_version = ".".join(version.split(".")[:3])

    for vuln_ver, cves in VULN_DB[product].items():
        if version.startswith(vuln_ver) or base_version == vuln_ver:
            for cve_id in cves:
                info = CVE_SEVERITY.get(cve_id, {})
                vulns.append({
                    "cve": cve_id,
                    "score": info.get("score", 0),
                    "severity": info.get("severity", "unknown"),
                    "description": info.get("desc", ""),
                })

    return vulns


def scan_target(host, port, timeout=3):
    """scan a single port for vulnerabilities"""
    result = {
        "port": port,
        "service": None,
        "product": None,
        "version": None,
        "banner": None,
        "tls": None,
        "vulns": [],
    }

    try:
        result["service"] = socket.getservbyport(port, "tcp")
    except OSError:
        result["service"] = "unknown"

    banner = grab_banner(host, port, timeout)
    if banner:
        result["banner"] = banner[:200]
        product, version = parse_version(banner)
        result["product"] = product
        result["version"] = version
        result["vulns"] = check_vulns(product, version)

    if port in (443, 8443):
        result["tls"] = get_ssl_version(host, port, timeout)

    return result


def scan(host, ports, threads=20, timeout=3):
    """scan all ports for vulnerabilities"""
    results = []

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(scan_target, host, p, timeout): p
            for p in ports
        }
        for future in as_completed(futures):
            result = future.result()
            if result["banner"] or result["vulns"]:
                results.append(result)

    results.sort(key=lambda r: r["port"])
    return results


def print_results(host, results):
    """display scan results"""
    total_vulns = sum(len(r["vulns"]) for r in results)

    print(f"\n{'port':<8} {'service':<12} {'product':<20} {'vulns'}")
    print("-" * 65)

    for r in results:
        product_str = ""
        if r["product"]:
            product_str = f"{r['product']}/{r['version'] or '?'}"

        vuln_str = ""
        if r["vulns"]:
            severities = [v["severity"] for v in r["vulns"]]
            vuln_str = f"{len(r['vulns'])} ({', '.join(set(severities))})"

        print(f"{r['port']:<8} {r['service'] or 'unknown':<12} "
              f"{product_str:<20} {vuln_str}")

    if total_vulns > 0:
        print("\n--- vulnerabilities ---")
        for r in results:
            for v in r["vulns"]:
                sev = v["severity"].upper()
                print(f"  [{sev}] {v['cve']} (CVSS {v['score']})")
                print(f"    {r['port']}/{r['service']}: {v['description']}")

    print(f"\n{len(results)} services, {total_vulns} vulnerabilities on {host}")


def main():
    parser = argparse.ArgumentParser(description="vulnerability scanner")
    parser.add_argument("host", nargs="?", default=None,
                        help="target host (default: localhost)")
    parser.add_argument("-p", "--ports", type=str,
                        default="21,22,25,80,443,8080,8443",
                        help="ports to scan")
    parser.add_argument("-t", "--threads", type=int, default=20)
    parser.add_argument("-T", "--timeout", type=float, default=3)
    parser.add_argument("-o", "--output", type=str,
                        help="save results to json")

    args = parser.parse_args()

    if args.host is None:
        args.host = "127.0.0.1"
        print("no target specified, scanning localhost services")

    # reduce threads on windows
    if platform.system() == "Windows":
        args.threads = min(args.threads, 15)

    ports = []
    for part in args.ports.split(","):
        if "-" in part:
            s, e = part.split("-")
            ports.extend(range(int(s), int(e) + 1))
        else:
            ports.append(int(part))

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"could not resolve {args.host}", file=sys.stderr)
        sys.exit(1)

    print(f"scanning {args.host} ({ip}) for vulnerabilities...")
    start = time.time()
    results = scan(ip, ports, args.threads, args.timeout)
    elapsed = time.time() - start

    print_results(args.host, results)
    print(f"completed in {elapsed:.1f}s")

    if args.output:
        with open(args.output, "w") as f:
            json.dump({
                "host": args.host,
                "ip": ip,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "results": results,
            }, f, indent=2)
        print(f"saved to {args.output}")


if __name__ == "__main__":
    main()
