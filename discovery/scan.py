#!/usr/bin/env python3
"""network host discovery - arp and ping sweep"""

import argparse
import ipaddress
import json
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def ping_host(ip, timeout=1):
    """check if host responds to icmp echo"""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), str(ip)],
            capture_output=True, timeout=timeout + 1
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def get_mac(ip):
    """get mac address from arp table"""
    try:
        result = subprocess.run(
            ["arp", "-n", str(ip)],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            if str(ip) in line:
                parts = line.split()
                if len(parts) >= 3 and ":" in parts[2]:
                    return parts[2]
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def resolve_hostname(ip):
    """reverse dns lookup"""
    try:
        hostname, _, _ = socket.gethostbyaddr(str(ip))
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def get_oui_vendor(mac):
    """lookup vendor from mac oui prefix"""
    if not mac:
        return None
    oui_map = {
        "00:50:56": "vmware",
        "00:0c:29": "vmware",
        "08:00:27": "virtualbox",
        "52:54:00": "qemu/kvm",
        "dc:a6:32": "raspberry pi",
        "b8:27:eb": "raspberry pi",
    }
    prefix = mac[:8].lower()
    return oui_map.get(prefix)


def scan_host(ip, timeout=1):
    """scan a single host and gather info"""
    if not ping_host(ip, timeout):
        return None

    mac = get_mac(ip)
    hostname = resolve_hostname(ip)
    vendor = get_oui_vendor(mac)

    return {
        "ip": str(ip),
        "mac": mac or "unknown",
        "hostname": hostname,
        "vendor": vendor,
    }


def discover(target, threads=50, timeout=1):
    """discover all live hosts on a network"""
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as e:
        print(f"invalid target: {e}", file=sys.stderr)
        return []

    hosts = list(network.hosts())
    results = []

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(scan_host, ip, timeout): ip
            for ip in hosts
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    results.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    return results


def print_results(results, verbose=False):
    """display scan results"""
    print(f"\n{'ip':<16} {'mac':<18} {'hostname':<30} {'vendor'}")
    print("-" * 75)

    for host in results:
        hostname = host["hostname"] or "-"
        vendor = host["vendor"] or ""
        print(f"{host['ip']:<16} {host['mac']:<18} {hostname:<30} {vendor}")

    print(f"\n{len(results)} hosts found")


def main():
    parser = argparse.ArgumentParser(
        description="network host discovery"
    )
    parser.add_argument("target", nargs="?", default=None,
                        help="target network (cidr notation)")
    parser.add_argument("-t", "--threads", type=int, default=50,
                        help="number of threads (default: 50)")
    parser.add_argument("-T", "--timeout", type=float, default=1,
                        help="ping timeout in seconds (default: 1)")
    parser.add_argument("-o", "--output", type=str,
                        help="save results to json file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="verbose output")

    args = parser.parse_args()

    if not args.target:
        try:
            result = subprocess.run(
                ["ip", "route"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "default" not in line and "/" in line:
                    args.target = line.split()[0]
                    break
        except (subprocess.TimeoutExpired, OSError):
            pass

    if not args.target:
        print("could not determine target network", file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    print(f"scanning {args.target} ({args.threads} threads)...")
    start = time.time()

    results = discover(args.target, args.threads, args.timeout)
    elapsed = time.time() - start

    print_results(results, args.verbose)
    print(f"completed in {elapsed:.1f}s")

    if args.output:
        data = {
            "target": args.target,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "elapsed": round(elapsed, 2),
            "hosts": results
        }
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2)
        print(f"saved to {args.output}")


if __name__ == "__main__":
    main()
