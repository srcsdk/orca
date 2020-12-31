#!/usr/bin/env python3
"""network host discovery - arp and ping sweep"""

import argparse
import ipaddress
import json
import platform
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

PLATFORM = platform.system().lower()


def ping_host(ip, timeout=1):
    """check if host responds to icmp echo"""
    try:
        if PLATFORM == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), str(ip)]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), str(ip)]
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def get_mac(ip):
    """get mac address from arp table"""
    try:
        if PLATFORM == "windows":
            cmd = ["arp", "-a", str(ip)]
        elif PLATFORM == "darwin":
            cmd = ["arp", "-n", str(ip)]
        else:
            cmd = ["arp", "-n", str(ip)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        for line in result.stdout.split("\n"):
            if str(ip) in line:
                parts = line.split()
                for part in parts:
                    if _is_mac(part):
                        return part.replace("-", ":")
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def _is_mac(s):
    """check if string looks like a mac address"""
    s = s.replace("-", ":").lower()
    if len(s) != 17:
        return False
    return all(c in "0123456789abcdef:" for c in s)


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
    parser.add_argument("-j", "--json", action="store_true",
                        help="output results as formatted json to stdout")

    args = parser.parse_args()

    if not args.target:
        args.target = _detect_local_subnet()

    if not args.target:
        print("could not determine target network", file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    print(f"scanning {args.target} ({args.threads} threads)...")
    start = time.time()

    results = discover(args.target, args.threads, args.timeout)
    elapsed = time.time() - start

    if args.json:
        data = {
            "target": args.target,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "elapsed": round(elapsed, 2),
            "host_count": len(results),
            "hosts": results
        }
        print(json.dumps(data, indent=2))
    else:
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


def _detect_local_subnet():
    """auto-detect local subnet from system network config"""
    # try ip route (linux)
    if PLATFORM == "linux":
        try:
            result = subprocess.run(
                ["ip", "route"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "default" not in line and "/" in line:
                    return line.split()[0]
        except (subprocess.TimeoutExpired, OSError):
            pass

    # try netstat -rn (macos/bsd)
    if PLATFORM == "darwin":
        try:
            result = subprocess.run(
                ["netstat", "-rn"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "default" in line or "0.0.0.0" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        gw = parts[1]
                        if "." in gw and not gw.startswith("0."):
                            prefix = ".".join(gw.split(".")[:3])
                            return f"{prefix}.0/24"
        except (subprocess.TimeoutExpired, OSError):
            pass

    # try ipconfig (windows)
    if PLATFORM == "windows":
        try:
            result = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=5
            )
            import re
            ips = re.findall(
                r"IPv4.*?:\s*(\d+\.\d+\.\d+\.\d+)", result.stdout
            )
            for ip in ips:
                if not ip.startswith("127."):
                    prefix = ".".join(ip.split(".")[:3])
                    return f"{prefix}.0/24"
        except (subprocess.TimeoutExpired, OSError):
            pass

    # fallback: use socket to get local ip
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        local_ip = s.getsockname()[0]
        s.close()
        prefix = ".".join(local_ip.split(".")[:3])
        return f"{prefix}.0/24"
    except OSError:
        pass

    return None


if __name__ == "__main__":
    main()


def guess_os_from_ttl(ip, timeout=1):
    """guess remote os based on icmp ttl value.

    common defaults:
      linux/unix: 64
      windows: 128
      cisco/network: 255
      solaris: 254
    """
    try:
        if PLATFORM == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), str(ip)]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), str(ip)]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 2
        )
        if result.returncode != 0:
            return None

        for line in result.stdout.split("\n"):
            if "ttl=" in line.lower():
                import re
                match = re.search(r"ttl=(\d+)", line, re.IGNORECASE)
                if match:
                    ttl = int(match.group(1))
                    return classify_ttl(ttl)
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def classify_ttl(ttl):
    """classify os family from ttl value"""
    if ttl <= 64:
        return {"ttl": ttl, "os_hint": "linux/unix", "confidence": "medium"}
    elif ttl <= 128:
        return {"ttl": ttl, "os_hint": "windows", "confidence": "medium"}
    elif ttl <= 254:
        return {"ttl": ttl, "os_hint": "solaris/aix", "confidence": "low"}
    else:
        return {"ttl": ttl, "os_hint": "cisco/network", "confidence": "low"}
