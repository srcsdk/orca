#!/usr/bin/env python3
"""dns reconnaissance and zone analysis"""

import argparse
import json
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]


def dig_query(domain, rtype, server=None, timeout=5):
    """query dns records using dig"""
    cmd = ["dig", "+short", "+time={}".format(timeout), domain, rtype]
    if server:
        cmd.insert(1, f"@{server}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 2
        )
        lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
        return lines
    except (subprocess.TimeoutExpired, OSError):
        return []


def enumerate_records(domain, server=None):
    """enumerate all dns record types for a domain"""
    records = {}
    for rtype in RECORD_TYPES:
        results = dig_query(domain, rtype, server)
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
        records = [l for l in lines if l and not l.startswith(";")]
        return records if records else None
    except (subprocess.TimeoutExpired, OSError):
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
        results = dig_query(fqdn, "A", server, timeout=3)
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
    """basic whois information"""
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
    except (subprocess.TimeoutExpired, OSError):
        return {}


def main():
    parser = argparse.ArgumentParser(description="dns reconnaissance")
    parser.add_argument("domain", help="target domain")
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
                print(f"  failed (transfer refused or timeout)")

    # subdomain brute force
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        if not wordlist:
            # default minimal wordlist
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
        info = whois_lookup(args.domain)
        results["whois"] = info
        for k, v in info.items():
            print(f"  {k}: {v}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nsaved to {args.output}")


if __name__ == "__main__":
    main()
