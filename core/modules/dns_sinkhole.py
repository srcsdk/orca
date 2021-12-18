#!/usr/bin/env python3
"""dns sinkhole for blocking malicious domains"""

import os
import json

BLOCKLIST_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "blocklist.json",
)

DEFAULT_BLOCKLIST = [
    "malware.example.com",
    "phishing.example.net",
    "c2server.example.org",
    "tracking.ads.example.com",
]


def load_blocklist():
    """load domain blocklist."""
    if os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE, "r") as f:
            return json.load(f)
    return list(DEFAULT_BLOCKLIST)


def save_blocklist(domains):
    """save domain blocklist."""
    with open(BLOCKLIST_FILE, "w") as f:
        json.dump(sorted(set(domains)), f, indent=2)


def add_domain(domain):
    """add a domain to the blocklist."""
    domains = load_blocklist()
    domain = domain.lower().strip()
    if domain not in domains:
        domains.append(domain)
        save_blocklist(domains)
    return len(domains)


def remove_domain(domain):
    """remove a domain from the blocklist."""
    domains = load_blocklist()
    domain = domain.lower().strip()
    domains = [d for d in domains if d != domain]
    save_blocklist(domains)
    return len(domains)


def is_blocked(domain):
    """check if a domain is in the blocklist."""
    domains = set(load_blocklist())
    domain = domain.lower().strip()
    parts = domain.split(".")
    for i in range(len(parts)):
        check = ".".join(parts[i:])
        if check in domains:
            return True
    return False


def generate_hosts_entries(sinkhole_ip="0.0.0.0"):
    """generate /etc/hosts format entries for blocked domains."""
    domains = load_blocklist()
    lines = ["# orca dns sinkhole blocklist"]
    for domain in sorted(domains):
        lines.append(f"{sinkhole_ip} {domain}")
    return "\n".join(lines)


if __name__ == "__main__":
    domains = load_blocklist()
    print(f"blocklist: {len(domains)} domains")
    test = "malware.example.com"
    print(f"  {test}: {'blocked' if is_blocked(test) else 'allowed'}")
