#!/usr/bin/env python3
"""arp spoofing detector with mac validation"""

import subprocess
import re
import time
from collections import defaultdict


def get_arp_table():
    """read current arp table from system."""
    try:
        result = subprocess.run(
            ["arp", "-n"], capture_output=True, text=True, timeout=5,
        )
        entries = []
        for line in result.stdout.split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 3:
                entries.append({
                    "ip": parts[0],
                    "mac": parts[2] if len(parts) > 2 else "",
                    "interface": parts[-1] if parts else "",
                })
        return entries
    except (subprocess.TimeoutExpired, OSError):
        return []


def build_mac_ip_map(entries):
    """build mapping of mac addresses to ip addresses."""
    mac_to_ips = defaultdict(set)
    ip_to_mac = {}
    for entry in entries:
        mac = entry.get("mac", "")
        ip = entry.get("ip", "")
        if mac and ip and mac != "(incomplete)":
            mac_to_ips[mac].add(ip)
            ip_to_mac[ip] = mac
    return mac_to_ips, ip_to_mac


def detect_spoofing(mac_to_ips, known_bindings=None):
    """detect potential arp spoofing.

    a mac address serving multiple ips may indicate spoofing.
    """
    alerts = []
    for mac, ips in mac_to_ips.items():
        if len(ips) > 2:
            alerts.append({
                "type": "multiple_ips",
                "mac": mac,
                "ips": sorted(ips),
                "severity": "high",
                "message": f"mac {mac} has {len(ips)} associated ips",
            })
    if known_bindings:
        entries = get_arp_table()
        _, ip_to_mac = build_mac_ip_map(entries)
        for ip, expected_mac in known_bindings.items():
            actual_mac = ip_to_mac.get(ip)
            if actual_mac and actual_mac != expected_mac:
                alerts.append({
                    "type": "mac_mismatch",
                    "ip": ip,
                    "expected": expected_mac,
                    "actual": actual_mac,
                    "severity": "critical",
                })
    return alerts


def monitor(interval=30, duration=300):
    """monitor arp table for changes over time."""
    start = time.time()
    baseline_entries = get_arp_table()
    baseline_map, _ = build_mac_ip_map(baseline_entries)
    changes = []
    while time.time() - start < duration:
        time.sleep(interval)
        current = get_arp_table()
        current_map, _ = build_mac_ip_map(current)
        alerts = detect_spoofing(current_map)
        if alerts:
            changes.extend(alerts)
    return changes


if __name__ == "__main__":
    entries = get_arp_table()
    print(f"arp entries: {len(entries)}")
    mac_map, _ = build_mac_ip_map(entries)
    alerts = detect_spoofing(mac_map)
    if alerts:
        for a in alerts:
            print(f"  [{a['severity']}] {a['message']}")
    else:
        print("  no spoofing detected")
