#!/usr/bin/env python3
"""monitor log files for security events and anomalies"""

import os
import re
from collections import defaultdict


def tail_file(filepath, lines=100):
    """read last n lines from a file efficiently."""
    if not os.path.isfile(filepath):
        return []
    with open(filepath, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        block = min(size, 8192)
        f.seek(-block, 2)
        data = f.read().decode("utf-8", errors="replace")
    return data.splitlines()[-lines:]


def parse_auth_log(lines):
    """extract failed login attempts from auth log."""
    failed = []
    pattern = re.compile(
        r"Failed password for (?:invalid user )?(\S+) from (\S+)"
    )
    for line in lines:
        match = pattern.search(line)
        if match:
            failed.append({
                "user": match.group(1),
                "ip": match.group(2),
                "line": line.strip(),
            })
    return failed


def detect_brute_force(failed_attempts, threshold=5):
    """detect brute force attempts by ip frequency."""
    ip_counts = defaultdict(int)
    for attempt in failed_attempts:
        ip_counts[attempt["ip"]] += 1
    flagged = {
        ip: count for ip, count in ip_counts.items()
        if count >= threshold
    }
    return flagged


def scan_for_patterns(lines, patterns=None):
    """scan log lines for suspicious patterns."""
    if patterns is None:
        patterns = [
            r"POSSIBLE BREAK-IN ATTEMPT",
            r"segfault",
            r"error.*permission denied",
            r"unauthorized",
            r"SQL.*injection",
        ]
    findings = []
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
    for line in lines:
        for pat in compiled:
            if pat.search(line):
                findings.append({
                    "pattern": pat.pattern,
                    "line": line.strip(),
                })
                break
    return findings


def monitor_summary(log_path="/var/log/auth.log"):
    """generate summary of security events from log file."""
    lines = tail_file(log_path, 500)
    failed = parse_auth_log(lines)
    brute = detect_brute_force(failed)
    suspicious = scan_for_patterns(lines)
    return {
        "total_lines": len(lines),
        "failed_logins": len(failed),
        "brute_force_ips": brute,
        "suspicious_events": len(suspicious),
        "details": suspicious[:10],
    }


if __name__ == "__main__":
    sample = [
        "Mar  4 10:01:00 server sshd: Failed password for root from 192.168.1.100",
        "Mar  4 10:01:05 server sshd: Failed password for root from 192.168.1.100",
        "Mar  4 10:01:10 server sshd: Failed password for root from 192.168.1.100",
        "Mar  4 10:01:15 server sshd: Failed password for admin from 192.168.1.100",
        "Mar  4 10:01:20 server sshd: Failed password for root from 192.168.1.100",
        "Mar  4 10:01:25 server sshd: Failed password for root from 192.168.1.100",
        "Mar  4 10:02:00 server sshd: Accepted password for collin from 10.0.0.1",
    ]
    failed = parse_auth_log(sample)
    print(f"failed attempts: {len(failed)}")
    brute = detect_brute_force(failed)
    print(f"brute force ips: {brute}")
