#!/usr/bin/env python3
"""data loss prevention engine with pattern matching and anomaly detection"""

import argparse
import json
import math
import os
import re
import socket
import struct
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


SENSITIVE_PATTERNS = {
    "credit_card": re.compile(
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?'
        r'|5[1-5][0-9]{14}'
        r'|3[47][0-9]{13}'
        r'|6(?:011|5[0-9]{2})[0-9]{12})\b'
    ),
    "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "api_key": re.compile(
        r'\b(?:sk|pk|api|key|token|secret)[_-]?[a-zA-Z0-9]{20,}\b', re.IGNORECASE
    ),
    "aws_key": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    "private_key": re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    "email_bulk": re.compile(
        r'(?:\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b.*){3,}'
    ),
    "ip_list": re.compile(
        r'(?:\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b.*){5,}'
    ),
}


def calculate_entropy(data):
    """calculate shannon entropy of byte data"""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
    return entropy


def luhn_check(number_str):
    """validate credit card number with luhn algorithm"""
    digits = [int(d) for d in number_str if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class DlpAlert:
    def __init__(self, severity, category, message, source="", evidence=""):
        self.severity = severity
        self.category = category
        self.message = message
        self.source = source
        self.evidence = evidence[:200]
        self.timestamp = datetime.now()

    def to_dict(self):
        return {
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "source": self.source,
            "evidence": self.evidence,
        }


class DlpEngine:
    def __init__(self, entropy_threshold=6.5, volume_threshold_mb=100):
        self.entropy_threshold = entropy_threshold
        self.volume_threshold = volume_threshold_mb * 1024 * 1024
        self.alerts = []
        self.dns_cache = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {"bytes": 0, "packets": 0, "first": None})

    def add_alert(self, severity, category, message, source="", evidence=""):
        alert = DlpAlert(severity, category, message, source, evidence)
        self.alerts.append(alert)
        return alert

    def scan_content(self, data, source="unknown"):
        """scan content for sensitive data patterns"""
        if isinstance(data, bytes):
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                text = str(data)
        else:
            text = data

        for pattern_name, pattern in SENSITIVE_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                if pattern_name == "credit_card":
                    valid = [m for m in matches if luhn_check(m)]
                    if valid:
                        self.add_alert(
                            "critical", "sensitive_data",
                            f"valid credit card numbers detected: {len(valid)} matches",
                            source, f"pattern: {valid[0][:6]}******"
                        )
                else:
                    self.add_alert(
                        "high", "sensitive_data",
                        f"{pattern_name} pattern detected: {len(matches)} matches",
                        source, f"sample: {matches[0][:30]}..."
                    )

    def analyze_entropy(self, data, source="unknown"):
        """check for high-entropy data indicating encryption or encoding"""
        if len(data) < 64:
            return

        entropy = calculate_entropy(data if isinstance(data, bytes) else data.encode())

        if entropy > self.entropy_threshold:
            self.add_alert(
                "high", "entropy",
                f"high entropy data detected ({entropy:.2f} bits/byte)",
                source, f"size: {len(data)} bytes"
            )

        # check for base64 encoded blocks
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{64,}={0,2}')
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        b64_matches = b64_pattern.findall(text)
        if b64_matches:
            total_b64 = sum(len(m) for m in b64_matches)
            if total_b64 > 256:
                self.add_alert(
                    "medium", "encoding",
                    f"large base64 blocks detected: {total_b64} chars in {len(b64_matches)} blocks",
                    source
                )

    def monitor_dns(self, query, source_ip="unknown"):
        """analyze dns query for tunneling indicators"""
        now = datetime.now()
        self.dns_cache[source_ip].append({"query": query, "time": now})

        # prune old entries
        cutoff = now - timedelta(seconds=60)
        self.dns_cache[source_ip] = [
            e for e in self.dns_cache[source_ip] if e["time"] > cutoff
        ]

        # check query rate
        rate = len(self.dns_cache[source_ip])
        if rate > 50:
            self.add_alert(
                "high", "dns_tunnel",
                f"high dns query rate: {rate} queries/min from {source_ip}",
                source_ip
            )

        # check subdomain length (tunneling indicator)
        parts = query.split(".")
        if parts:
            longest_label = max(len(p) for p in parts)
            if longest_label > 30:
                self.add_alert(
                    "high", "dns_tunnel",
                    f"long dns label ({longest_label} chars) possible tunnel: {query[:60]}",
                    source_ip
                )

        # check entropy of subdomain
        if len(parts) > 2:
            subdomain = ".".join(parts[:-2])
            ent = calculate_entropy(subdomain.encode())
            if ent > 4.0 and len(subdomain) > 20:
                self.add_alert(
                    "medium", "dns_tunnel",
                    f"high entropy dns subdomain ({ent:.1f}): {subdomain[:40]}",
                    source_ip
                )

    def check_volume(self, interface="eth0"):
        """check network interface for volumetric anomalies"""
        stats_path = Path(f"/sys/class/net/{interface}/statistics")
        if not stats_path.exists():
            return

        try:
            tx_bytes = int((stats_path / "tx_bytes").read_text().strip())
            rx_bytes = int((stats_path / "rx_bytes").read_text().strip())
            tx_packets = int((stats_path / "tx_packets").read_text().strip())
        except (ValueError, FileNotFoundError):
            return

        if tx_bytes > self.volume_threshold:
            tx_mb = tx_bytes / (1024 * 1024)
            self.add_alert(
                "medium", "volume",
                f"high outbound volume on {interface}: {tx_mb:.0f}MB",
                interface
            )

        if tx_packets > 0 and tx_bytes / tx_packets > 1400:
            self.add_alert(
                "low", "volume",
                f"large average packet size on {interface}: {tx_bytes / tx_packets:.0f} bytes",
                interface
            )

        tx_rx_ratio = tx_bytes / max(rx_bytes, 1)
        if tx_rx_ratio > 5:
            self.add_alert(
                "high", "volume",
                f"unusual tx/rx ratio on {interface}: {tx_rx_ratio:.1f}",
                interface
            )

    def scan_file(self, filepath):
        """scan a file for sensitive data and encoding"""
        path = Path(filepath)
        if not path.exists():
            return

        try:
            data = path.read_bytes()
        except PermissionError:
            return

        source = path.name
        self.scan_content(data, source)
        self.analyze_entropy(data, source)

    def scan_processes(self):
        """check running processes for suspicious data handling"""
        proc = Path("/proc")
        if not proc.exists():
            return

        for pid_dir in proc.iterdir():
            if not pid_dir.name.isdigit():
                continue
            try:
                cmdline = (pid_dir / "cmdline").read_bytes().replace(b"\x00", b" ").decode(
                    errors="replace"
                )
                if len(cmdline) > 100:
                    self.analyze_entropy(cmdline.encode(), f"pid:{pid_dir.name}")
                    self.scan_content(cmdline, f"pid:{pid_dir.name}")
            except (PermissionError, FileNotFoundError):
                continue

    def get_report(self):
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_alerts = sorted(
            self.alerts,
            key=lambda a: severity_order.get(a.severity, 4)
        )
        return {
            "timestamp": datetime.now().isoformat(),
            "total_alerts": len(self.alerts),
            "severity_counts": {
                s: sum(1 for a in self.alerts if a.severity == s)
                for s in severity_order
            },
            "alerts": [a.to_dict() for a in sorted_alerts],
        }


def print_report(report, as_json=False):
    if as_json:
        print(json.dumps(report, indent=2))
        return

    print(f"\n[tropy] dlp scan results")
    print(f"total alerts: {report['total_alerts']}")
    print(f"severity: {report['severity_counts']}")
    print()

    for alert in report["alerts"]:
        sev = alert["severity"].upper().ljust(8)
        print(f"  [{sev}] [{alert['category']}] {alert['message']}")
        if alert.get("evidence"):
            print(f"           {alert['evidence']}")


def main():
    parser = argparse.ArgumentParser(description="data loss prevention engine")
    parser.add_argument("-m", "--mode", default="all",
                        choices=["content", "dns", "volume", "processes", "all"],
                        help="scan mode")
    parser.add_argument("-f", "--file", action="append", help="file to scan")
    parser.add_argument("-i", "--interface", default="eth0", help="network interface")
    parser.add_argument("--entropy", type=float, default=6.5, help="entropy threshold")
    parser.add_argument("--volume", type=int, default=100, help="volume threshold (MB)")
    parser.add_argument("-o", "--output", help="output file")
    parser.add_argument("--json", action="store_true", help="json output")
    args = parser.parse_args()

    engine = DlpEngine(
        entropy_threshold=args.entropy,
        volume_threshold_mb=args.volume,
    )

    if args.mode in ("content", "all") and args.file:
        for fp in args.file:
            engine.scan_file(fp)

    if args.mode in ("volume", "all"):
        engine.check_volume(args.interface)

    if args.mode in ("processes", "all"):
        engine.scan_processes()

    report = engine.get_report()
    print_report(report, args.json)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[tropy] report saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
