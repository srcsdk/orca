#!/usr/bin/env python3
__version__ = "1.1.0"
"""network scan detection and alerting"""

import argparse
import json
import math
import os
import platform
import signal
import subprocess
import sys
import time
from collections import defaultdict, Counter
from datetime import datetime

PLATFORM = platform.system().lower()


class ScanDetector:
    """detect port scanning and network reconnaissance"""

    def __init__(self, port_threshold=25, time_window=10,
                 rate_threshold=50):
        self.port_threshold = port_threshold
        self.time_window = time_window
        self.rate_threshold = rate_threshold
        self.sources = defaultdict(lambda: {
            "ports": set(),
            "first_seen": 0,
            "last_seen": 0,
            "count": 0,
            "syn_count": 0,
        })
        self.alerts = []
        self.blocklist = set()

    def process_connection(self, src_ip, dst_port, timestamp, flags=""):
        """analyze a connection attempt"""
        entry = self.sources[src_ip]

        # reset window if expired
        if timestamp - entry["first_seen"] > self.time_window:
            entry["ports"] = set()
            entry["first_seen"] = timestamp
            entry["count"] = 0
            entry["syn_count"] = 0

        entry["ports"].add(dst_port)
        entry["last_seen"] = timestamp
        entry["count"] += 1

        if "S" in flags and "A" not in flags:
            entry["syn_count"] += 1

        # check thresholds
        alerts = []
        port_count = len(entry["ports"])
        rate = entry["count"] / max(timestamp - entry["first_seen"], 1)

        if port_count >= self.port_threshold:
            severity = self.classify_severity(port_count, rate)
            alert = {
                "type": "port_scan",
                "source": src_ip,
                "ports_probed": port_count,
                "rate": round(rate, 1),
                "severity": severity,
                "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
            }
            alerts.append(alert)

        if entry["syn_count"] > self.rate_threshold:
            alert = {
                "type": "syn_flood",
                "source": src_ip,
                "syn_count": entry["syn_count"],
                "window": self.time_window,
                "severity": "critical",
                "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
            }
            alerts.append(alert)

        for alert in alerts:
            if not self.is_duplicate(alert):
                self.alerts.append(alert)
                self.print_alert(alert)
                if alert["severity"] in ("critical", "high"):
                    self.blocklist.add(src_ip)

        return alerts

    def classify_severity(self, port_count, rate):
        """determine alert severity"""
        if port_count > 100 or rate > 100:
            return "critical"
        elif port_count > 50 or rate > 50:
            return "high"
        elif port_count > 25 or rate > 20:
            return "medium"
        return "low"

    def port_entropy(self, src_ip):
        """calculate entropy of destination ports for a source"""
        entry = self.sources.get(src_ip)
        if not entry or not entry["ports"]:
            return 0
        # uniform distribution = high entropy = likely scanning
        n = len(entry["ports"])
        if n <= 1:
            return 0
        # normalized entropy (0 to 1)
        return math.log2(n) / math.log2(65535)

    def is_duplicate(self, alert):
        """avoid alerting on the same source repeatedly"""
        for existing in self.alerts[-20:]:
            if (existing["source"] == alert["source"]
                    and existing["type"] == alert["type"]):
                return True
        return False

    def print_alert(self, alert):
        """display an alert"""
        sev = alert["severity"].upper()
        if alert["type"] == "port_scan":
            print(f"[{sev}] scan detected from {alert['source']}: "
                  f"{alert['ports_probed']} ports, "
                  f"{alert['rate']} pkt/s")
        elif alert["type"] == "syn_flood":
            print(f"[{sev}] syn flood from {alert['source']}: "
                  f"{alert['syn_count']} syns in {self.time_window}s")

    def export_blocklist(self, filename):
        """export blocklist as firewall rules for current platform"""
        with open(filename, "w") as f:
            if PLATFORM == "windows":
                f.write("@echo off\n")
                f.write("rem auto-generated blocklist\n")
                for ip in sorted(self.blocklist):
                    f.write(f"netsh advfirewall firewall add rule "
                            f"name=\"block_{ip}\" dir=in action=block "
                            f"remoteip={ip}\n")
            elif PLATFORM == "darwin":
                f.write("#!/bin/bash\n")
                f.write("# auto-generated blocklist (pf)\n")
                for ip in sorted(self.blocklist):
                    f.write(f"echo \"block drop from {ip} to any\" "
                            f"| pfctl -f -\n")
            else:
                f.write("#!/bin/bash\n")
                f.write("# auto-generated blocklist\n")
                for ip in sorted(self.blocklist):
                    f.write(f"iptables -A INPUT -s {ip} -j DROP\n")
        if PLATFORM != "windows":
            os.chmod(filename, 0o755)
        print(f"exported {len(self.blocklist)} rules to {filename}")

    def stats(self):
        """return detection statistics"""
        return {
            "total_sources": len(self.sources),
            "total_alerts": len(self.alerts),
            "blocked_ips": list(self.blocklist),
            "alert_types": dict(Counter(a["type"] for a in self.alerts)),
            "severities": dict(Counter(a["severity"] for a in self.alerts)),
        }


def monitor_tcpdump(interface, detector, bpf_filter=None):
    """monitor live traffic with tcpdump"""
    cmd = ["tcpdump", "-i", interface, "-nn", "-l", "-tttt"]
    if bpf_filter:
        cmd.extend(bpf_filter.split())
    else:
        cmd.extend(["tcp[tcpflags] & tcp-syn != 0"])

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    def stop(sig, frame):
        proc.terminate()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    for line in proc.stdout:
        parts = line.split()
        if "IP" not in parts:
            continue

        try:
            ip_idx = parts.index("IP")
            src = parts[ip_idx + 1]
            dst = parts[ip_idx + 3].rstrip(":")

            src_ip = src.rsplit(".", 1)[0] if "." in src else src
            dst_port = int(dst.rsplit(".", 1)[1]) if "." in dst else 0

            flags = ""
            for p in parts:
                if p.startswith("[") and "]" in p:
                    flags = p.strip("[]")
                    break

            detector.process_connection(
                src_ip, dst_port, time.time(), flags
            )
        except (ValueError, IndexError):
            continue

    proc.wait()


def _default_interface():
    """detect default network interface"""
    if PLATFORM == "linux":
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            parts = result.stdout.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
        except (subprocess.TimeoutExpired, OSError):
            pass
        return "eth0"
    elif PLATFORM == "darwin":
        try:
            result = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "interface:" in line:
                    return line.split("interface:")[1].strip()
        except (subprocess.TimeoutExpired, OSError):
            pass
        return "en0"
    elif PLATFORM == "windows":
        return "Ethernet"
    return "eth0"


def _check_root():
    """check for root/admin privileges"""
    if PLATFORM == "windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (ImportError, AttributeError):
            return False
    return os.geteuid() == 0


def run_self_test(detector):
    """run a self-test with simulated scan data"""
    print("running self-test with simulated scan data...\n")
    base_time = time.time()
    # simulate a port scan from a single source
    test_ip = "10.0.0.99"
    for port in range(1, 60):
        detector.process_connection(test_ip, port, base_time + port * 0.1, "S")
    # simulate a syn flood
    flood_ip = "10.0.0.100"
    for i in range(80):
        detector.process_connection(flood_ip, 80, base_time + i * 0.05, "S")

    print()
    stats = detector.stats()
    print("--- self-test results ---")
    print(f"sources tracked: {stats['total_sources']}")
    print(f"alerts raised:   {stats['total_alerts']}")
    print(f"ips blocked:     {len(stats['blocked_ips'])}")
    if stats["alert_types"]:
        print(f"alert types:     {stats['alert_types']}")
    if stats["severities"]:
        print(f"severities:      {stats['severities']}")
    print("\ndetector is working correctly" if stats["total_alerts"] > 0
          else "\nwarning: no alerts generated")


def main():
    parser = argparse.ArgumentParser(description="network scan detection")
    parser.add_argument("-i", "--interface", default=None,
                        help="network interface")
    parser.add_argument("--port-threshold", type=int, default=25,
                        help="ports before alerting (default: 25)")
    parser.add_argument("--window", type=int, default=10,
                        help="time window in seconds (default: 10)")
    parser.add_argument("-f", "--filter", type=str,
                        help="bpf filter")
    parser.add_argument("--blocklist", type=str,
                        help="export blocklist to file")
    parser.add_argument("-o", "--output", type=str,
                        help="save alerts to json")
    parser.add_argument("--self-test", action="store_true",
                        help="run self-test with simulated data")

    args = parser.parse_args()

    detector = ScanDetector(
        port_threshold=args.port_threshold,
        time_window=args.window,
    )

    # default behavior: self-test if not root, monitor if root
    if args.self_test:
        run_self_test(detector)
        return

    if not _check_root():
        print("not running as root/admin - running self-test instead\n")
        run_self_test(detector)
        return

    iface = args.interface or _default_interface()

    print(f"monitoring {iface} for scan activity...")
    print(f"thresholds: {args.port_threshold} ports in {args.window}s window")
    print("ctrl+c to stop\n")

    try:
        monitor_tcpdump(iface, detector, args.filter)
    except KeyboardInterrupt:
        pass

    print(f"\n--- detection summary ---")
    stats = detector.stats()
    print(f"sources tracked: {stats['total_sources']}")
    print(f"alerts raised:   {stats['total_alerts']}")
    print(f"ips blocked:     {len(stats['blocked_ips'])}")

    if args.blocklist:
        detector.export_blocklist(args.blocklist)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({
                "stats": stats,
                "alerts": detector.alerts,
            }, f, indent=2)
        print(f"saved to {args.output}")


if __name__ == "__main__":
    main()


# configurable thresholds can be loaded from a json file
DEFAULT_THRESHOLDS = {
    "port_scan": {"low": 15, "medium": 25, "high": 50, "critical": 100},
    "syn_flood": {"low": 30, "medium": 50, "high": 100, "critical": 200},
    "rate_pps": {"low": 10, "medium": 20, "high": 50, "critical": 100},
}


def load_thresholds(config_file):
    """load alert thresholds from a json config file.

    falls back to defaults if file is missing or invalid.
    """
    if not config_file or not os.path.exists(config_file):
        return DEFAULT_THRESHOLDS

    try:
        with open(config_file, "r") as f:
            custom = json.load(f)
        merged = dict(DEFAULT_THRESHOLDS)
        for key in custom:
            if key in merged:
                merged[key].update(custom[key])
        return merged
    except (json.JSONDecodeError, ValueError) as e:
        print(f"invalid threshold config: {e}", file=sys.stderr)
        return DEFAULT_THRESHOLDS


def apply_thresholds(detector, thresholds):
    """apply loaded thresholds to a scan detector instance"""
    port_th = thresholds.get("port_scan", {})
    detector.port_threshold = port_th.get("medium", detector.port_threshold)
    rate_th = thresholds.get("syn_flood", {})
    detector.rate_threshold = rate_th.get("medium", detector.rate_threshold)
