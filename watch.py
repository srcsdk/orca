#!/usr/bin/env python3
__version__ = "1.1.0"
"""arp spoofing detection and monitoring"""

import argparse
import csv
import json
import os
import platform
import signal
import socket
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime


class ArpMonitor:
    """monitor arp traffic for spoofing indicators"""

    def __init__(self, interface=None, baseline_file=None):
        self.interface = interface or self._default_interface()
        self.baseline = {}
        self.current = {}
        self.alerts = []
        self.mac_to_ips = defaultdict(set)
        self.arp_counts = defaultdict(int)
        self.running = False

        self.system = platform.system()

        if baseline_file and os.path.exists(baseline_file):
            self.load_baseline(baseline_file)

    def load_baseline(self, filename):
        """load trusted ip->mac bindings"""
        with open(filename, "r") as f:
            self.baseline = json.load(f)
        print(f"loaded {len(self.baseline)} baseline entries")

    def save_baseline(self, filename):
        """save current arp table as baseline"""
        self.scan_arp_table()
        with open(filename, "w") as f:
            json.dump(self.current, f, indent=2)
        print(f"saved {len(self.current)} entries to {filename}")

    @staticmethod
    def _default_interface():
        """detect default network interface"""
        system = platform.system()
        try:
            if system == "Linux":
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True, text=True, timeout=5
                )
                parts = result.stdout.split()
                if "dev" in parts:
                    return parts[parts.index("dev") + 1]
            elif system == "Darwin":
                result = subprocess.run(
                    ["route", "-n", "get", "default"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split("\n"):
                    if "interface:" in line:
                        return line.split()[-1]
            elif system == "Windows":
                result = subprocess.run(
                    ["netsh", "interface", "show", "interface"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split("\n"):
                    if "Connected" in line:
                        return line.split()[-1]
        except (subprocess.TimeoutExpired, OSError, IndexError):
            pass
        defaults = {"Linux": "eth0", "Darwin": "en0", "Windows": "Ethernet"}
        return defaults.get(system, "eth0")

    def scan_arp_table(self):
        """get current arp table from system (cross-platform)"""
        self.current = {}
        try:
            if self.system == "Linux":
                result = subprocess.run(
                    ["ip", "neigh", "show"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.strip().split("\n"):
                    parts = line.split()
                    if len(parts) >= 4 and "lladdr" in line:
                        ip = parts[0]
                        mac_idx = parts.index("lladdr") + 1
                        if mac_idx < len(parts):
                            mac = parts[mac_idx]
                            self.current[ip] = mac
                            self.mac_to_ips[mac].add(ip)
            elif self.system in ("Darwin", "Windows"):
                result = subprocess.run(
                    ["arp", "-a"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.strip().split("\n"):
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    if self.system == "Darwin":
                        # format: host (ip) at mac on iface
                        ip_match = None
                        mac_val = None
                        for j, p in enumerate(parts):
                            if p.startswith("(") and p.endswith(")"):
                                ip_match = p.strip("()")
                            if p == "at" and j + 1 < len(parts):
                                mac_val = parts[j + 1]
                        if ip_match and mac_val and mac_val != "(incomplete)":
                            self.current[ip_match] = mac_val
                            self.mac_to_ips[mac_val].add(ip_match)
                    else:
                        # windows: ip, mac, type columns
                        import re
                        ip_re = re.match(r'\s*(\d+\.\d+\.\d+\.\d+)', line)
                        mac_re = re.search(
                            r'([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}'
                            r'[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})',
                            line, re.IGNORECASE
                        )
                        if ip_re and mac_re:
                            ip = ip_re.group(1)
                            mac = mac_re.group(1)
                            self.current[ip] = mac
                            self.mac_to_ips[mac].add(ip)
        except (subprocess.TimeoutExpired, OSError):
            pass

    def check_anomalies(self):
        """compare current state against baseline"""
        if not self.baseline:
            return

        for ip, mac in self.current.items():
            if ip in self.baseline and self.baseline[ip] != mac:
                alert = {
                    "type": "mac_change",
                    "ip": ip,
                    "expected": self.baseline[ip],
                    "observed": mac,
                    "severity": "critical",
                    "timestamp": datetime.now().isoformat(),
                }
                self.alerts.append(alert)
                self.print_alert(alert)

        # check for one mac claiming multiple ips (gateway spoofing)
        for mac, ips in self.mac_to_ips.items():
            if len(ips) > 3:
                alert = {
                    "type": "multi_ip_mac",
                    "mac": mac,
                    "ips": list(ips),
                    "severity": "high",
                    "timestamp": datetime.now().isoformat(),
                }
                self.alerts.append(alert)
                self.print_alert(alert)

    def print_alert(self, alert):
        """display an alert"""
        sev = alert["severity"].upper()
        if alert["type"] == "mac_change":
            print(f"[{sev}] {alert['ip']}: mac changed "
                  f"{alert['expected']} -> {alert['observed']}")
        elif alert["type"] == "multi_ip_mac":
            print(f"[{sev}] {alert['mac']} claims {len(alert['ips'])} ips: "
                  f"{', '.join(alert['ips'][:5])}")

    def monitor(self, interval=5):
        """continuously monitor arp table"""
        self.running = True

        def stop(sig, frame):
            self.running = False
            print("\nstopping monitor")

        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)

        print(f"monitoring arp table on {self.interface} "
              f"(interval: {interval}s)")
        if self.baseline:
            print(f"baseline: {len(self.baseline)} entries")
        print("watching for changes... (ctrl+c to stop)\n")

        check_count = 0
        while self.running:
            self.scan_arp_table()
            self.check_anomalies()
            check_count += 1
            if check_count % 12 == 0:  # status every minute at 5s interval
                print(f"  [{datetime.now().strftime('%H:%M:%S')}] "
                      f"{len(self.current)} hosts, "
                      f"{len(self.alerts)} alerts")
            time.sleep(interval)

    def print_table(self):
        """display current arp table"""
        self.scan_arp_table()
        print(f"\n{'ip':<16} {'mac':<18} {'status'}")
        print("-" * 50)

        for ip in sorted(self.current.keys(),
                         key=lambda x: socket.inet_aton(x)):
            mac = self.current[ip]
            status = ""
            if ip in self.baseline:
                if self.baseline[ip] != mac:
                    status = "CHANGED"
                else:
                    status = "ok"
            print(f"{ip:<16} {mac:<18} {status}")

        print(f"\n{len(self.current)} entries")


def main():
    default_iface = ArpMonitor._default_interface()
    parser = argparse.ArgumentParser(
        description="arp spoofing detection"
    )
    parser.add_argument("-i", "--interface", default=default_iface,
                        help=f"network interface (default: {default_iface})")
    parser.add_argument("--interval", type=int, default=5,
                        help="check interval in seconds (default: 5)")
    parser.add_argument("-b", "--baseline", type=str,
                        help="baseline file (json)")
    parser.add_argument("--save-baseline", type=str,
                        help="save current arp table as baseline")
    parser.add_argument("--show", action="store_true",
                        help="show current arp table and exit")
    parser.add_argument("-o", "--output", type=str,
                        help="save alerts to json file")
    parser.add_argument("--csv", type=str,
                        help="export alerts to csv file")

    args = parser.parse_args()

    monitor = ArpMonitor(args.interface, args.baseline)

    if args.save_baseline:
        monitor.save_baseline(args.save_baseline)
        return

    if args.show:
        monitor.print_table()
        return

    # default: show arp table then monitor
    if not any([args.baseline, args.output, args.csv]):
        monitor.print_table()
        print()

    monitor.monitor(args.interval)

    if args.output and monitor.alerts:
        with open(args.output, "w") as f:
            json.dump(monitor.alerts, f, indent=2)
        print(f"saved {len(monitor.alerts)} alerts to {args.output}")

    if args.csv and monitor.alerts:
        fieldnames = ["timestamp", "type", "severity", "ip", "mac",
                      "expected", "observed"]
        with open(args.csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames,
                                    extrasaction="ignore")
            writer.writeheader()
            for alert in monitor.alerts:
                writer.writerow(alert)
        print(f"exported {len(monitor.alerts)} alerts to {args.csv}")


if __name__ == "__main__":
    main()


class HostNotifier:
    """send notifications when new hosts appear on the network"""

    def __init__(self, log_file=None):
        self.log_file = log_file
        self.notified = set()

    def notify_new_host(self, ip, mac, timestamp=None):
        """log and print notification for a newly discovered host"""
        if ip in self.notified:
            return

        ts = timestamp or datetime.now().isoformat()
        msg = f"new host detected: {ip} ({mac}) at {ts}"
        print(f"  [NEW] {msg}")

        if self.log_file:
            self.write_log(msg)
        self.notified.add(ip)

    def notify_mac_change(self, ip, old_mac, new_mac, timestamp=None):
        """log and print notification for a mac address change"""
        ts = timestamp or datetime.now().isoformat()
        msg = f"mac change on {ip}: {old_mac} -> {new_mac} at {ts}"
        print(f"  [CHANGE] {msg}")

        if self.log_file:
            self.write_log(msg)

    def write_log(self, message):
        """append a notification to the log file"""
        try:
            with open(self.log_file, "a") as f:
                f.write(message + "\n")
        except OSError as e:
            print(f"log write error: {e}", file=sys.stderr)

    def summary(self):
        """return notification statistics"""
        return {
            "hosts_notified": len(self.notified),
            "log_file": self.log_file,
        }
