#!/usr/bin/env python3
"""arp spoofing detection and monitoring"""

import argparse
import csv
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime


class ArpMonitor:
    """monitor arp traffic for spoofing indicators"""

    def __init__(self, interface="eth0", baseline_file=None):
        self.interface = interface
        self.baseline = {}
        self.current = {}
        self.alerts = []
        self.mac_to_ips = defaultdict(set)
        self.arp_counts = defaultdict(int)
        self.running = False

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

    def scan_arp_table(self):
        """get current arp table from system"""
        try:
            result = subprocess.run(
                ["ip", "neigh", "show"],
                capture_output=True, text=True, timeout=5
            )
            self.current = {}
            for line in result.stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 4 and "lladdr" in line:
                    ip = parts[0]
                    mac_idx = parts.index("lladdr") + 1
                    if mac_idx < len(parts):
                        mac = parts[mac_idx]
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
    parser = argparse.ArgumentParser(
        description="arp spoofing detection"
    )
    parser.add_argument("-i", "--interface", default="eth0",
                        help="network interface")
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
