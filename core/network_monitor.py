#!/usr/bin/env python3
"""real-time network traffic monitoring"""

import subprocess
import time
import re
from collections import defaultdict


class NetworkMonitor:
    """monitor network traffic and detect anomalies."""

    def __init__(self, interface=None):
        self.interface = interface or self._detect_interface()
        self.connections = defaultdict(list)
        self.baselines = {}
        self._running = False

    def _detect_interface(self):
        """detect primary network interface."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            )
            parts = result.stdout.split()
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return "eth0"

    def get_connections(self):
        """get current network connections."""
        try:
            result = subprocess.run(
                ["ss", "-tunp"],
                capture_output=True, text=True, timeout=10,
            )
            connections = []
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    connections.append({
                        "state": parts[0],
                        "local": parts[3],
                        "remote": parts[4],
                    })
            return connections
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    def get_traffic_stats(self):
        """get interface traffic statistics."""
        stats_path = f"/sys/class/net/{self.interface}/statistics"
        stats = {}
        for metric in ["rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                        "rx_errors", "tx_errors"]:
            path = f"{stats_path}/{metric}"
            try:
                with open(path) as f:
                    stats[metric] = int(f.read().strip())
            except (FileNotFoundError, ValueError):
                stats[metric] = 0
        return stats

    def bandwidth_usage(self, interval=1):
        """measure bandwidth over interval."""
        before = self.get_traffic_stats()
        time.sleep(interval)
        after = self.get_traffic_stats()
        rx_rate = (after["rx_bytes"] - before["rx_bytes"]) / interval
        tx_rate = (after["tx_bytes"] - before["tx_bytes"]) / interval
        return {
            "rx_bytes_sec": int(rx_rate),
            "tx_bytes_sec": int(tx_rate),
            "rx_mbps": round(rx_rate * 8 / 1_000_000, 2),
            "tx_mbps": round(tx_rate * 8 / 1_000_000, 2),
        }

    def detect_unusual(self, current_connections):
        """detect unusual connection patterns."""
        alerts = []
        remote_ips = defaultdict(int)
        for conn in current_connections:
            remote = conn.get("remote", "")
            if ":" in remote:
                ip = remote.rsplit(":", 1)[0]
                remote_ips[ip] += 1
        for ip, count in remote_ips.items():
            if count > 20:
                alerts.append({
                    "type": "high_connection_count",
                    "ip": ip,
                    "count": count,
                    "severity": "MED",
                })
        return alerts

    def summary(self):
        """get monitoring summary."""
        connections = self.get_connections()
        stats = self.get_traffic_stats()
        return {
            "interface": self.interface,
            "active_connections": len(connections),
            "rx_bytes": stats.get("rx_bytes", 0),
            "tx_bytes": stats.get("tx_bytes", 0),
        }


if __name__ == "__main__":
    monitor = NetworkMonitor()
    summary = monitor.summary()
    for key, val in summary.items():
        print(f"  {key}: {val}")
