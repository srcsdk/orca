#!/usr/bin/env python3
"""security dashboard data aggregation"""

import time
from collections import defaultdict


class Dashboard:
    """aggregate and serve security dashboard data."""

    def __init__(self, bus=None):
        self.bus = bus
        self.alerts = []
        self.modules_status = {}
        self.stats = defaultdict(int)
        self._start_time = time.time()
        if bus:
            bus.subscribe("alert.", self._on_alert)
            bus.subscribe("system.", self._on_system)

    def _on_alert(self, event):
        """handle incoming alert events."""
        self.alerts.append(event["data"])
        severity = event["data"].get("severity", "INFO")
        self.stats[f"alerts_{severity.lower()}"] += 1
        self.stats["alerts_total"] += 1
        if len(self.alerts) > 500:
            self.alerts = self.alerts[-500:]

    def _on_system(self, event):
        """handle system status events."""
        module = event["data"].get("module", "unknown")
        if "started" in event["topic"]:
            self.modules_status[module] = "running"
        elif "stopped" in event["topic"]:
            self.modules_status[module] = "stopped"

    def get_summary(self):
        """get dashboard summary data."""
        uptime = time.time() - self._start_time
        hours = int(uptime // 3600)
        minutes = int((uptime % 3600) // 60)
        active = sum(
            1 for s in self.modules_status.values() if s == "running"
        )
        return {
            "uptime": f"{hours}h {minutes}m",
            "active_modules": active,
            "total_modules": len(self.modules_status),
            "alerts_total": self.stats["alerts_total"],
            "alerts_critical": self.stats["alerts_crit"],
            "alerts_high": self.stats["alerts_high"],
        }

    def get_recent_alerts(self, limit=20, severity=None):
        """get recent alerts with optional severity filter."""
        alerts = self.alerts
        if severity:
            alerts = [
                a for a in alerts
                if a.get("severity") == severity
            ]
        return alerts[-limit:]

    def get_module_status(self):
        """get status of all registered modules."""
        return dict(self.modules_status)

    def get_alert_trend(self, hours=24, interval=1):
        """get alert count trend over time."""
        now = time.time()
        buckets = {}
        for i in range(int(hours / interval)):
            bucket_start = now - (i + 1) * interval * 3600
            bucket_end = now - i * interval * 3600
            count = sum(
                1 for a in self.alerts
                if bucket_start <= a.get("timestamp", 0) < bucket_end
            )
            buckets[f"-{(i + 1) * interval}h"] = count
        return buckets


if __name__ == "__main__":
    dash = Dashboard()
    summary = dash.get_summary()
    print("dashboard summary:")
    for key, value in summary.items():
        print(f"  {key}: {value}")
