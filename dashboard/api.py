#!/usr/bin/env python3
"""rest api endpoints for orca security dashboard"""

import json
import os


class DashboardAPI:
    """serve security data through api endpoints."""

    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        self.cache = {}

    def system_status(self):
        """get overall system security status."""
        return {
            "status": "operational",
            "modules_loaded": self._count_modules(),
            "last_scan": self._last_scan_time(),
            "alerts": self._active_alerts(),
        }

    def scan_results(self, scan_type=None):
        """get results from security scans."""
        results_file = os.path.join(self.data_dir, "scan_results.json")
        if os.path.isfile(results_file):
            with open(results_file) as f:
                results = json.load(f)
            if scan_type:
                results = [
                    r for r in results
                    if r.get("type") == scan_type
                ]
            return results
        return []

    def module_status(self):
        """get status of all loaded security modules."""
        modules_file = os.path.join(self.data_dir, "modules.json")
        if os.path.isfile(modules_file):
            with open(modules_file) as f:
                return json.load(f)
        return {}

    def network_info(self):
        """get network security information."""
        return {
            "open_ports": self._get_cached("open_ports", []),
            "active_connections": self._get_cached("connections", []),
            "firewall_status": self._get_cached("firewall", "unknown"),
        }

    def add_alert(self, severity, message, source=""):
        """add a security alert."""
        alerts_file = os.path.join(self.data_dir, "alerts.json")
        alerts = []
        if os.path.isfile(alerts_file):
            with open(alerts_file) as f:
                alerts = json.load(f)
        alerts.append({
            "severity": severity,
            "message": message,
            "source": source,
            "resolved": False,
        })
        os.makedirs(self.data_dir, exist_ok=True)
        with open(alerts_file, "w") as f:
            json.dump(alerts, f, indent=2)

    def resolve_alert(self, index):
        """mark an alert as resolved."""
        alerts_file = os.path.join(self.data_dir, "alerts.json")
        if not os.path.isfile(alerts_file):
            return False
        with open(alerts_file) as f:
            alerts = json.load(f)
        if 0 <= index < len(alerts):
            alerts[index]["resolved"] = True
            with open(alerts_file, "w") as f:
                json.dump(alerts, f, indent=2)
            return True
        return False

    def _count_modules(self):
        modules_file = os.path.join(self.data_dir, "modules.json")
        if os.path.isfile(modules_file):
            with open(modules_file) as f:
                return len(json.load(f))
        return 0

    def _last_scan_time(self):
        results_file = os.path.join(self.data_dir, "scan_results.json")
        if os.path.isfile(results_file):
            stat = os.stat(results_file)
            return stat.st_mtime
        return None

    def _active_alerts(self):
        alerts_file = os.path.join(self.data_dir, "alerts.json")
        if os.path.isfile(alerts_file):
            with open(alerts_file) as f:
                alerts = json.load(f)
            return len([a for a in alerts if not a.get("resolved")])
        return 0

    def _get_cached(self, key, default=None):
        return self.cache.get(key, default)


if __name__ == "__main__":
    api = DashboardAPI("/tmp/orca_data")
    status = api.system_status()
    print(f"status: {status['status']}")
    print(f"modules: {status['modules_loaded']}")
    print(f"alerts: {status['alerts']}")
