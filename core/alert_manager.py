#!/usr/bin/env python3
"""centralized alert management and escalation"""

import time
import json
from collections import defaultdict


SEVERITY_LEVELS = {"INFO": 0, "LOW": 1, "MED": 2, "HIGH": 3, "CRIT": 4}


class AlertManager:
    """manage, deduplicate, and escalate security alerts."""

    def __init__(self, bus=None, dedup_window=300):
        self.bus = bus
        self.dedup_window = dedup_window
        self.alerts = []
        self.rules = []
        self._dedup_cache = {}
        self._counts = defaultdict(int)
        if bus:
            bus.subscribe("alert.new", self._on_alert)

    def _on_alert(self, event):
        """handle incoming alert event."""
        alert = event.get("data", {})
        if self._is_duplicate(alert):
            return
        alert["id"] = len(self.alerts)
        alert["timestamp"] = time.time()
        alert["status"] = "new"
        self.alerts.append(alert)
        self._counts[alert.get("severity", "INFO")] += 1
        self._check_escalation(alert)

    def _is_duplicate(self, alert):
        """check if alert is duplicate within time window."""
        key = f"{alert.get('module')}:{alert.get('title')}"
        now = time.time()
        if key in self._dedup_cache:
            if now - self._dedup_cache[key] < self.dedup_window:
                return True
        self._dedup_cache[key] = now
        return False

    def _check_escalation(self, alert):
        """check if alert should be escalated."""
        for rule in self.rules:
            if rule.matches(alert):
                rule.execute(alert, self)

    def add_rule(self, rule):
        """add an escalation rule."""
        self.rules.append(rule)

    def acknowledge(self, alert_id):
        """acknowledge an alert."""
        if 0 <= alert_id < len(self.alerts):
            self.alerts[alert_id]["status"] = "acknowledged"
            return True
        return False

    def resolve(self, alert_id, resolution=""):
        """resolve an alert."""
        if 0 <= alert_id < len(self.alerts):
            self.alerts[alert_id]["status"] = "resolved"
            self.alerts[alert_id]["resolution"] = resolution
            return True
        return False

    def get_active(self, min_severity="INFO"):
        """get active alerts above severity threshold."""
        min_level = SEVERITY_LEVELS.get(min_severity, 0)
        return [
            a for a in self.alerts
            if a["status"] != "resolved"
            and SEVERITY_LEVELS.get(a.get("severity"), 0) >= min_level
        ]

    def summary(self):
        """get alert summary counts."""
        active = [a for a in self.alerts if a["status"] != "resolved"]
        return {
            "total": len(self.alerts),
            "active": len(active),
            "by_severity": dict(self._counts),
        }

    def export(self, filepath):
        """export alerts to json file."""
        with open(filepath, "w") as f:
            json.dump(self.alerts, f, indent=2)


class EscalationRule:
    """rule for automatic alert escalation."""

    def __init__(self, name, condition, action):
        self.name = name
        self.condition = condition
        self.action = action

    def matches(self, alert):
        """check if alert matches rule condition."""
        return self.condition(alert)

    def execute(self, alert, manager):
        """execute escalation action."""
        self.action(alert, manager)


if __name__ == "__main__":
    am = AlertManager()
    print(f"alert manager ready, dedup window: {am.dedup_window}s")
    print(f"summary: {am.summary()}")
