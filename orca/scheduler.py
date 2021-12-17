#!/usr/bin/env python3
"""scheduled scan with cron-style configuration"""

import json
import os
import time


SCHEDULE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "scan_schedule.json"
)


def load_schedule():
    """load scan schedule configuration."""
    if os.path.exists(SCHEDULE_FILE):
        with open(SCHEDULE_FILE, "r") as f:
            return json.load(f)
    return {"scans": [], "results": []}


def save_schedule(schedule):
    """save scan schedule."""
    with open(SCHEDULE_FILE, "w") as f:
        json.dump(schedule, f, indent=2)


def add_scan(name, modules, interval_hours=24):
    """add a scheduled scan."""
    schedule = load_schedule()
    schedule["scans"].append({
        "name": name,
        "modules": modules,
        "interval": interval_hours * 3600,
        "last_run": 0,
        "enabled": True,
    })
    save_schedule(schedule)


def get_due_scans():
    """get scans that are due to run."""
    schedule = load_schedule()
    now = time.time()
    due = []
    for scan in schedule["scans"]:
        if not scan.get("enabled", True):
            continue
        if now - scan.get("last_run", 0) >= scan.get("interval", 86400):
            due.append(scan)
    return due


def record_result(scan_name, result):
    """record scan result."""
    schedule = load_schedule()
    for scan in schedule["scans"]:
        if scan["name"] == scan_name:
            scan["last_run"] = time.time()
    schedule["results"].append({
        "scan": scan_name,
        "timestamp": time.time(),
        "findings": result.get("total_findings", 0),
    })
    schedule["results"] = schedule["results"][-100:]
    save_schedule(schedule)


def format_schedule():
    """format schedule for display."""
    schedule = load_schedule()
    lines = [f"scheduled scans: {len(schedule['scans'])}"]
    for scan in schedule["scans"]:
        status = "enabled" if scan.get("enabled") else "disabled"
        interval = scan.get("interval", 0) // 3600
        lines.append(f"  {scan['name']}: every {interval}h ({status})")
        lines.append(f"    modules: {', '.join(scan.get('modules', []))}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(format_schedule())
