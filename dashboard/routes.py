#!/usr/bin/env python3
"""dashboard routes for system status and scan results"""

import json
import os
from datetime import datetime


def get_system_status():
    """gather current system status for dashboard."""
    import platform
    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.release(),
        "python": platform.python_version(),
        "timestamp": datetime.now().isoformat(),
    }


def get_scan_results(results_dir="scan_results"):
    """load latest scan results from file."""
    if not os.path.isdir(results_dir):
        return []
    results = []
    for fname in sorted(os.listdir(results_dir), reverse=True):
        if fname.endswith(".json"):
            filepath = os.path.join(results_dir, fname)
            with open(filepath, "r") as f:
                data = json.load(f)
            data["filename"] = fname
            results.append(data)
    return results[:20]


def get_module_status(base_dir=None):
    """check status of all orca modules."""
    if base_dir is None:
        base_dir = os.path.dirname(os.path.dirname(__file__))
    cybersec_dir = os.path.join(base_dir, "cybersec")
    modules = []
    if os.path.isdir(cybersec_dir):
        for fname in sorted(os.listdir(cybersec_dir)):
            if fname.endswith(".py") and not fname.startswith("_"):
                modules.append({
                    "name": fname[:-3],
                    "path": os.path.join(cybersec_dir, fname),
                    "status": "available",
                })
    return modules


def format_dashboard_data():
    """compile all dashboard data into single dict."""
    return {
        "status": get_system_status(),
        "modules": get_module_status(),
        "recent_scans": get_scan_results(),
        "generated_at": datetime.now().isoformat(),
    }


if __name__ == "__main__":
    data = format_dashboard_data()
    print(f"system: {data['status']['os']} {data['status']['os_version']}")
    print(f"modules: {len(data['modules'])}")
    print(f"recent scans: {len(data['recent_scans'])}")
