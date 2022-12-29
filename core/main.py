#!/usr/bin/env python3
"""main entry point for orca security platform"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def init_platform(profile_name=None):
    """initialize orca platform with optional profile."""
    from core.config import load_config
    from core.event_bus import EventBus
    from core.plugin_base import PluginRegistry
    from core.profiles import ProfileManager
    from core.dashboard import Dashboard
    from core.alert_manager import AlertManager

    config = load_config()
    bus = EventBus()
    registry = PluginRegistry()
    alert_mgr = AlertManager(bus=bus)
    dashboard = Dashboard(bus=bus)

    pm = ProfileManager()
    if profile_name:
        modules = pm.get_modules(profile_name)
    else:
        modules = pm.get_modules("personal")

    return {
        "config": config,
        "bus": bus,
        "registry": registry,
        "alert_manager": alert_mgr,
        "dashboard": dashboard,
        "active_modules": modules,
    }


def run_scan(target, scan_type="quick"):
    """run a one-shot security scan."""
    from core.port_scanner import scan_ports
    from core.os_detect import detect_os
    from core.ssl_check import check_ssl

    results = {"target": target, "type": scan_type}
    if scan_type in ("quick", "full"):
        ports = scan_ports(target)
        results["ports"] = ports
    if scan_type == "full":
        os_info = detect_os()
        results["os"] = os_info
        ssl = check_ssl(target)
        results["ssl"] = ssl
    return results


def main():
    """main entry point."""
    if len(sys.argv) < 2:
        print("usage: orca <command> [options]")
        print("commands: start, scan, status, alerts, modules, report")
        return 1
    command = sys.argv[1]
    if command == "start":
        profile = sys.argv[2] if len(sys.argv) > 2 else "personal"
        platform = init_platform(profile)
        modules = platform["active_modules"]
        print(f"orca started with {len(modules)} modules")
        print(f"profile: {profile}")
        return 0
    elif command == "scan":
        target = sys.argv[2] if len(sys.argv) > 2 else "localhost"
        scan_type = sys.argv[3] if len(sys.argv) > 3 else "quick"
        print(f"scanning {target} ({scan_type})...")
        return 0
    elif command == "status":
        print("orca status: ready")
        return 0
    elif command == "version":
        print("orca 2.0.0")
        return 0
    else:
        print(f"unknown command: {command}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
