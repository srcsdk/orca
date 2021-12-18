#!/usr/bin/env python3
"""wifi security scanner for wpa wep detection"""

import subprocess
import re


def scan_wifi(interface="wlan0"):
    """scan for nearby wifi networks and their security."""
    try:
        result = subprocess.run(
            ["iwlist", interface, "scan"],
            capture_output=True, text=True, timeout=15,
        )
        return parse_scan_results(result.stdout)
    except (subprocess.TimeoutExpired, OSError):
        return []


def parse_scan_results(output):
    """parse iwlist scan output into network dicts."""
    networks = []
    current = {}
    for line in output.split("\n"):
        line = line.strip()
        if "Cell" in line and "Address:" in line:
            if current:
                networks.append(current)
            mac = line.split("Address:")[1].strip()
            current = {"mac": mac}
        elif "ESSID:" in line:
            match = re.search(r'ESSID:"(.*?)"', line)
            current["ssid"] = match.group(1) if match else ""
        elif "Encryption key:" in line:
            current["encrypted"] = "on" in line.lower()
        elif "IE:" in line:
            if "WPA2" in line:
                current["security"] = "WPA2"
            elif "WPA" in line:
                current["security"] = "WPA"
        elif "Quality=" in line:
            match = re.search(r"Quality[=:]([\d/]+)", line)
            if match:
                parts = match.group(1).split("/")
                if len(parts) == 2:
                    current["signal"] = int(
                        int(parts[0]) / int(parts[1]) * 100
                    )
    if current:
        networks.append(current)
    return networks


def assess_security(network):
    """assess security level of a wifi network."""
    security = network.get("security", "")
    encrypted = network.get("encrypted", False)
    if not encrypted:
        return {"level": "critical", "issue": "open network, no encryption"}
    if security == "WEP" or "WEP" in security:
        return {"level": "high", "issue": "wep is broken, easily cracked"}
    if security == "WPA":
        return {"level": "medium", "issue": "wpa1 has known vulnerabilities"}
    if security == "WPA2":
        return {"level": "low", "issue": "wpa2 is reasonably secure"}
    return {"level": "unknown", "issue": "could not determine encryption"}


def scan_report():
    """generate wifi security scan report."""
    networks = scan_wifi()
    report = []
    for net in networks:
        assessment = assess_security(net)
        report.append({
            "ssid": net.get("ssid", "hidden"),
            "mac": net.get("mac", ""),
            "signal": net.get("signal", 0),
            "security": net.get("security", "none"),
            "risk_level": assessment["level"],
            "issue": assessment["issue"],
        })
    return sorted(report, key=lambda r: r.get("signal", 0), reverse=True)


if __name__ == "__main__":
    print("wifi security scanner")
    print("requires root and wireless interface")
    report = scan_report()
    for net in report:
        print(f"  {net['ssid']}: {net['security']} "
              f"(risk: {net['risk_level']})")
