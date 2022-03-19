#!/usr/bin/env python3
"""firewall rule management and analysis"""

import subprocess
import re


def get_iptables_rules():
    """parse current iptables rules."""
    try:
        output = subprocess.check_output(
            ["iptables", "-L", "-n", "--line-numbers"],
            stderr=subprocess.STDOUT,
            text=True,
        )
        return _parse_iptables(output)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def _parse_iptables(output):
    """parse iptables output into structured rules."""
    rules = []
    chain = ""
    for line in output.splitlines():
        if line.startswith("Chain"):
            chain = line.split()[1]
        elif re.match(r"\d+", line.strip()):
            parts = line.split()
            if len(parts) >= 6:
                rules.append({
                    "chain": chain,
                    "num": parts[0],
                    "target": parts[1],
                    "protocol": parts[2],
                    "source": parts[4],
                    "destination": parts[5],
                })
    return rules


def get_ufw_status():
    """get ufw firewall status."""
    try:
        output = subprocess.check_output(
            ["ufw", "status", "verbose"],
            stderr=subprocess.STDOUT,
            text=True,
        )
        return _parse_ufw(output)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {"active": False, "rules": []}


def _parse_ufw(output):
    """parse ufw status output."""
    active = "Status: active" in output
    rules = []
    in_rules = False
    for line in output.splitlines():
        if line.startswith("--"):
            in_rules = True
            continue
        if in_rules and line.strip():
            parts = line.split()
            if len(parts) >= 2:
                rules.append({
                    "to": parts[0],
                    "action": parts[1],
                    "from": parts[2] if len(parts) > 2 else "any",
                })
    return {"active": active, "rules": rules}


def recommended_rules():
    """return recommended firewall rules for a server."""
    return [
        {"port": 22, "protocol": "tcp", "action": "allow",
         "note": "ssh access"},
        {"port": 80, "protocol": "tcp", "action": "allow",
         "note": "http"},
        {"port": 443, "protocol": "tcp", "action": "allow",
         "note": "https"},
        {"port": "1:21", "protocol": "tcp", "action": "deny",
         "note": "block low ports"},
        {"port": "23:79", "protocol": "tcp", "action": "deny",
         "note": "block unused services"},
    ]


def audit_rules(rules):
    """check firewall rules for common issues."""
    issues = []
    for rule in rules:
        if rule.get("source") == "0.0.0.0/0":
            if rule.get("target") == "ACCEPT":
                port_info = rule.get("destination", "")
                issues.append(
                    f"wide open accept from any source "
                    f"in {rule['chain']} -> {port_info}"
                )
    return issues


if __name__ == "__main__":
    print("recommended firewall rules:")
    for rule in recommended_rules():
        print(f"  port {rule['port']}/{rule['protocol']}: "
              f"{rule['action']} ({rule['note']})")
