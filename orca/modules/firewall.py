#!/usr/bin/env python3
"""firewall rule generator for detected vulnerabilities"""

import subprocess


def generate_iptables_rule(action, protocol="tcp", port=None,
                           source=None, destination=None):
    """generate an iptables rule string."""
    parts = ["iptables"]
    if action == "block":
        parts.extend(["-A", "INPUT", "-j", "DROP"])
    elif action == "allow":
        parts.extend(["-A", "INPUT", "-j", "ACCEPT"])
    else:
        return None
    if protocol:
        parts.extend(["-p", protocol])
    if port:
        parts.extend(["--dport", str(port)])
    if source:
        parts.extend(["-s", source])
    if destination:
        parts.extend(["-d", destination])
    return " ".join(parts)


def block_port(port, protocol="tcp"):
    """generate rule to block a specific port."""
    return generate_iptables_rule("block", protocol, port)


def block_ip(ip_address):
    """generate rule to block traffic from an ip."""
    return generate_iptables_rule("block", source=ip_address)


def whitelist_ip(ip_address):
    """generate rule to allow traffic from an ip."""
    return generate_iptables_rule("allow", source=ip_address)


def rules_from_vulns(vulnerabilities):
    """generate firewall rules from vulnerability scan results."""
    rules = []
    for vuln in vulnerabilities:
        port = vuln.get("port")
        severity = vuln.get("severity", "").lower()
        if severity in ("critical", "high") and port:
            rule = block_port(port)
            rules.append({
                "rule": rule,
                "reason": vuln.get("description", "vulnerability detected"),
                "port": port,
                "severity": severity,
            })
    return rules


def list_current_rules():
    """list current iptables rules."""
    try:
        result = subprocess.run(
            ["iptables", "-L", "-n", "--line-numbers"],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout
    except (subprocess.TimeoutExpired, OSError):
        return "could not retrieve rules (need root)"


def format_rules(rules):
    """format rules for display."""
    lines = [f"generated {len(rules)} firewall rules:"]
    for r in rules:
        lines.append(f"  [{r['severity']}] port {r['port']}: {r['rule']}")
        lines.append(f"    reason: {r['reason']}")
    return "\n".join(lines)


if __name__ == "__main__":
    sample_vulns = [
        {"port": 23, "severity": "high", "description": "telnet exposed"},
        {"port": 21, "severity": "critical", "description": "ftp exposed"},
        {"port": 80, "severity": "low", "description": "http open"},
    ]
    rules = rules_from_vulns(sample_vulns)
    print(format_rules(rules))
