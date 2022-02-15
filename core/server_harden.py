#!/usr/bin/env python3
"""server hardening checklist with ssh and firewall rules"""

import os


HARDENING_CHECKS = [
    {"id": "ssh_root", "name": "disable root ssh login",
     "file": "/etc/ssh/sshd_config", "check": "PermitRootLogin no"},
    {"id": "ssh_password", "name": "disable password authentication",
     "file": "/etc/ssh/sshd_config", "check": "PasswordAuthentication no"},
    {"id": "ssh_port", "name": "change default ssh port",
     "file": "/etc/ssh/sshd_config", "check": "Port"},
    {"id": "firewall", "name": "firewall enabled",
     "command": "ufw status"},
    {"id": "updates", "name": "automatic security updates",
     "file": "/etc/apt/apt.conf.d/20auto-upgrades"},
    {"id": "fail2ban", "name": "fail2ban installed and running",
     "command": "systemctl is-active fail2ban"},
]


def check_file_contains(filepath, search_string):
    """check if a config file contains expected setting."""
    if not os.path.exists(filepath):
        return {"exists": False, "contains": False}
    try:
        with open(filepath, "r") as f:
            content = f.read()
        return {
            "exists": True,
            "contains": search_string in content,
        }
    except PermissionError:
        return {"exists": True, "contains": None, "error": "permission denied"}


def run_hardening_audit():
    """run all hardening checks and return results."""
    results = []
    for check in HARDENING_CHECKS:
        result = {"id": check["id"], "name": check["name"]}
        if "file" in check and "check" in check:
            status = check_file_contains(check["file"], check["check"])
            result["passed"] = status.get("contains", False)
            result["details"] = status
        else:
            result["passed"] = None
            result["details"] = "manual check required"
        results.append(result)
    return results


def generate_fix_script(failed_checks):
    """generate shell commands to fix failed checks."""
    fixes = {
        "ssh_root": "sed -i 's/.*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
        "ssh_password": "sed -i 's/.*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
        "firewall": "ufw enable && ufw default deny incoming && ufw default allow outgoing",
        "fail2ban": "apt install -y fail2ban && systemctl enable fail2ban && systemctl start fail2ban",
    }
    script_lines = ["#!/bin/bash", "# auto-generated hardening script", ""]
    for check in failed_checks:
        if check["id"] in fixes:
            script_lines.append(f"# {check['name']}")
            script_lines.append(fixes[check["id"]])
            script_lines.append("")
    return "\n".join(script_lines)


def format_audit_report(results):
    """format audit results for display."""
    lines = ["server hardening audit", "=" * 30, ""]
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    lines.append(f"score: {passed}/{total}")
    lines.append("")
    for r in results:
        status = "PASS" if r["passed"] else ("FAIL" if r["passed"] is False else "SKIP")
        lines.append(f"  [{status}] {r['name']}")
    return "\n".join(lines)


if __name__ == "__main__":
    results = run_hardening_audit()
    print(format_audit_report(results))
