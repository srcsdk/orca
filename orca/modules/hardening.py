#!/usr/bin/env python3
"""system hardening checklist with auto-fix options"""

import os


CHECKS = [
    {
        "name": "ssh_root_login",
        "description": "root ssh login should be disabled",
        "config_file": "/etc/ssh/sshd_config",
        "check_pattern": "PermitRootLogin",
        "secure_value": "no",
    },
    {
        "name": "ssh_password_auth",
        "description": "password auth should be disabled for ssh",
        "config_file": "/etc/ssh/sshd_config",
        "check_pattern": "PasswordAuthentication",
        "secure_value": "no",
    },
    {
        "name": "core_dumps",
        "description": "core dumps should be disabled",
        "config_file": "/etc/security/limits.conf",
        "check_pattern": "core",
        "secure_value": "0",
    },
]


def check_file_permissions(path, expected_mode):
    """check if file has expected permissions."""
    try:
        mode = oct(os.stat(path).st_mode)[-3:]
        return mode == expected_mode, mode
    except OSError:
        return False, "missing"


def check_config_value(config_file, pattern, expected):
    """check if a config file has expected value."""
    try:
        with open(config_file) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#"):
                    continue
                if pattern in line:
                    value = line.split()[-1] if line.split() else ""
                    return value.lower() == expected.lower(), value
    except OSError:
        return False, "file not found"
    return False, "not set"


def run_checklist():
    """run all hardening checks and return results."""
    results = []
    for check in CHECKS:
        passed, current = check_config_value(
            check["config_file"],
            check["check_pattern"],
            check["secure_value"],
        )
        results.append({
            "name": check["name"],
            "description": check["description"],
            "passed": passed,
            "current_value": current,
            "expected_value": check["secure_value"],
        })
    ssh_key_ok, ssh_mode = check_file_permissions(
        os.path.expanduser("~/.ssh"), "700"
    )
    results.append({
        "name": "ssh_dir_permissions",
        "description": "~/.ssh should be mode 700",
        "passed": ssh_key_ok,
        "current_value": ssh_mode,
        "expected_value": "700",
    })
    return results


def format_checklist(results):
    """format checklist results for display."""
    lines = ["system hardening checklist:"]
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        lines.append(f"  [{status}] {r['description']}")
        if not r["passed"]:
            lines.append(f"         current: {r['current_value']}, "
                         f"expected: {r['expected_value']}")
    passed = sum(1 for r in results if r["passed"])
    lines.append(f"\n  score: {passed}/{len(results)} checks passed")
    return "\n".join(lines)


if __name__ == "__main__":
    results = run_checklist()
    print(format_checklist(results))
