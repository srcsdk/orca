#!/usr/bin/env python3
"""security compliance checking against common standards"""


CHECKS = {
    "password_policy": {
        "description": "enforce strong password requirements",
        "category": "access_control",
    },
    "ssh_key_auth": {
        "description": "require ssh key authentication",
        "category": "access_control",
    },
    "firewall_enabled": {
        "description": "firewall must be active",
        "category": "network",
    },
    "no_root_login": {
        "description": "disable direct root login",
        "category": "access_control",
    },
    "disk_encryption": {
        "description": "enable disk encryption",
        "category": "data_protection",
    },
    "log_retention": {
        "description": "logs retained for at least 90 days",
        "category": "monitoring",
    },
    "auto_updates": {
        "description": "automatic security updates enabled",
        "category": "patch_management",
    },
    "mfa_enabled": {
        "description": "multi-factor authentication enabled",
        "category": "access_control",
    },
}


def run_compliance_check(system_state):
    """run all compliance checks against system state."""
    results = []
    for check_id, check in CHECKS.items():
        passed = system_state.get(check_id, False)
        results.append({
            "id": check_id,
            "description": check["description"],
            "category": check["category"],
            "passed": passed,
        })
    return results


def compliance_score(results):
    """calculate overall compliance score."""
    if not results:
        return 0
    passed = sum(1 for r in results if r["passed"])
    return round(passed / len(results) * 100, 1)


def by_category(results):
    """group results by category."""
    categories = {}
    for r in results:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {"passed": 0, "failed": 0, "items": []}
        if r["passed"]:
            categories[cat]["passed"] += 1
        else:
            categories[cat]["failed"] += 1
        categories[cat]["items"].append(r)
    return categories


def failed_checks(results):
    """get list of failed checks."""
    return [r for r in results if not r["passed"]]


def format_compliance_report(results):
    """format compliance results for display."""
    score = compliance_score(results)
    lines = [f"compliance score: {score}%", ""]
    categories = by_category(results)
    for cat, data in sorted(categories.items()):
        total = data["passed"] + data["failed"]
        lines.append(f"  {cat}: {data['passed']}/{total} passed")
    failed = failed_checks(results)
    if failed:
        lines.append("\nfailed checks:")
        for f in failed:
            lines.append(f"  - {f['description']}")
    return "\n".join(lines)


if __name__ == "__main__":
    state = {
        "password_policy": True,
        "ssh_key_auth": True,
        "firewall_enabled": True,
        "no_root_login": True,
        "disk_encryption": False,
        "log_retention": True,
        "auto_updates": False,
        "mfa_enabled": False,
    }
    results = run_compliance_check(state)
    print(format_compliance_report(results))
