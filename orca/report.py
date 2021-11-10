#!/usr/bin/env python3
"""combined report generator for all orca modules"""

import json
import os
from datetime import datetime


def generate_report(scan_results, output_format="text"):
    """generate combined security report from module results."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": summarize(scan_results),
        "modules": scan_results,
    }
    if output_format == "json":
        return json.dumps(report, indent=2)
    return format_text_report(report)


def summarize(scan_results):
    """create summary statistics from scan results."""
    total_findings = 0
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for module_name, results in scan_results.items():
        findings = results.get("findings", [])
        total_findings += len(findings)
        for finding in findings:
            sev = finding.get("severity", "low").lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1
    score = 100
    score -= by_severity["critical"] * 20
    score -= by_severity["high"] * 10
    score -= by_severity["medium"] * 5
    score -= by_severity["low"] * 1
    return {
        "total_findings": total_findings,
        "by_severity": by_severity,
        "security_score": max(0, score),
        "modules_scanned": len(scan_results),
    }


def format_text_report(report):
    """format report as readable text."""
    lines = [
        "=" * 50,
        "orca security report",
        f"generated: {report['timestamp']}",
        "=" * 50,
        "",
        f"security score: {report['summary']['security_score']}/100",
        f"total findings: {report['summary']['total_findings']}",
        "",
    ]
    sev = report["summary"]["by_severity"]
    lines.append("severity breakdown:")
    for level in ["critical", "high", "medium", "low"]:
        count = sev.get(level, 0)
        if count > 0:
            lines.append(f"  {level}: {count}")
    lines.append("")
    for module_name, results in report["modules"].items():
        lines.append(f"--- {module_name} ---")
        for finding in results.get("findings", []):
            lines.append(
                f"  [{finding.get('severity', 'info')}] "
                f"{finding.get('description', '')}"
            )
        lines.append("")
    return "\n".join(lines)


def save_report(report_text, output_dir=None, filename=None):
    """save report to file."""
    if output_dir is None:
        output_dir = os.path.dirname(os.path.dirname(__file__))
    if filename is None:
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    path = os.path.join(output_dir, filename)
    with open(path, "w") as f:
        f.write(report_text)
    return path


if __name__ == "__main__":
    sample = {
        "netscan": {
            "findings": [
                {"severity": "high", "description": "port 23 (telnet) open"},
                {"severity": "medium", "description": "port 80 unencrypted"},
            ]
        },
        "passwd": {
            "findings": [
                {"severity": "critical", "description": "weak root password"},
            ]
        },
    }
    print(generate_report(sample))
