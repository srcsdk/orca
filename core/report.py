#!/usr/bin/env python3
"""security report generation"""

import json
import os


class SecurityReport:
    """generate formatted security assessment reports."""

    def __init__(self):
        self.sections = []
        self.findings = []
        self.metadata = {}

    def set_metadata(self, target="", scan_type="full"):
        """set report metadata."""
        self.metadata = {
            "target": target,
            "scan_type": scan_type,
        }

    def add_finding(self, title, severity, description, remediation=""):
        """add a security finding."""
        self.findings.append({
            "title": title,
            "severity": severity,
            "description": description,
            "remediation": remediation,
        })

    def add_section(self, title, content):
        """add a report section."""
        self.sections.append({"title": title, "content": content})

    def severity_summary(self):
        """summarize findings by severity."""
        counts = {}
        for f in self.findings:
            sev = f["severity"]
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def to_text(self):
        """generate text format report."""
        lines = ["security assessment report", "=" * 40]
        for key, val in self.metadata.items():
            lines.append(f"  {key}: {val}")
        lines.append("")
        summary = self.severity_summary()
        lines.append("findings summary:")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = summary.get(sev, 0)
            if count:
                lines.append(f"  {sev}: {count}")
        lines.append("")
        for section in self.sections:
            lines.append(f"--- {section['title']} ---")
            lines.append(section["content"])
            lines.append("")
        if self.findings:
            lines.append("--- findings ---")
            for i, f in enumerate(self.findings, 1):
                lines.append(
                    f"  {i}. [{f['severity'].upper()}] {f['title']}"
                )
                lines.append(f"     {f['description']}")
                if f["remediation"]:
                    lines.append(f"     fix: {f['remediation']}")
                lines.append("")
        return "\n".join(lines)

    def to_json(self):
        """generate json format report."""
        return json.dumps({
            "metadata": self.metadata,
            "summary": self.severity_summary(),
            "sections": self.sections,
            "findings": self.findings,
        }, indent=2)

    def save(self, filepath, fmt="text"):
        """save report to file."""
        content = self.to_text() if fmt == "text" else self.to_json()
        with open(filepath, "w") as f:
            f.write(content)


if __name__ == "__main__":
    report = SecurityReport()
    report.set_metadata(target="192.168.1.0/24", scan_type="network")
    report.add_section("scope", "internal network scan of 254 hosts")
    report.add_finding(
        "ssh with password auth enabled", "medium",
        "host 192.168.1.10 allows ssh password authentication",
        "disable password auth in sshd_config",
    )
    report.add_finding(
        "outdated ssl certificate", "high",
        "host 192.168.1.20 has expired ssl certificate",
        "renew certificate and update server config",
    )
    print(report.to_text())
