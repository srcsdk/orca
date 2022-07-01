#!/usr/bin/env python3
"""basic vulnerability scanning and reporting"""

import os
import re
import stat


def check_file_permissions(directory, sensitive_patterns=None):
    """check for overly permissive file permissions."""
    if sensitive_patterns is None:
        sensitive_patterns = [
            r"\.env$", r"\.pem$", r"\.key$", r"id_rsa",
            r"credentials", r"secret", r"password",
        ]
    findings = []
    for root, dirs, files in os.walk(directory):
        for name in files:
            path = os.path.join(root, name)
            try:
                mode = os.stat(path).st_mode
                is_sensitive = any(
                    re.search(p, name, re.IGNORECASE)
                    for p in sensitive_patterns
                )
                if is_sensitive and mode & stat.S_IROTH:
                    findings.append({
                        "path": path,
                        "issue": "world-readable sensitive file",
                        "severity": "high",
                        "mode": oct(mode)[-3:],
                    })
                elif mode & stat.S_IWOTH:
                    findings.append({
                        "path": path,
                        "issue": "world-writable file",
                        "severity": "medium",
                        "mode": oct(mode)[-3:],
                    })
            except (OSError, PermissionError):
                continue
    return findings


def check_exposed_secrets(directory, extensions=None):
    """scan files for exposed secrets and credentials."""
    if extensions is None:
        extensions = [".py", ".js", ".json", ".yml", ".yaml", ".cfg", ".ini"]
    patterns = [
        (r"""(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]+['"]""",
         "hardcoded password"),
        (r"""(?:api_key|apikey|api-key)\s*[=:]\s*['"][^'"]+['"]""",
         "hardcoded api key"),
        (r"""(?:secret|token)\s*[=:]\s*['"][A-Za-z0-9+/=]{20,}['"]""",
         "hardcoded secret or token"),
        (r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
         "embedded private key"),
    ]
    findings = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in {
            ".git", "node_modules", "__pycache__", "venv",
        }]
        for name in files:
            ext = os.path.splitext(name)[1]
            if ext not in extensions:
                continue
            path = os.path.join(root, name)
            try:
                with open(path, errors="replace") as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern, desc in patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    "file": path,
                                    "line": line_num,
                                    "issue": desc,
                                    "severity": "critical",
                                })
            except (OSError, PermissionError):
                continue
    return findings


def check_outdated_deps(requirements_file):
    """check for known patterns in requirements files."""
    if not os.path.isfile(requirements_file):
        return []
    findings = []
    with open(requirements_file) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "==" in line:
                name, version = line.split("==", 1)
                findings.append({
                    "package": name.strip(),
                    "pinned_version": version.strip(),
                    "line": line_num,
                    "note": "pinned version, check for updates",
                })
    return findings


def format_findings(findings):
    """format vulnerability findings for display."""
    if not findings:
        return "no findings"
    lines = [f"found {len(findings)} issues:"]
    for f in findings:
        severity = f.get("severity", "info").upper()
        issue = f.get("issue", "unknown")
        location = f.get("path", f.get("file", ""))
        line = f.get("line", "")
        loc = f"{location}:{line}" if line else location
        lines.append(f"  [{severity}] {issue} - {loc}")
    return "\n".join(lines)


if __name__ == "__main__":
    findings = check_file_permissions(".")
    print(f"permission issues: {len(findings)}")
    print(format_findings(findings))
