#!/usr/bin/env python3
"""scan codebases and configs for leaked secrets"""

import os
import re


SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("aws_secret_key", re.compile(r"""(?:aws|AWS).*(?:secret|SECRET).*['"][0-9a-zA-Z/+=]{40}['"]""")),
    ("github_token", re.compile(r'gh[ps]_[A-Za-z0-9_]{36,}')),
    ("generic_api_key", re.compile(r"""(?:api[_-]?key|apikey)\s*[=:]\s*['"][a-zA-Z0-9]{20,}['"]""", re.I)),
    ("generic_secret", re.compile(r"""(?:secret|password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]""", re.I)),
    ("private_key", re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----')),
    ("jwt_token", re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')),
    ("slack_webhook", re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+')),
]

IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"}
IGNORE_EXTENSIONS = {".pyc", ".pyo", ".so", ".o", ".a", ".jpg", ".png", ".gif", ".ico"}


class SecretScanner:
    """scan files for leaked secrets and credentials."""

    def __init__(self, patterns=None):
        self.patterns = patterns or SECRET_PATTERNS
        self.findings = []
        self.scanned_files = 0

    def scan_file(self, filepath):
        """scan a single file for secrets."""
        ext = os.path.splitext(filepath)[1]
        if ext in IGNORE_EXTENSIONS:
            return []
        try:
            with open(filepath, errors="ignore") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError):
            return []
        self.scanned_files += 1
        file_findings = []
        for name, pattern in self.patterns:
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                file_findings.append({
                    "type": name,
                    "file": filepath,
                    "line": line_num,
                    "match": self._redact(match.group()),
                })
        self.findings.extend(file_findings)
        return file_findings

    def scan_directory(self, directory, recursive=True):
        """scan directory for secrets."""
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for fname in files:
                self.scan_file(os.path.join(root, fname))
            if not recursive:
                break
        return self.findings

    def scan_env_file(self, filepath):
        """specifically scan .env files."""
        findings = []
        try:
            with open(filepath) as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, val = line.split("=", 1)
                        val = val.strip().strip("'\"")
                        if len(val) > 8 and not val.startswith("${"):
                            sensitive = any(
                                w in key.upper()
                                for w in [
                                    "SECRET", "PASSWORD", "TOKEN",
                                    "KEY", "PRIVATE",
                                ]
                            )
                            if sensitive:
                                findings.append({
                                    "type": "env_secret",
                                    "file": filepath,
                                    "line": i,
                                    "variable": key,
                                })
        except OSError:
            pass
        self.findings.extend(findings)
        return findings

    def _redact(self, text, show=4):
        """partially redact a secret value."""
        if len(text) <= show * 2:
            return "*" * len(text)
        return text[:show] + "*" * (len(text) - show * 2) + text[-show:]

    def summary(self):
        """get scan summary."""
        by_type = {}
        for f in self.findings:
            t = f["type"]
            by_type[t] = by_type.get(t, 0) + 1
        return {
            "files_scanned": self.scanned_files,
            "total_findings": len(self.findings),
            "by_type": by_type,
        }


if __name__ == "__main__":
    scanner = SecretScanner()
    print(f"secret scanner ready, {len(scanner.patterns)} patterns loaded")
