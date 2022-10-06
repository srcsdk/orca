#!/usr/bin/env python3
"""container and image security scanning"""

import subprocess
import json


class ContainerScanner:
    """scan docker containers and images for vulnerabilities."""

    def __init__(self):
        self.findings = []

    def scan_image(self, image_name):
        """scan a docker image for known vulnerabilities."""
        layers = self._get_image_layers(image_name)
        findings = []
        for layer in layers:
            issues = self._check_layer(layer)
            findings.extend(issues)
        env_secrets = self._check_env_vars(image_name)
        findings.extend(env_secrets)
        self.findings.extend(findings)
        return {
            "image": image_name,
            "layers": len(layers),
            "findings": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "CRIT"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        }

    def _get_image_layers(self, image_name):
        """get image layer information."""
        try:
            result = subprocess.run(
                ["docker", "history", "--no-trunc", "--format",
                 "{{.CreatedBy}}", image_name],
                capture_output=True, text=True, timeout=30,
            )
            return result.stdout.strip().splitlines()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    def _check_layer(self, layer_cmd):
        """check a layer command for security issues."""
        issues = []
        danger_patterns = {
            "curl | sh": ("CRIT", "remote code execution via curl pipe"),
            "wget -O- | sh": ("CRIT", "remote code execution via wget pipe"),
            "chmod 777": ("HIGH", "world-writable permissions"),
            "ADD http": ("MED", "fetching remote files at build time"),
        }
        for pattern, (severity, desc) in danger_patterns.items():
            if pattern in layer_cmd:
                issues.append({
                    "type": "layer_issue",
                    "severity": severity,
                    "description": desc,
                    "layer": layer_cmd[:100],
                })
        return issues

    def _check_env_vars(self, image_name):
        """check for secrets in environment variables."""
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format",
                 "{{json .Config.Env}}", image_name],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return []
            env_vars = json.loads(result.stdout.strip())
            secret_patterns = [
                "PASSWORD", "SECRET", "API_KEY", "TOKEN",
                "PRIVATE_KEY", "AWS_ACCESS",
            ]
            findings = []
            for var in env_vars:
                name = var.split("=")[0] if "=" in var else var
                for pattern in secret_patterns:
                    if pattern in name.upper():
                        findings.append({
                            "type": "env_secret",
                            "severity": "HIGH",
                            "description": f"potential secret in env: {name}",
                            "variable": name,
                        })
            return findings
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return []

    def scan_running(self):
        """scan all running containers."""
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Image}}"],
                capture_output=True, text=True, timeout=10,
            )
            images = result.stdout.strip().splitlines()
            results = []
            for image in images:
                scan = self.scan_image(image)
                results.append(scan)
            return results
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    def get_findings(self, min_severity="LOW"):
        """get findings above severity threshold."""
        levels = {"INFO": 0, "LOW": 1, "MED": 2, "HIGH": 3, "CRIT": 4}
        threshold = levels.get(min_severity, 0)
        return [
            f for f in self.findings
            if levels.get(f.get("severity"), 0) >= threshold
        ]


if __name__ == "__main__":
    scanner = ContainerScanner()
    print(f"container scanner ready, findings: {len(scanner.findings)}")
