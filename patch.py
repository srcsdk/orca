#!/usr/bin/env python3
"""system configuration and patch auditor"""

import argparse
import json
import os
import platform
import re
import stat
import subprocess
from datetime import datetime
from pathlib import Path


def get_os():
    return platform.system().lower()


class AuditResult:
    """stores a single audit check result"""

    def __init__(self, name, status, message, category="general"):
        self.name = name
        self.status = status
        self.message = message
        self.category = category
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "category": self.category,
            "timestamp": self.timestamp,
        }


class ConfigAuditor:
    """audit system configuration files"""

    def __init__(self):
        self.results = []
        self.os_type = get_os()

    def add(self, name, status, message, category="config"):
        self.results.append(AuditResult(name, status, message, category))

    def audit_sshd(self):
        """check sshd configuration against best practices"""
        if self.os_type == "windows":
            config_path = Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData")) / \
                "ssh" / "sshd_config"
        else:
            config_path = Path("/etc/ssh/sshd_config")

        if not config_path.exists():
            self.add("sshd_config", "skip", "file not found")
            return

        content = config_path.read_text()
        checks = {
            "permit_root_login": {
                "pattern": r"^\s*PermitRootLogin\s+(\S+)",
                "bad": ["yes"],
                "description": "root login should be disabled",
            },
            "password_auth": {
                "pattern": r"^\s*PasswordAuthentication\s+(\S+)",
                "bad": ["yes"],
                "description": "prefer key-based authentication",
            },
            "empty_passwords": {
                "pattern": r"^\s*PermitEmptyPasswords\s+(\S+)",
                "bad": ["yes"],
                "description": "empty passwords must be disabled",
            },
            "x11_forwarding": {
                "pattern": r"^\s*X11Forwarding\s+(\S+)",
                "bad": ["yes"],
                "description": "x11 forwarding should be disabled",
            },
            "max_auth_tries": {
                "pattern": r"^\s*MaxAuthTries\s+(\d+)",
                "max_value": 4,
                "description": "max auth tries should be <= 4",
            },
            "protocol": {
                "pattern": r"^\s*Protocol\s+(\S+)",
                "bad": ["1", "1,2"],
                "description": "only protocol 2 should be used",
            },
        }

        for name, check in checks.items():
            match = re.search(check["pattern"], content, re.MULTILINE)
            if not match:
                self.add(f"sshd_{name}", "info",
                         f"not explicitly set ({check['description']})")
                continue
            value = match.group(1).lower()
            if "bad" in check and value in check["bad"]:
                self.add(f"sshd_{name}", "fail", check["description"])
            elif "max_value" in check:
                if int(value) > check["max_value"]:
                    self.add(f"sshd_{name}", "fail", check["description"])
                else:
                    self.add(f"sshd_{name}", "pass", f"set to {value}")
            else:
                self.add(f"sshd_{name}", "pass", f"set to {value}")

    def audit_file_permissions(self):
        """check critical file permissions"""
        if self.os_type == "windows":
            self._audit_windows_permissions()
            return
        if self.os_type == "darwin":
            self._audit_unix_permissions(macos=True)
            return
        self._audit_unix_permissions(macos=False)

    def _audit_unix_permissions(self, macos=False):
        """check unix file permissions"""
        critical_files = {
            "/etc/passwd": {"max_mode": 0o644, "owner": "root"},
            "/etc/group": {"max_mode": 0o644, "owner": "root"},
        }
        if not macos:
            critical_files.update({
                "/etc/shadow": {"max_mode": 0o640, "owner": "root"},
                "/etc/gshadow": {"max_mode": 0o640, "owner": "root"},
                "/etc/ssh/sshd_config": {"max_mode": 0o600, "owner": "root"},
                "/etc/crontab": {"max_mode": 0o644, "owner": "root"},
            })

        import pwd as _pwd
        for filepath, expected in critical_files.items():
            path = Path(filepath)
            if not path.exists():
                continue
            try:
                st = path.stat()
                mode = stat.S_IMODE(st.st_mode)
                owner = _pwd.getpwuid(st.st_uid).pw_name
                if mode > expected["max_mode"]:
                    self.add(
                        f"perms_{path.name}", "fail",
                        f"{filepath} has mode {oct(mode)} "
                        f"(expected <= {oct(expected['max_mode'])})",
                        "permissions"
                    )
                elif owner != expected["owner"]:
                    self.add(
                        f"perms_{path.name}", "fail",
                        f"{filepath} owned by {owner} "
                        f"(expected {expected['owner']})",
                        "permissions"
                    )
                else:
                    self.add(
                        f"perms_{path.name}", "pass",
                        f"{filepath} ok ({oct(mode)}, {owner})",
                        "permissions"
                    )
            except (PermissionError, KeyError):
                self.add(f"perms_{path.name}", "skip",
                         f"cannot check {filepath}", "permissions")

    def _audit_windows_permissions(self):
        """check windows system file access controls"""
        sys_root = os.environ.get("SYSTEMROOT", "C:\\Windows")
        critical = [
            os.path.join(sys_root, "System32", "config"),
            os.path.join(sys_root, "System32", "drivers", "etc", "hosts"),
        ]
        for filepath in critical:
            if os.path.exists(filepath):
                self.add(f"perms_{os.path.basename(filepath)}", "info",
                         f"{filepath} exists (use icacls to verify acls)",
                         "permissions")
            else:
                self.add(f"perms_{os.path.basename(filepath)}", "skip",
                         f"{filepath} not found", "permissions")

    def audit_world_writable(self, search_path=None):
        """find world-writable files"""
        if self.os_type == "windows":
            self.add("world_writable", "skip",
                     "world-writable check not applicable on windows",
                     "permissions")
            return

        if search_path is None:
            search_path = "/etc"

        writable = []
        try:
            for root, dirs, files in os.walk(search_path):
                for name in files:
                    fpath = os.path.join(root, name)
                    try:
                        st = os.stat(fpath)
                        if st.st_mode & stat.S_IWOTH:
                            writable.append(fpath)
                    except (OSError, PermissionError):
                        continue
        except PermissionError:
            pass

        if writable:
            self.add("world_writable", "fail",
                     f"found {len(writable)} world-writable files in "
                     f"{search_path}: {', '.join(writable[:5])}",
                     "permissions")
        else:
            self.add("world_writable", "pass",
                     f"no world-writable files in {search_path}",
                     "permissions")

    def audit_suid_binaries(self):
        """check for unexpected suid binaries"""
        if self.os_type == "windows":
            self.add("suid_check", "skip",
                     "suid check not applicable on windows", "permissions")
            return

        known_suid = {
            "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su",
            "/usr/bin/newgrp", "/usr/bin/chsh", "/usr/bin/chfn",
            "/usr/bin/gpasswd", "/usr/bin/mount", "/usr/bin/umount",
            "/usr/bin/pkexec", "/usr/bin/crontab",
        }
        found_suid = []
        search_dirs = ["/usr/bin", "/usr/sbin", "/usr/local/bin"]
        if self.os_type == "darwin":
            search_dirs.append("/usr/local/sbin")

        for search_dir in search_dirs:
            if not os.path.isdir(search_dir):
                continue
            try:
                for name in os.listdir(search_dir):
                    fpath = os.path.join(search_dir, name)
                    try:
                        st = os.stat(fpath)
                        if st.st_mode & stat.S_ISUID:
                            if fpath not in known_suid:
                                found_suid.append(fpath)
                    except OSError:
                        continue
            except PermissionError:
                continue

        if found_suid:
            self.add("suid_check", "warn",
                     f"unexpected suid binaries: {', '.join(found_suid)}",
                     "permissions")
        else:
            self.add("suid_check", "pass",
                     "no unexpected suid binaries found",
                     "permissions")


class PackageAuditor:
    """check package versions and updates"""

    def __init__(self):
        self.results = []
        self.os_type = get_os()

    def add(self, name, status, message):
        self.results.append(AuditResult(name, status, message, "packages"))

    def check_updates(self):
        """check for available package updates"""
        if self.os_type == "windows":
            return self._check_winget()
        if self.os_type == "darwin":
            return self._check_brew()
        if os.path.exists("/usr/bin/apt"):
            return self._check_apt()
        if os.path.exists("/usr/bin/dnf"):
            return self._check_dnf()
        if os.path.exists("/usr/bin/pacman"):
            return self._check_pacman()
        self.add("pkg_manager", "skip", "no supported package manager found")

    def _check_apt(self):
        try:
            result = subprocess.run(
                ["apt", "list", "--upgradable"],
                capture_output=True, text=True, timeout=30
            )
            lines = [ln for ln in result.stdout.strip().split("\n")
                     if "upgradable" in ln.lower()]
            if lines:
                self.add("apt_updates", "warn",
                         f"{len(lines)} packages have updates available")
                for line in lines[:10]:
                    pkg = line.split("/")[0] if "/" in line else line
                    self.add(f"apt_update_{pkg}", "info", line.strip())
            else:
                self.add("apt_updates", "pass", "all packages up to date")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.add("apt_updates", "skip", "could not check apt updates")

    def _check_dnf(self):
        try:
            result = subprocess.run(
                ["dnf", "check-update", "-q"],
                capture_output=True, text=True, timeout=60
            )
            lines = [ln for ln in result.stdout.strip().split("\n") if ln.strip()]
            if lines:
                self.add("dnf_updates", "warn",
                         f"{len(lines)} packages have updates available")
            else:
                self.add("dnf_updates", "pass", "all packages up to date")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.add("dnf_updates", "skip", "could not check dnf updates")

    def _check_pacman(self):
        try:
            result = subprocess.run(
                ["pacman", "-Qu"],
                capture_output=True, text=True, timeout=30
            )
            lines = [ln for ln in result.stdout.strip().split("\n") if ln.strip()]
            if lines:
                self.add("pacman_updates", "warn",
                         f"{len(lines)} packages have updates available")
            else:
                self.add("pacman_updates", "pass", "all packages up to date")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.add("pacman_updates", "skip", "could not check pacman")

    def _check_brew(self):
        """check homebrew for outdated packages"""
        try:
            result = subprocess.run(
                ["brew", "outdated"],
                capture_output=True, text=True, timeout=60
            )
            lines = [ln for ln in result.stdout.strip().split("\n") if ln.strip()]
            if lines:
                self.add("brew_updates", "warn",
                         f"{len(lines)} brew packages have updates")
                for line in lines[:10]:
                    self.add(f"brew_update_{line.split()[0]}", "info",
                             line.strip())
            else:
                self.add("brew_updates", "pass", "all brew packages up to date")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.add("brew_updates", "skip", "homebrew not available")

    def _check_winget(self):
        """check winget for available updates"""
        try:
            result = subprocess.run(
                ["winget", "upgrade"],
                capture_output=True, text=True, timeout=60
            )
            lines = result.stdout.strip().split("\n")
            upgrade_lines = [ln for ln in lines
                             if ln.strip() and not ln.startswith("-")
                             and not ln.startswith("Name")]
            count = max(0, len(upgrade_lines) - 1)
            if count > 0:
                self.add("winget_updates", "warn",
                         f"{count} packages have updates via winget")
            else:
                self.add("winget_updates", "pass",
                         "all winget packages up to date")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.add("winget_updates", "skip", "winget not available")


def generate_report(config_results, package_results, output_format="text"):
    """generate audit report"""
    all_results = config_results + package_results
    if output_format == "json":
        return json.dumps({
            "audit_date": datetime.now().isoformat(),
            "platform": platform.system(),
            "total_checks": len(all_results),
            "passed": sum(1 for r in all_results if r.status == "pass"),
            "failed": sum(1 for r in all_results if r.status == "fail"),
            "warnings": sum(1 for r in all_results if r.status == "warn"),
            "results": [r.to_dict() for r in all_results],
        }, indent=2)

    lines = [
        f"audit report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
        f"({platform.system()})",
        "",
    ]
    status_map = {"pass": "PASS", "fail": "FAIL", "warn": "WARN",
                  "info": "INFO", "skip": "SKIP"}
    current_cat = ""
    for r in all_results:
        if r.category != current_cat:
            current_cat = r.category
            lines.append(f"--- {current_cat} ---")
        tag = status_map.get(r.status, "????")
        lines.append(f"[{tag}] {r.message}")
    lines.append("")
    passed = sum(1 for r in all_results if r.status == "pass")
    failed = sum(1 for r in all_results if r.status == "fail")
    warned = sum(1 for r in all_results if r.status == "warn")
    lines.append(f"total: {len(all_results)} checks, "
                 f"{passed} passed, {failed} failed, {warned} warnings")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="system configuration auditor")
    parser.add_argument("-c", "--config", action="store_true",
                        help="audit config files")
    parser.add_argument("-p", "--packages", action="store_true",
                        help="audit packages")
    parser.add_argument("-o", "--output", help="write report to file")
    parser.add_argument("--json", action="store_true",
                        help="output as json")
    args = parser.parse_args()

    if not args.config and not args.packages:
        args.config = True
        args.packages = True

    config_auditor = ConfigAuditor()
    package_auditor = PackageAuditor()

    if args.config:
        config_auditor.audit_sshd()
        config_auditor.audit_file_permissions()
        config_auditor.audit_world_writable()
        config_auditor.audit_suid_binaries()

    if args.packages:
        package_auditor.check_updates()

    fmt = "json" if args.json else "text"
    report = generate_report(
        config_auditor.results, package_auditor.results, fmt
    )
    print(report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"\nreport saved to {args.output}")


if __name__ == "__main__":
    main()
