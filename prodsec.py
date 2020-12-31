#!/usr/bin/env python3
"""automated server hardening checks against cis benchmarks"""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def get_os():
    return platform.system().lower()


class Check:
    def __init__(self, status, benchmark, message, details=""):
        self.status = status
        self.benchmark = benchmark
        self.message = message
        self.details = details
        self.timestamp = datetime.now()

    def to_dict(self):
        return {
            "status": self.status,
            "benchmark": self.benchmark,
            "message": self.message,
            "details": self.details,
        }


class CisBenchmark:
    def __init__(self):
        self.checks = []
        self.baseline = None
        self.os_type = get_os()

    def add_check(self, status, benchmark, message, details=""):
        self.checks.append(Check(status, benchmark, message, details))

    def check_ssh(self):
        """cis 5.2 - ssh server configuration"""
        if self.os_type == "windows":
            sshd_config = Path(
                os.environ.get("PROGRAMDATA", "C:\\ProgramData")
            ) / "ssh" / "sshd_config"
        else:
            sshd_config = Path("/etc/ssh/sshd_config")

        if not sshd_config.exists():
            self.add_check("info", "5.2", "sshd_config not found")
            return

        content = sshd_config.read_text()

        ssh_checks = [
            ("5.2.1", r'^\s*Protocol\s+1', False,
             "ssh protocol version", "protocol 1 must be disabled"),
            ("5.2.2", r'^\s*LogLevel\s+(INFO|VERBOSE)', True,
             "ssh loglevel", "loglevel should be INFO or VERBOSE"),
            ("5.2.3", r'^\s*X11Forwarding\s+no', True,
             "x11 forwarding", "x11 forwarding should be disabled"),
            ("5.2.4", r'^\s*MaxAuthTries\s+[1-4]\s*$', True,
             "max auth tries", "should be 4 or less"),
            ("5.2.5", r'^\s*IgnoreRhosts\s+yes', True,
             "ignore rhosts", "rhosts should be ignored"),
            ("5.2.6", r'^\s*PermitRootLogin\s+(no|prohibit-password)', True,
             "root login", "root login should be restricted"),
            ("5.2.7", r'^\s*PermitEmptyPasswords\s+no', True,
             "empty passwords", "empty passwords must be disabled"),
            ("5.2.8", r'^\s*PasswordAuthentication\s+no', True,
             "password auth", "prefer key-based authentication"),
            ("5.2.9", r'^\s*ClientAliveInterval\s+\d+', True,
             "client alive interval", "idle timeout should be configured"),
            ("5.2.10", r'^\s*ClientAliveCountMax\s+[0-3]\s*$', True,
             "client alive count max", "should be 3 or less"),
            ("5.2.11", r'^\s*AllowUsers\s+|^\s*AllowGroups\s+', True,
             "ssh access control", "allow users/groups should be configured"),
            ("5.2.12", r'^\s*Banner\s+\S+', True,
             "ssh banner", "warning banner should be configured"),
        ]

        for benchmark, pattern, should_match, name, detail in ssh_checks:
            found = bool(re.search(pattern, content, re.MULTILINE | re.IGNORECASE))
            if found == should_match:
                self.add_check("pass", benchmark, name)
            else:
                self.add_check("fail", benchmark, name, detail)

        if self.os_type != "windows":
            for key_type in ["rsa", "ecdsa", "ed25519"]:
                key_path = Path(f"/etc/ssh/ssh_host_{key_type}_key")
                if key_path.exists():
                    perms = oct(key_path.stat().st_mode)[-3:]
                    if perms in ("600", "400"):
                        self.add_check("pass", "5.2.13",
                                       f"host key permissions ({key_type}): {perms}")
                    else:
                        self.add_check("fail", "5.2.13",
                                       f"host key permissions too open ({key_type}): {perms}")

    def check_permissions(self):
        """cis 6.1 - system file permissions"""
        if self.os_type == "windows":
            self._check_windows_permissions()
            return

        file_checks = [
            ("/etc/passwd", "644", "6.1.2"),
            ("/etc/group", "644", "6.1.4"),
        ]
        if self.os_type == "linux":
            file_checks.extend([
                ("/etc/shadow", "640", "6.1.3"),
                ("/etc/gshadow", "640", "6.1.5"),
                ("/etc/passwd-", "600", "6.1.6"),
                ("/etc/shadow-", "600", "6.1.7"),
                ("/etc/group-", "600", "6.1.8"),
            ])

        for filepath, expected, benchmark in file_checks:
            path = Path(filepath)
            if not path.exists():
                continue
            actual = oct(path.stat().st_mode)[-3:]
            if int(actual) <= int(expected):
                self.add_check("pass", benchmark, f"{filepath} permissions: {actual}")
            else:
                self.add_check("fail", benchmark,
                               f"{filepath} permissions: {actual} (expected {expected} or stricter)")

        # world-writable files check (unix only)
        try:
            for root, dirs, files in os.walk("/etc", topdown=True):
                depth = root.replace("/etc", "").count(os.sep)
                if depth >= 2:
                    dirs.clear()
                    continue
                for name in files:
                    fpath = os.path.join(root, name)
                    try:
                        if os.stat(fpath).st_mode & 0o002:
                            self.add_check("fail", "6.1.10",
                                           f"world-writable: {fpath}")
                    except OSError:
                        continue
        except PermissionError:
            pass

    def _check_windows_permissions(self):
        """basic windows permission checks"""
        sys_root = os.environ.get("SYSTEMROOT", "C:\\Windows")
        critical_dirs = [
            os.path.join(sys_root, "System32"),
            os.path.join(sys_root, "System32", "config"),
        ]
        for d in critical_dirs:
            if os.path.isdir(d):
                self.add_check("info", "6.1.w",
                               f"{d} exists (verify acls with icacls)")
            else:
                self.add_check("warn", "6.1.w", f"{d} not found")

    def check_services(self):
        """cis 2.x - service audit"""
        if self.os_type == "windows":
            self._check_windows_services()
            return
        if self.os_type == "darwin":
            self._check_macos_services()
            return

        risky_services = {
            "telnet": ("2.1.1", "critical"),
            "rsh": ("2.1.2", "critical"),
            "rlogin": ("2.1.3", "critical"),
            "tftp": ("2.1.4", "high"),
            "xinetd": ("2.1.5", "medium"),
            "avahi-daemon": ("2.1.6", "medium"),
            "cups": ("2.1.7", "low"),
            "rpcbind": ("2.1.8", "medium"),
        }

        for service, (benchmark, severity) in risky_services.items():
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", service],
                    capture_output=True, text=True, timeout=5,
                )
                if result.stdout.strip() == "active":
                    self.add_check("fail", benchmark,
                                   f"{service} is running (consider disabling)")
                else:
                    self.add_check("pass", benchmark, f"{service} is not running")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        self._check_firewall()

    def _check_macos_services(self):
        """check macos services via launchctl"""
        risky = ["com.apple.telnetd", "com.apple.ftpd",
                 "com.apple.screensharing"]
        for service in risky:
            try:
                result = subprocess.run(
                    ["launchctl", "print", f"system/{service}"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    self.add_check("warn", "2.x.m",
                                   f"{service} is loaded")
                else:
                    self.add_check("pass", "2.x.m",
                                   f"{service} is not loaded")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        if shutil.which("pfctl"):
            try:
                result = subprocess.run(
                    ["pfctl", "-s", "info"],
                    capture_output=True, text=True, timeout=5,
                )
                if "enabled" in result.stdout.lower() or "enabled" in result.stderr.lower():
                    self.add_check("pass", "3.5.1", "pf firewall is enabled")
                else:
                    self.add_check("warn", "3.5.1", "pf firewall may be disabled")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

    def _check_windows_services(self):
        """check windows services"""
        risky = {
            "TlntSvr": ("2.1.w", "telnet server"),
            "FTPSVC": ("2.2.w", "ftp server"),
            "RemoteRegistry": ("2.3.w", "remote registry"),
        }
        for svc_name, (benchmark, desc) in risky.items():
            try:
                result = subprocess.run(
                    ["sc", "query", svc_name],
                    capture_output=True, text=True, timeout=5,
                )
                if "RUNNING" in result.stdout:
                    self.add_check("fail", benchmark, f"{desc} is running")
                else:
                    self.add_check("pass", benchmark, f"{desc} is not running")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=5,
            )
            if "ON" in result.stdout.upper():
                self.add_check("pass", "3.5.w", "windows firewall is enabled")
            else:
                self.add_check("fail", "3.5.w", "windows firewall is disabled")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    def _check_firewall(self):
        """check firewall status on linux"""
        firewall_active = False
        for fw in ["ufw", "firewalld"]:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", fw],
                    capture_output=True, text=True, timeout=5,
                )
                if result.stdout.strip() == "active":
                    self.add_check("pass", "3.5.1", f"firewall active: {fw}")
                    firewall_active = True
                    break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        if not firewall_active:
            try:
                result = subprocess.run(
                    ["iptables", "-L"],
                    capture_output=True, text=True, timeout=5,
                )
                rules = len([l for l in result.stdout.splitlines()
                             if l and not l.startswith("Chain")
                             and not l.startswith("target")])
                if rules > 0:
                    self.add_check("pass", "3.5.1", f"iptables has {rules} rules")
                    firewall_active = True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        if not firewall_active:
            self.add_check("fail", "3.5.1", "no active firewall detected")

    def check_password_policy(self):
        """cis 5.4 - password policy"""
        if self.os_type == "windows":
            self._check_windows_password_policy()
            return

        login_defs = Path("/etc/login.defs")
        if login_defs.exists():
            content = login_defs.read_text()

            max_days = re.search(r'^\s*PASS_MAX_DAYS\s+(\d+)', content, re.MULTILINE)
            if max_days and int(max_days.group(1)) <= 90:
                self.add_check("pass", "5.4.1.1",
                               f"password max age: {max_days.group(1)} days")
            else:
                self.add_check("fail", "5.4.1.1",
                               f"password max age: {max_days.group(1) if max_days else 'not set'}")

            min_days = re.search(r'^\s*PASS_MIN_DAYS\s+(\d+)', content, re.MULTILINE)
            if min_days and int(min_days.group(1)) >= 1:
                self.add_check("pass", "5.4.1.2",
                               f"password min age: {min_days.group(1)} days")
            else:
                self.add_check("warn", "5.4.1.2",
                               "password min age not configured")

            min_len = re.search(r'^\s*PASS_MIN_LEN\s+(\d+)', content, re.MULTILINE)
            if min_len and int(min_len.group(1)) >= 8:
                self.add_check("pass", "5.4.1.3",
                               f"password min length: {min_len.group(1)}")
            else:
                self.add_check("fail", "5.4.1.3",
                               "password min length should be >= 8")

        passwd = Path("/etc/passwd")
        if passwd.exists():
            uid0 = [l.split(":")[0] for l in passwd.read_text().splitlines()
                     if l.split(":")[2] == "0" if len(l.split(":")) > 2]
            if len(uid0) == 1:
                self.add_check("pass", "6.2.5", "only root has uid 0")
            else:
                self.add_check("fail", "6.2.5",
                               f"multiple uid 0 accounts: {', '.join(uid0)}")

        shadow = Path("/etc/shadow")
        if shadow.exists():
            try:
                content = shadow.read_text()
                empty_pw = [l.split(":")[0] for l in content.splitlines()
                            if len(l.split(":")) > 1 and l.split(":")[1] == ""]
                if not empty_pw:
                    self.add_check("pass", "6.2.1", "no accounts with empty passwords")
                else:
                    self.add_check("fail", "6.2.1",
                                   f"accounts with empty passwords: {', '.join(empty_pw)}")
            except PermissionError:
                self.add_check("info", "6.2.1",
                               "cannot read /etc/shadow (need root)")

    def _check_windows_password_policy(self):
        """check windows password policy via net accounts"""
        try:
            result = subprocess.run(
                ["net", "accounts"],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout
            max_match = re.search(r'Maximum password age.*?:\s*(\d+)', output)
            min_match = re.search(r'Minimum password length.*?:\s*(\d+)', output)

            if max_match:
                max_age = int(max_match.group(1))
                if max_age <= 90:
                    self.add_check("pass", "5.4.w",
                                   f"password max age: {max_age} days")
                else:
                    self.add_check("fail", "5.4.w",
                                   f"password max age: {max_age} days (should be <= 90)")

            if min_match:
                min_len = int(min_match.group(1))
                if min_len >= 8:
                    self.add_check("pass", "5.4.w.2",
                                   f"password min length: {min_len}")
                else:
                    self.add_check("fail", "5.4.w.2",
                                   f"password min length: {min_len} (should be >= 8)")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.add_check("skip", "5.4.w", "cannot check windows password policy")

    def check_privilege_escalation(self):
        """check for common privilege escalation paths"""
        if self.os_type == "windows":
            self._check_windows_privesc()
            return

        sudoers = Path("/etc/sudoers")
        if sudoers.exists():
            try:
                content = sudoers.read_text()
                if "NOPASSWD" in content:
                    nopasswd_lines = [l.strip() for l in content.splitlines()
                                       if "NOPASSWD" in l and not l.strip().startswith("#")]
                    if nopasswd_lines:
                        self.add_check("warn", "priv.1",
                                       f"{len(nopasswd_lines)} NOPASSWD sudo rules",
                                       "; ".join(nopasswd_lines[:3]))
            except PermissionError:
                pass

        path_dirs = os.environ.get("PATH", "").split(os.pathsep)
        for d in path_dirs:
            if os.path.exists(d):
                try:
                    perms = oct(os.stat(d).st_mode)[-3:]
                    if int(perms[-1]) >= 2:
                        self.add_check("warn", "priv.2",
                                       f"world-writable directory in PATH: {d}")
                except OSError:
                    pass

    def _check_windows_privesc(self):
        """check windows privilege escalation vectors"""
        path_dirs = os.environ.get("PATH", "").split(";")
        for d in path_dirs:
            if not os.path.isdir(d):
                continue
            try:
                if os.access(d, os.W_OK):
                    sys_root = os.environ.get("SYSTEMROOT", "C:\\Windows")
                    if not d.lower().startswith(sys_root.lower()):
                        self.add_check("warn", "priv.w",
                                       f"writable non-system directory in PATH: {d}")
            except OSError:
                pass

    def check_docker(self):
        """audit docker security configuration"""
        docker_path = shutil.which("docker")
        if not docker_path:
            self.add_check("info", "docker.0", "docker not installed")
            return

        try:
            result = subprocess.run(
                ["docker", "info", "--format", "{{json .}}"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                self.add_check("info", "docker.0",
                               "docker not accessible (daemon not running?)")
                return

            info = json.loads(result.stdout)
            if info.get("LiveRestoreEnabled"):
                self.add_check("pass", "docker.1", "live restore is enabled")
            else:
                self.add_check("warn", "docker.1", "live restore is not enabled")

            if info.get("SecurityOptions"):
                sec_opts = " ".join(str(s) for s in info["SecurityOptions"])
                self.add_check("info", "docker.2", f"security: {sec_opts}")

        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            self.add_check("skip", "docker.0", "could not query docker")

        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"],
                capture_output=True, text=True, timeout=10,
            )
            containers = [l for l in result.stdout.strip().split("\n") if l.strip()]
            self.add_check("info", "docker.3",
                           f"{len(containers)} running containers")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    def save_baseline(self, filepath):
        """save current state as baseline"""
        report = self.get_report()
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

    def compare_baseline(self, filepath):
        """compare current state against saved baseline"""
        if not Path(filepath).exists():
            return []

        with open(filepath) as f:
            baseline = json.load(f)

        baseline_checks = {
            (c["benchmark"], c["message"]): c["status"]
            for c in baseline.get("checks", [])
        }

        drifts = []
        for check in self.checks:
            key = (check.benchmark, check.message)
            if key in baseline_checks:
                if baseline_checks[key] != check.status:
                    drifts.append({
                        "benchmark": check.benchmark,
                        "message": check.message,
                        "baseline_status": baseline_checks[key],
                        "current_status": check.status,
                    })

        return drifts

    def get_report(self):
        counts = {}
        for c in self.checks:
            counts[c.status] = counts.get(c.status, 0) + 1

        return {
            "timestamp": datetime.now().isoformat(),
            "platform": platform.system(),
            "total_checks": len(self.checks),
            "status_counts": counts,
            "score": (counts.get("pass", 0) /
                      max(len(self.checks), 1) * 100),
            "checks": [c.to_dict() for c in self.checks],
        }


def print_report(report, as_json=False):
    if as_json:
        print(json.dumps(report, indent=2))
        return

    print(f"\n[prodsec] hardening audit results ({report.get('platform', 'unknown')})")
    print(f"total checks: {report['total_checks']}")
    print(f"score: {report['score']:.0f}%")
    print(f"results: {report['status_counts']}")
    print()

    for check in report["checks"]:
        status = check["status"].upper().ljust(4)
        prefix = {"PASS": "+", "FAIL": "x", "WARN": "!", "INFO": "*"}
        marker = prefix.get(status.strip(), "-")
        print(f"  [{marker}] [{check['benchmark']:8s}] {check['message']}")
        if check.get("details"):
            print(f"                          {check['details']}")


def main():
    parser = argparse.ArgumentParser(description="server hardening audit")
    parser.add_argument("-m", "--mode", default="all",
                        choices=["ssh", "perms", "services", "password",
                                 "privesc", "docker", "all"],
                        help="audit mode")
    parser.add_argument("-o", "--output", help="output report file")
    parser.add_argument("--baseline", help="baseline file for drift detection")
    parser.add_argument("--save-baseline", help="save results as baseline")
    parser.add_argument("--json", action="store_true", help="json output")
    args = parser.parse_args()

    benchmark = CisBenchmark()

    mode_map = {
        "ssh": benchmark.check_ssh,
        "perms": benchmark.check_permissions,
        "services": benchmark.check_services,
        "password": benchmark.check_password_policy,
        "privesc": benchmark.check_privilege_escalation,
        "docker": benchmark.check_docker,
    }

    if args.mode == "all":
        for func in mode_map.values():
            func()
    else:
        mode_map[args.mode]()

    report = benchmark.get_report()

    if args.baseline:
        drifts = benchmark.compare_baseline(args.baseline)
        if drifts:
            print(f"\n[prodsec] configuration drift detected ({len(drifts)} changes):")
            for d in drifts:
                print(f"  [{d['benchmark']}] {d['message']}: "
                      f"{d['baseline_status']} -> {d['current_status']}")
        report["drifts"] = drifts

    print_report(report, args.json)

    if args.save_baseline:
        benchmark.save_baseline(args.save_baseline)
        print(f"\n[prodsec] baseline saved to {args.save_baseline}", file=sys.stderr)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[prodsec] report saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
