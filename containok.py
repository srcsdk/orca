#!/usr/bin/env python3
"""container and docker security scanner"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

PLATFORM = platform.system().lower()


class Finding:
    def __init__(self, severity, category, message, resource=""):
        self.severity = severity
        self.category = category
        self.message = message
        self.resource = resource
        self.timestamp = datetime.now()

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "resource": self.resource,
        }


class DockerScanner:
    def __init__(self):
        self.findings = []
        self._docker_available = None

    def add_finding(self, severity, category, message, resource=""):
        self.findings.append(Finding(severity, category, message, resource))

    def _run_docker(self, args):
        """run docker command and return output"""
        try:
            result = subprocess.run(
                ["docker"] + args,
                capture_output=True, text=True, timeout=30,
            )
            return result.stdout, result.returncode
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return "", 1

    def check_docker(self):
        """verify docker is available"""
        if self._docker_available is not None:
            return self._docker_available
        out, code = self._run_docker(["info"])
        self._docker_available = code == 0
        if not self._docker_available:
            self.add_finding("info", "runtime", "docker not available or not running")
        return self._docker_available

    def _daemon_config_path(self):
        """return platform-specific daemon.json path"""
        if PLATFORM == "windows":
            return Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData"),
                        "docker", "config", "daemon.json")
        elif PLATFORM == "darwin":
            home = Path.home()
            return home / ".docker" / "daemon.json"
        return Path("/etc/docker/daemon.json")

    def audit_daemon(self):
        """audit docker daemon configuration"""
        daemon_json = self._daemon_config_path()
        if not daemon_json.exists():
            self.add_finding("medium", "daemon",
                             f"no daemon.json at {daemon_json} (using defaults)")
            return

        try:
            config = json.loads(daemon_json.read_text())
        except json.JSONDecodeError:
            self.add_finding("high", "daemon", "daemon.json is not valid json")
            return

        checks = {
            "userns-remap": ("medium", "user namespace remapping not configured"),
            "no-new-privileges": ("medium", "no-new-privileges not set"),
            "live-restore": ("low", "live-restore not enabled"),
            "userland-proxy": ("low", "userland proxy setting not configured"),
        }
        for key, (severity, message) in checks.items():
            if key not in config:
                self.add_finding(severity, "daemon", message)
            else:
                self.add_finding("info", "daemon",
                                 f"{key} configured: {config[key]}")

        if config.get("icc") is not False:
            self.add_finding("medium", "daemon",
                             "inter-container communication not disabled")

        # check socket permissions (linux/macos only)
        if PLATFORM != "windows":
            socket_path = Path("/var/run/docker.sock")
            if socket_path.exists():
                stat = socket_path.stat()
                perms = oct(stat.st_mode)[-3:]
                if perms not in ("660", "600"):
                    self.add_finding("high", "daemon",
                                     f"docker socket permissions too open: {perms}")
                else:
                    self.add_finding("info", "daemon",
                                     f"socket permissions: {perms}")

    def audit_containers(self):
        """audit running containers"""
        if not self.check_docker():
            return

        out, _ = self._run_docker(["ps", "--format", "{{.ID}}"])
        container_ids = [cid.strip() for cid in out.splitlines() if cid.strip()]

        if not container_ids:
            self.add_finding("info", "containers", "no running containers")
            return

        for cid in container_ids:
            self._audit_container(cid)

    def _audit_container(self, container_id):
        """audit a single container"""
        out, code = self._run_docker(["inspect", container_id])
        if code != 0:
            return

        try:
            data = json.loads(out)
            if isinstance(data, list):
                data = data[0]
        except json.JSONDecodeError:
            return

        name = data.get("Name", container_id).lstrip("/")
        resource = f"{name} ({container_id[:12]})"

        # host config checks
        host_config = data.get("HostConfig", {})

        if host_config.get("Privileged"):
            self.add_finding("critical", "container",
                             "running in privileged mode", resource)

        if host_config.get("PidMode") == "host":
            self.add_finding("high", "container",
                             "using host pid namespace", resource)

        if host_config.get("NetworkMode") == "host":
            self.add_finding("medium", "container",
                             "using host network", resource)

        if host_config.get("IpcMode") == "host":
            self.add_finding("high", "container",
                             "using host ipc namespace", resource)

        # user check
        config = data.get("Config", {})
        user = config.get("User", "")
        if not user or user == "root" or user == "0":
            self.add_finding("medium", "container",
                             "running as root user", resource)

        # mount analysis
        mounts = data.get("Mounts", [])
        for mount in mounts:
            source = mount.get("Source", "")
            if source == "/var/run/docker.sock":
                self.add_finding("critical", "container",
                                 "docker socket mounted inside container", resource)
            elif source in ("/", "/etc", "/root"):
                self.add_finding("high", "container",
                                 f"sensitive host path mounted: {source}", resource)
            if mount.get("RW") and source.startswith("/"):
                self.add_finding("low", "container",
                                 f"writable host mount: {source}", resource)

        # capabilities
        cap_add = host_config.get("CapAdd") or []
        dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE",
                          "DAC_OVERRIDE", "ALL"]
        for cap in cap_add:
            if cap in dangerous_caps:
                self.add_finding("high", "container",
                                 f"dangerous capability: {cap}", resource)

        cap_drop = host_config.get("CapDrop") or []
        if not cap_drop:
            self.add_finding("low", "container",
                             "no capabilities dropped", resource)

        # security options
        security_opt = host_config.get("SecurityOpt") or []
        if not any("no-new-privileges" in opt for opt in security_opt):
            self.add_finding("low", "container",
                             "no-new-privileges not set", resource)

        # port bindings
        ports = host_config.get("PortBindings") or {}
        for port, bindings in ports.items():
            if bindings:
                for binding in bindings:
                    host_ip = binding.get("HostIp", "")
                    if host_ip in ("", "0.0.0.0"):
                        self.add_finding("low", "container",
                                         f"port {port} bound to all interfaces", resource)

    def lint_dockerfile(self, filepath):
        """lint a dockerfile for security issues"""
        path = Path(filepath)
        if not path.exists():
            self.add_finding("high", "dockerfile", f"not found: {filepath}")
            return

        content = path.read_text()
        lines = content.splitlines()

        # check for USER instruction
        has_user = any(re.match(r'^\s*USER\s+', line, re.IGNORECASE) for line in lines)
        if not has_user:
            self.add_finding("high", "dockerfile", "no USER instruction (runs as root)")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # FROM checks
            if re.match(r'^\s*FROM\s+', stripped, re.IGNORECASE):
                if ":latest" in stripped or not re.search(r':\S+', stripped.split()[-1]):
                    self.add_finding("medium", "dockerfile",
                                     f"line {i}: untagged or latest base image")

            # secrets in ENV
            if re.match(r'^\s*ENV\s+', stripped, re.IGNORECASE):
                if re.search(r'(PASSWORD|SECRET|KEY|TOKEN)\s*=', stripped, re.IGNORECASE):
                    self.add_finding("critical", "dockerfile",
                                     f"line {i}: secret in ENV instruction")

            # ADD vs COPY
            if re.match(r'^\s*ADD\s+', stripped, re.IGNORECASE):
                if not re.search(r'https?://', stripped):
                    self.add_finding("low", "dockerfile",
                                     f"line {i}: use COPY instead of ADD for local files")

            # RUN with curl|bash
            if re.match(r'^\s*RUN\s+', stripped, re.IGNORECASE):
                if re.search(r'curl.*\|.*sh|wget.*\|.*sh', stripped):
                    self.add_finding("high", "dockerfile",
                                     f"line {i}: piping remote script to shell")

        # HEALTHCHECK
        has_healthcheck = any(
            re.match(r'^\s*HEALTHCHECK\s+', line, re.IGNORECASE) for line in lines
        )
        if not has_healthcheck:
            self.add_finding("low", "dockerfile", "no HEALTHCHECK defined")

    def audit_compose(self, filepath):
        """audit docker-compose file"""
        path = Path(filepath)
        if not path.exists():
            self.add_finding("high", "compose", f"not found: {filepath}")
            return

        try:
            import yaml
            with open(filepath) as f:
                data = yaml.safe_load(f)
        except ImportError:
            self.add_finding("info", "compose", "pyyaml needed for compose audit")
            return
        except Exception as e:
            self.add_finding("high", "compose", f"parse error: {e}")
            return

        services = data.get("services", {})
        for name, svc in services.items():
            if svc.get("privileged"):
                self.add_finding("critical", "compose",
                                 f"{name}: privileged mode", name)
            if svc.get("network_mode") == "host":
                self.add_finding("medium", "compose",
                                 f"{name}: host network mode", name)

            volumes = svc.get("volumes", [])
            for vol in volumes:
                vol_str = vol if isinstance(vol, str) else vol.get("source", "")
                if "/var/run/docker.sock" in str(vol_str):
                    self.add_finding("critical", "compose",
                                     f"{name}: docker socket mount", name)

            env = svc.get("environment", {})
            if isinstance(env, dict):
                for key in env:
                    if re.search(r'PASSWORD|SECRET|KEY|TOKEN', key, re.IGNORECASE):
                        self.add_finding("high", "compose",
                                         f"{name}: secret in environment: {key}", name)

    def get_report(self):
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: severity_order.get(f.severity, 5)
        )
        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        return {
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "severity_counts": counts,
            "findings": [f.to_dict() for f in sorted_findings],
        }


def print_report(report, as_json=False):
    if as_json:
        print(json.dumps(report, indent=2))
        return

    print(f"\n[containok] scan results")
    print(f"total findings: {report['total_findings']}")
    print(f"severity: {report['severity_counts']}")
    print()

    for f in report["findings"]:
        sev = f["severity"].upper().ljust(8)
        res = f" ({f['resource']})" if f["resource"] else ""
        print(f"  [{sev}] [{f['category']}] {f['message']}{res}")


def show_docker_info():
    """show docker environment info as default action"""
    print(f"container security scanner")
    print(f"platform: {PLATFORM}\n")

    try:
        result = subprocess.run(
            ["docker", "version", "--format",
             "{{.Server.Version}}"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print(f"docker version: {result.stdout.strip()}")
        else:
            print("docker: not available or not running")
            print("install docker to use container scanning features")
            return
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("docker: not installed")
        print("install docker to use container scanning features")
        return

    # show running containers
    try:
        result = subprocess.run(
            ["docker", "ps", "--format",
             "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}"],
            capture_output=True, text=True, timeout=10
        )
        print(f"\nrunning containers:")
        print(result.stdout.strip() or "  (none)")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # show images
    try:
        result = subprocess.run(
            ["docker", "images", "--format",
             "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"],
            capture_output=True, text=True, timeout=10
        )
        print(f"\nimages:")
        print(result.stdout.strip() or "  (none)")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    print("\nuse -m all to run full security audit")
    print("use --help to see all options")


def main():
    parser = argparse.ArgumentParser(description="container security scanner")
    parser.add_argument("-m", "--mode", default=None,
                        choices=["daemon", "containers", "dockerfile",
                                 "compose", "all"],
                        help="scan mode")
    parser.add_argument("-f", "--file", help="dockerfile or compose file path")
    parser.add_argument("-o", "--output", help="output report file")
    parser.add_argument("--json", action="store_true", help="json output")
    args = parser.parse_args()

    # default behavior: show docker info and container summary
    if not args.mode and not args.file:
        show_docker_info()
        return

    mode = args.mode or "all"
    scanner = DockerScanner()

    if mode in ("daemon", "all"):
        scanner.audit_daemon()

    if mode in ("containers", "all"):
        scanner.audit_containers()

    if mode == "dockerfile" and args.file:
        scanner.lint_dockerfile(args.file)
    elif mode == "compose" and args.file:
        scanner.audit_compose(args.file)
    elif mode == "all" and args.file:
        if "compose" in args.file.lower() or args.file.endswith(".yml"):
            scanner.audit_compose(args.file)
        else:
            scanner.lint_dockerfile(args.file)

    report = scanner.get_report()
    print_report(report, args.json)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[containok] report saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
