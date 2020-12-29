#!/usr/bin/env python3
"""incident response automation with evidence collection and containment"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


class Evidence:
    def __init__(self, output_dir):
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_dir = Path(output_dir) / f"evidence_{self.timestamp}"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.base_dir / "collection.log"
        self.manifest = []

    def log(self, message):
        entry = f"[{datetime.now().strftime('%H:%M:%S')}] {message}"
        print(entry)
        with open(self.log_path, "a") as f:
            f.write(entry + "\n")

    def save(self, filename, content):
        """save evidence to file"""
        filepath = self.base_dir / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            filepath.write_bytes(content)
        else:
            filepath.write_text(content)
        self.manifest.append({
            "file": filename,
            "size": filepath.stat().st_size,
            "timestamp": datetime.now().isoformat(),
        })
        return filepath

    def run_cmd(self, cmd, filename, timeout=30):
        """run command and save output as evidence"""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, shell=isinstance(cmd, str),
            )
            output = result.stdout
            if result.stderr:
                output += f"\n--- stderr ---\n{result.stderr}"
            self.save(filename, output)
            return output
        except subprocess.TimeoutExpired:
            self.save(filename, f"command timed out after {timeout}s: {cmd}")
            return ""
        except Exception as e:
            self.save(filename, f"command failed: {cmd}\nerror: {e}")
            return ""


class IncidentResponse:
    def __init__(self, output_dir="./ir_evidence"):
        self.evidence = Evidence(output_dir)
        self.timeline = []

    def add_timeline_event(self, timestamp, source, description):
        self.timeline.append({
            "timestamp": timestamp,
            "source": source,
            "description": description,
        })

    def collect_system(self):
        """collect system information"""
        self.evidence.log("collecting system information")

        self.evidence.run_cmd(["hostname"], "system/hostname.txt")
        self.evidence.run_cmd(["date", "+%Y-%m-%dT%H:%M:%S%z"], "system/date.txt")
        self.evidence.run_cmd(["date", "-u"], "system/date_utc.txt")
        self.evidence.run_cmd(["uptime"], "system/uptime.txt")
        self.evidence.run_cmd(["uname", "-a"], "system/kernel.txt")
        self.evidence.run_cmd(["cat", "/etc/os-release"], "system/os_release.txt")
        self.evidence.run_cmd(["df", "-h"], "system/disk.txt")
        self.evidence.run_cmd(["free", "-h"], "system/memory.txt")
        self.evidence.run_cmd(["mount"], "system/mounts.txt")
        self.evidence.run_cmd(["lsmod"], "system/modules.txt")
        self.evidence.run_cmd(["env"], "system/environment.txt")

        self.evidence.log("system info collected")

    def collect_processes(self, target_pid=None):
        """collect process information"""
        self.evidence.log("collecting process information")

        self.evidence.run_cmd(["ps", "auxf"], "processes/tree.txt")
        self.evidence.run_cmd(["ps", "aux", "--sort=-%mem"], "processes/by_memory.txt")
        self.evidence.run_cmd(["ps", "aux", "--sort=-%cpu"], "processes/by_cpu.txt")
        self.evidence.run_cmd(
            "ls -la /proc/*/exe 2>/dev/null | grep deleted",
            "processes/deleted_executables.txt"
        )

        if target_pid:
            self._collect_pid(target_pid)

        # look for suspicious processes
        suspicious = self._find_suspicious_processes()
        if suspicious:
            self.evidence.save(
                "processes/suspicious.json",
                json.dumps(suspicious, indent=2)
            )
            for proc in suspicious:
                self.add_timeline_event(
                    datetime.now().isoformat(),
                    "process_audit",
                    f"suspicious process: pid={proc['pid']} name={proc['name']} "
                    f"reason={proc['reason']}"
                )

    def _collect_pid(self, pid):
        """collect detailed info for a specific pid"""
        self.evidence.log(f"collecting details for pid {pid}")
        proc_dir = Path(f"/proc/{pid}")

        if not proc_dir.exists():
            self.evidence.log(f"pid {pid} not found")
            return

        files = {
            "cmdline": "cmdline.txt",
            "environ": "environ.txt",
            "status": "status.txt",
            "maps": "maps.txt",
            "io": "io.txt",
            "limits": "limits.txt",
        }

        for proc_file, output_name in files.items():
            try:
                content = (proc_dir / proc_file).read_bytes()
                if proc_file in ("cmdline", "environ"):
                    content = content.replace(b"\x00", b"\n")
                self.evidence.save(f"processes/pid_{pid}/{output_name}", content)
            except (PermissionError, FileNotFoundError):
                pass

        self.evidence.run_cmd(
            f"ls -la /proc/{pid}/fd/ 2>/dev/null",
            f"processes/pid_{pid}/fd.txt"
        )
        self.evidence.run_cmd(
            f"ls -la /proc/{pid}/exe 2>/dev/null",
            f"processes/pid_{pid}/exe_link.txt"
        )

    def _find_suspicious_processes(self):
        """find potentially suspicious processes"""
        suspicious = []
        proc = Path("/proc")
        suspicious_names = {
            "nc", "ncat", "netcat", "socat", "meterpreter",
            "mimikatz", "pwdump", "procdump",
        }

        for pid_dir in proc.iterdir():
            if not pid_dir.name.isdigit():
                continue
            try:
                comm = (pid_dir / "comm").read_text().strip()
                cmdline = (pid_dir / "cmdline").read_bytes().replace(b"\x00", b" ").decode(
                    errors="replace"
                ).strip()

                reasons = []
                if comm.lower() in suspicious_names:
                    reasons.append(f"suspicious name: {comm}")

                exe_link = os.readlink(f"/proc/{pid_dir.name}/exe")
                if "(deleted)" in exe_link:
                    reasons.append("running from deleted binary")

                if re.search(r'/tmp/|/dev/shm/', exe_link):
                    reasons.append(f"running from temp directory: {exe_link}")

                if re.search(r'base64.*decode|curl.*\|.*sh|wget.*\|.*bash', cmdline):
                    reasons.append("suspicious command pattern")

                if reasons:
                    suspicious.append({
                        "pid": pid_dir.name,
                        "name": comm,
                        "cmdline": cmdline[:200],
                        "exe": exe_link,
                        "reason": "; ".join(reasons),
                    })
            except (PermissionError, FileNotFoundError, OSError):
                continue

        return suspicious

    def collect_network(self):
        """collect network state"""
        self.evidence.log("collecting network information")

        self.evidence.run_cmd(["ip", "addr"], "network/interfaces.txt")
        self.evidence.run_cmd(["ip", "route"], "network/routes.txt")
        self.evidence.run_cmd(["ip", "neigh"], "network/arp.txt")
        self.evidence.run_cmd(["cat", "/etc/resolv.conf"], "network/dns.txt")

        if shutil.which("ss"):
            self.evidence.run_cmd(["ss", "-tulnp"], "network/listening.txt")
            self.evidence.run_cmd(["ss", "-tnp"], "network/established.txt")
        elif shutil.which("netstat"):
            self.evidence.run_cmd(["netstat", "-tulnp"], "network/listening.txt")
            self.evidence.run_cmd(["netstat", "-tnp"], "network/established.txt")

        self.evidence.run_cmd(
            "iptables -L -n -v 2>/dev/null",
            "network/iptables.txt"
        )

    def collect_users(self):
        """collect user and authentication info"""
        self.evidence.log("collecting user information")

        self.evidence.run_cmd(["w"], "users/current.txt")
        self.evidence.run_cmd(["last", "-20"], "users/last_logins.txt")
        self.evidence.run_cmd("lastb -20 2>/dev/null", "users/failed_logins.txt")

        # auth logs
        for log_path in ["/var/log/auth.log", "/var/log/secure"]:
            if Path(log_path).exists():
                self.evidence.run_cmd(
                    ["tail", "-500", log_path],
                    "users/auth_log.txt"
                )
                break

        # cron
        self.evidence.run_cmd(["cat", "/etc/crontab"], "users/crontab.txt")
        self.evidence.run_cmd("ls -la /etc/cron.d/ 2>/dev/null", "users/cron_d.txt")

        # ssh keys
        try:
            result = subprocess.run(
                ["find", "/home", "-name", "authorized_keys", "-type", "f"],
                capture_output=True, text=True, timeout=10,
            )
            keys_data = ""
            for keyfile in result.stdout.splitlines():
                keyfile = keyfile.strip()
                if keyfile:
                    keys_data += f"=== {keyfile} ===\n"
                    try:
                        keys_data += Path(keyfile).read_text() + "\n"
                    except PermissionError:
                        keys_data += "(permission denied)\n"
            if keys_data:
                self.evidence.save("users/authorized_keys.txt", keys_data)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    def check_integrity(self):
        """check system integrity"""
        self.evidence.log("checking system integrity")

        self.evidence.run_cmd(
            "find /etc -type f -mtime -7 -ls 2>/dev/null",
            "integrity/recent_etc.txt"
        )
        self.evidence.run_cmd(
            "find /usr/bin -type f -mtime -7 -ls 2>/dev/null",
            "integrity/recent_bin.txt"
        )
        self.evidence.run_cmd(
            "find /tmp -type f -ls 2>/dev/null",
            "integrity/tmp.txt"
        )
        self.evidence.run_cmd(
            "find /dev -type f 2>/dev/null",
            "integrity/dev_files.txt"
        )

        if shutil.which("dpkg"):
            self.evidence.run_cmd(
                "dpkg --verify 2>/dev/null",
                "integrity/package_verify.txt",
                timeout=60,
            )
        elif shutil.which("rpm"):
            self.evidence.run_cmd(
                "rpm -Va 2>/dev/null",
                "integrity/package_verify.txt",
                timeout=60,
            )

    def contain_network(self, interface=None, allow_ip=None):
        """network containment - isolate the host"""
        self.evidence.log("starting network containment")

        if os.getuid() != 0:
            self.evidence.log("network containment requires root")
            return False

        self.evidence.run_cmd("iptables -L -n -v", "containment/iptables_before.txt")

        if allow_ip:
            cmds = [
                f"iptables -A INPUT -s {allow_ip} -j ACCEPT",
                f"iptables -A OUTPUT -d {allow_ip} -j ACCEPT",
                "iptables -A INPUT -j DROP",
                "iptables -A OUTPUT -j DROP",
            ]
        else:
            cmds = [
                "iptables -A INPUT -i lo -j ACCEPT",
                "iptables -A OUTPUT -o lo -j ACCEPT",
                "iptables -A INPUT -j DROP",
                "iptables -A OUTPUT -j DROP",
            ]

        for cmd in cmds:
            self.evidence.run_cmd(cmd, "containment/actions.txt")

        self.evidence.run_cmd("iptables -L -n -v", "containment/iptables_after.txt")
        self.add_timeline_event(
            datetime.now().isoformat(), "containment",
            f"network isolation applied (allow: {allow_ip or 'loopback only'})"
        )
        return True

    def contain_process(self, pid):
        """kill a suspicious process"""
        self.evidence.log(f"containing process {pid}")

        self._collect_pid(pid)

        try:
            os.kill(int(pid), signal.SIGSTOP)
            self.evidence.log(f"process {pid} stopped (SIGSTOP)")
            self.add_timeline_event(
                datetime.now().isoformat(), "containment",
                f"process {pid} stopped"
            )
        except (ProcessLookupError, PermissionError) as e:
            self.evidence.log(f"failed to stop process {pid}: {e}")
            return False

        return True

    def generate_timeline(self):
        """generate incident timeline from collected evidence"""
        self.evidence.log("generating timeline")

        # parse auth log for timeline events
        auth_log = self.evidence.base_dir / "users" / "auth_log.txt"
        if auth_log.exists():
            for line in auth_log.read_text().splitlines():
                ts_match = re.match(
                    r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})', line
                )
                if ts_match and any(
                    kw in line.lower()
                    for kw in ["failed", "accepted", "invalid", "error", "session"]
                ):
                    self.add_timeline_event(
                        ts_match.group(1), "auth_log", line.strip()
                    )

        # sort timeline
        self.timeline.sort(key=lambda e: e["timestamp"])

        self.evidence.save(
            "timeline.json",
            json.dumps(self.timeline, indent=2)
        )

        return self.timeline

    def generate_report(self):
        """generate final incident report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "evidence_dir": str(self.evidence.base_dir),
            "manifest": self.evidence.manifest,
            "timeline_entries": len(self.timeline),
            "timeline": self.timeline[-20:] if self.timeline else [],
        }

        self.evidence.save("report.json", json.dumps(report, indent=2))
        return report


def print_report(report, as_json=False):
    if as_json:
        print(json.dumps(report, indent=2))
        return

    print(f"\n[res] incident response report")
    print(f"evidence directory: {report['evidence_dir']}")
    print(f"files collected: {len(report['manifest'])}")
    print(f"timeline entries: {report['timeline_entries']}")
    print()

    if report.get("timeline"):
        print("recent timeline:")
        for event in report["timeline"][-10:]:
            print(f"  [{event['timestamp']}] [{event['source']}] {event['description'][:100]}")


def main():
    parser = argparse.ArgumentParser(description="incident response automation")
    parser.add_argument("-m", "--mode", default="all",
                        choices=["collect", "network", "processes", "users",
                                 "integrity", "contain", "timeline", "all"],
                        help="operation mode")
    parser.add_argument("-o", "--output", default="./ir_evidence",
                        help="output directory")
    parser.add_argument("-p", "--pid", help="target pid for investigation")
    parser.add_argument("--isolate", action="store_true",
                        help="network isolation (requires root)")
    parser.add_argument("--allow-ip", help="ip to allow during isolation")
    parser.add_argument("--kill-pid", help="pid to stop")
    parser.add_argument("--json", action="store_true", help="json output")
    args = parser.parse_args()

    ir = IncidentResponse(args.output)

    if args.mode == "contain":
        if args.isolate:
            ir.contain_network(allow_ip=args.allow_ip)
        if args.kill_pid:
            ir.contain_process(args.kill_pid)
        report = ir.generate_report()
        print_report(report, args.json)
        return

    mode_map = {
        "collect": ir.collect_system,
        "network": ir.collect_network,
        "users": ir.collect_users,
        "integrity": ir.check_integrity,
    }

    if args.mode == "processes":
        ir.collect_processes(args.pid)
    elif args.mode == "timeline":
        ir.collect_system()
        ir.collect_users()
        ir.generate_timeline()
    elif args.mode == "all":
        ir.collect_system()
        ir.collect_processes(args.pid)
        ir.collect_network()
        ir.collect_users()
        ir.check_integrity()
        ir.generate_timeline()
    elif args.mode in mode_map:
        mode_map[args.mode]()

    report = ir.generate_report()
    print_report(report, args.json)

    print(f"\narchive: tar czf evidence.tar.gz -C {args.output} "
          f"evidence_{ir.evidence.timestamp}")


if __name__ == "__main__":
    main()
