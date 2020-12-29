#!/usr/bin/env python3
"""process and system call monitor"""

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path


class ProcessInfo:
    """information about a running process"""

    def __init__(self, pid):
        self.pid = pid
        self.name = ""
        self.cmdline = ""
        self.ppid = 0
        self.uid = 0
        self.exe = ""
        self.fd_count = 0
        self.threads = 0
        self.rss_kb = 0
        self.start_time = 0
        self._read_proc()

    def _read_proc(self):
        """read process info from /proc"""
        base = f"/proc/{self.pid}"
        try:
            self.name = Path(f"{base}/comm").read_text().strip()
        except (FileNotFoundError, PermissionError):
            return
        try:
            self.cmdline = Path(f"{base}/cmdline").read_bytes().replace(
                b"\x00", b" ").decode("utf-8", errors="ignore").strip()
        except (FileNotFoundError, PermissionError):
            pass
        try:
            status = Path(f"{base}/status").read_text()
            ppid_match = re.search(r"PPid:\s+(\d+)", status)
            uid_match = re.search(r"Uid:\s+(\d+)", status)
            rss_match = re.search(r"VmRSS:\s+(\d+)", status)
            threads_match = re.search(r"Threads:\s+(\d+)", status)
            if ppid_match:
                self.ppid = int(ppid_match.group(1))
            if uid_match:
                self.uid = int(uid_match.group(1))
            if rss_match:
                self.rss_kb = int(rss_match.group(1))
            if threads_match:
                self.threads = int(threads_match.group(1))
        except (FileNotFoundError, PermissionError):
            pass
        try:
            self.exe = os.readlink(f"{base}/exe")
        except (FileNotFoundError, PermissionError, OSError):
            pass
        try:
            self.fd_count = len(os.listdir(f"{base}/fd"))
        except (FileNotFoundError, PermissionError):
            pass

    def is_valid(self):
        return bool(self.name)

    def to_dict(self):
        return {
            "pid": self.pid,
            "name": self.name,
            "cmdline": self.cmdline,
            "ppid": self.ppid,
            "uid": self.uid,
            "exe": self.exe,
            "fd_count": self.fd_count,
            "threads": self.threads,
            "rss_kb": self.rss_kb,
        }


class FileIntegrityMonitor:
    """monitor files for changes"""

    def __init__(self, paths=None):
        self.watched = paths or [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/etc/crontab",
        ]
        self.hashes = {}
        self._initial_scan()

    def _initial_scan(self):
        for path in self.watched:
            h = self._hash_file(path)
            if h:
                self.hashes[path] = h

    def _hash_file(self, path):
        try:
            data = Path(path).read_bytes()
            return hashlib.sha256(data).hexdigest()
        except (FileNotFoundError, PermissionError):
            return None

    def check(self):
        """check all watched files for changes"""
        changes = []
        for path in self.watched:
            current = self._hash_file(path)
            if current is None:
                if path in self.hashes:
                    changes.append({
                        "path": path, "type": "deleted",
                    })
                    del self.hashes[path]
                continue
            if path not in self.hashes:
                changes.append({
                    "path": path, "type": "created",
                    "hash": current,
                })
                self.hashes[path] = current
            elif self.hashes[path] != current:
                changes.append({
                    "path": path, "type": "modified",
                    "old_hash": self.hashes[path],
                    "new_hash": current,
                })
                self.hashes[path] = current
        return changes


class StraceMonitor:
    """monitor system calls via strace"""

    SUSPICIOUS_CALLS = {
        "ptrace": "process injection",
        "process_vm_writev": "process memory write",
        "memfd_create": "anonymous file creation",
        "execveat": "file-less execution",
    }

    def __init__(self, pid):
        self.pid = pid
        self.proc = None

    def start(self):
        """start strace on target process"""
        calls = ",".join(self.SUSPICIOUS_CALLS.keys())
        try:
            self.proc = subprocess.Popen(
                ["strace", "-f", "-e", f"trace={calls}",
                 "-p", str(self.pid)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
        except FileNotFoundError:
            return False
        return True

    def check_output(self):
        """read strace output for suspicious calls"""
        alerts = []
        if not self.proc:
            return alerts
        try:
            line = self.proc.stderr.readline()
            if line:
                for call, desc in self.SUSPICIOUS_CALLS.items():
                    if call in line:
                        alerts.append({
                            "type": "suspicious_syscall",
                            "call": call,
                            "description": desc,
                            "pid": self.pid,
                            "raw": line.strip(),
                        })
        except Exception:
            pass
        return alerts

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait()


class ProcessMonitor:
    """main process monitoring engine"""

    SUSPICIOUS_NAMES = {
        "nc", "ncat", "netcat", "socat", "xmrig", "cryptominer",
        "mimikatz", "meterpreter", "reverse", "bind_shell",
    }

    def __init__(self, interval=5, extra_suspicious=None):
        self.interval = interval
        self.known_pids = {}
        self.alerts = []
        self.fim = FileIntegrityMonitor()
        self.strace_monitors = {}
        if extra_suspicious:
            self.SUSPICIOUS_NAMES.update(extra_suspicious)

    def scan_processes(self):
        """scan /proc for current processes"""
        current = {}
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                info = ProcessInfo(pid)
                if info.is_valid():
                    current[pid] = info
        except PermissionError:
            pass
        return current

    def detect_changes(self, current):
        """compare current processes to known state"""
        new_procs = []
        exited = []

        for pid, info in current.items():
            if pid not in self.known_pids:
                new_procs.append(info)

        for pid in list(self.known_pids.keys()):
            if pid not in current:
                exited.append(self.known_pids[pid])

        self.known_pids = {pid: info for pid, info in current.items()}
        return new_procs, exited

    def check_suspicious(self, proc_info):
        """check if a process is suspicious"""
        alerts = []

        # name check
        if proc_info.name.lower() in self.SUSPICIOUS_NAMES:
            alerts.append({
                "type": "suspicious_name",
                "severity": "high",
                "process": proc_info.to_dict(),
                "message": f"suspicious process: {proc_info.name}",
            })

        # deleted binary
        if "(deleted)" in proc_info.exe:
            alerts.append({
                "type": "deleted_binary",
                "severity": "critical",
                "process": proc_info.to_dict(),
                "message": f"running deleted binary: {proc_info.exe}",
            })

        # high fd count
        if proc_info.fd_count > 1000:
            alerts.append({
                "type": "high_fd_count",
                "severity": "medium",
                "process": proc_info.to_dict(),
                "message": f"{proc_info.name} has {proc_info.fd_count} fds",
            })

        return alerts

    def alert(self, alert_data):
        """record and display alert"""
        alert_data["timestamp"] = datetime.now().isoformat()
        self.alerts.append(alert_data)
        sev = alert_data.get("severity", "info").upper()
        msg = alert_data.get("message", "unknown alert")
        print(f"[{sev}] {msg}")

    def run(self):
        """main monitoring loop"""
        print(f"process monitor started (interval: {self.interval}s)")
        print(f"watching for: {', '.join(sorted(self.SUSPICIOUS_NAMES))}")
        print()

        # initial scan
        current = self.scan_processes()
        self.known_pids = {pid: info for pid, info in current.items()}
        print(f"tracking {len(self.known_pids)} processes")

        def stop(sig, frame):
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, stop)

        while True:
            time.sleep(self.interval)
            current = self.scan_processes()
            new_procs, exited = self.detect_changes(current)

            for proc in new_procs:
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[{ts}] new: pid={proc.pid} {proc.name} "
                      f"ppid={proc.ppid} uid={proc.uid}")
                for alert_data in self.check_suspicious(proc):
                    self.alert(alert_data)

            for proc in exited:
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[{ts}] exit: pid={proc.pid} {proc.name}")

            # file integrity check
            changes = self.fim.check()
            for change in changes:
                self.alert({
                    "type": "file_integrity",
                    "severity": "critical",
                    "message": f"file {change['type']}: {change['path']}",
                    "details": change,
                })

    def stats(self):
        return {
            "tracked_processes": len(self.known_pids),
            "total_alerts": len(self.alerts),
            "alerts": self.alerts,
        }


def main():
    parser = argparse.ArgumentParser(description="process and system monitor")
    parser.add_argument("-i", "--interval", type=int, default=5,
                        help="scan interval in seconds (default: 5)")
    parser.add_argument("-s", "--suspicious",
                        help="file with suspicious process names")
    parser.add_argument("-p", "--pid", type=int,
                        help="monitor specific pid with strace")
    parser.add_argument("-o", "--output", help="save alerts to json")
    args = parser.parse_args()

    extra = set()
    if args.suspicious and os.path.exists(args.suspicious):
        with open(args.suspicious) as f:
            for line in f:
                name = line.strip()
                if name and not name.startswith("#"):
                    extra.add(name)

    if args.pid:
        print(f"monitoring pid {args.pid} with strace")
        strace = StraceMonitor(args.pid)
        if not strace.start():
            print("strace not available", file=sys.stderr)
            sys.exit(1)
        try:
            while True:
                alerts = strace.check_output()
                for a in alerts:
                    print(f"[ALERT] {a['description']}: {a['call']}")
                time.sleep(0.1)
        except KeyboardInterrupt:
            strace.stop()
        return

    monitor = ProcessMonitor(interval=args.interval, extra_suspicious=extra)
    try:
        monitor.run()
    except KeyboardInterrupt:
        pass

    stats = monitor.stats()
    print(f"\n--- monitor summary ---")
    print(f"processes tracked: {stats['tracked_processes']}")
    print(f"alerts raised:     {stats['total_alerts']}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(stats, f, indent=2)
        print(f"saved to {args.output}")


if __name__ == "__main__":
    main()
