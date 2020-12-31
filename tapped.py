#!/usr/bin/env python3
"""process and system call monitor"""

import argparse
import hashlib
import json
import os
import platform
import re
import signal
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path


def get_os():
    return platform.system().lower()


class ProcessInfo:
    """information about a running process"""

    def __init__(self, pid, os_type=None):
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
        self.os_type = os_type or get_os()
        self._read_info()

    def _read_info(self):
        if self.os_type == "linux":
            self._read_proc()
        elif self.os_type == "darwin":
            self._read_darwin()
        elif self.os_type == "windows":
            self._read_windows()

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

    def _read_darwin(self):
        """read process info via ps on macos"""
        try:
            result = subprocess.run(
                ["ps", "-p", str(self.pid), "-o",
                 "comm=,ppid=,uid=,rss="],
                capture_output=True, text=True, timeout=5
            )
            line = result.stdout.strip()
            if not line:
                return
            parts = line.split()
            if len(parts) >= 1:
                self.name = os.path.basename(parts[0])
            if len(parts) >= 2:
                self.ppid = int(parts[1])
            if len(parts) >= 3:
                self.uid = int(parts[2])
            if len(parts) >= 4:
                self.rss_kb = int(parts[3])
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass

    def _read_windows(self):
        """read process info via wmic on windows"""
        try:
            result = subprocess.run(
                ["wmic", "process", "where",
                 f"ProcessId={self.pid}", "get",
                 "Name,ParentProcessId,CommandLine,WorkingSetSize",
                 "/format:csv"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.strip().split("\n"):
                parts = line.strip().split(",")
                if len(parts) >= 5 and parts[1]:
                    self.cmdline = parts[1]
                    self.name = parts[2]
                    self.ppid = int(parts[3]) if parts[3].isdigit() else 0
                    ws = parts[4].strip()
                    self.rss_kb = int(ws) // 1024 if ws.isdigit() else 0
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
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
        os_type = get_os()
        if paths:
            self.watched = paths
        elif os_type == "linux":
            self.watched = [
                "/etc/passwd", "/etc/shadow", "/etc/sudoers",
                "/etc/ssh/sshd_config", "/etc/crontab",
            ]
        elif os_type == "darwin":
            self.watched = [
                "/etc/passwd", "/etc/sudoers",
                "/etc/ssh/sshd_config",
            ]
        else:
            sys_root = os.environ.get("SYSTEMROOT", "C:\\Windows")
            self.watched = [
                os.path.join(sys_root, "System32", "drivers", "etc", "hosts"),
                os.path.join(sys_root, "System32", "config", "SAM"),
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
    """monitor system calls via strace (linux) or dtrace (macos)"""

    SUSPICIOUS_CALLS = {
        "ptrace": "process injection",
        "process_vm_writev": "process memory write",
        "memfd_create": "anonymous file creation",
        "execveat": "file-less execution",
    }

    def __init__(self, pid):
        self.pid = pid
        self.proc = None
        self.os_type = get_os()

    def start(self):
        """start tracing on target process"""
        if self.os_type == "windows":
            return False

        if self.os_type == "darwin":
            try:
                self.proc = subprocess.Popen(
                    ["dtruss", "-p", str(self.pid)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                return True
            except FileNotFoundError:
                return False

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
        """read trace output for suspicious calls"""
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
        self.os_type = get_os()
        if extra_suspicious:
            self.SUSPICIOUS_NAMES.update(extra_suspicious)

    def scan_processes(self):
        """scan for current processes"""
        if self.os_type == "linux":
            return self._scan_proc()
        return self._scan_ps()

    def _scan_proc(self):
        """scan /proc for processes (linux)"""
        current = {}
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                info = ProcessInfo(pid, "linux")
                if info.is_valid():
                    current[pid] = info
        except PermissionError:
            pass
        return current

    def _scan_ps(self):
        """scan processes via ps (macos) or tasklist (windows)"""
        current = {}
        if self.os_type == "windows":
            try:
                result = subprocess.run(
                    ["tasklist", "/fo", "csv", "/nh"],
                    capture_output=True, text=True, timeout=15
                )
                for line in result.stdout.strip().split("\n"):
                    parts = line.strip().strip('"').split('","')
                    if len(parts) >= 2:
                        try:
                            pid = int(parts[1].strip('"'))
                            info = ProcessInfo(pid, "windows")
                            if not info.is_valid():
                                info.name = parts[0]
                            current[pid] = info
                        except ValueError:
                            continue
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        else:
            try:
                result = subprocess.run(
                    ["ps", "-eo", "pid="],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line.isdigit():
                        pid = int(line)
                        info = ProcessInfo(pid, self.os_type)
                        if info.is_valid():
                            current[pid] = info
            except (subprocess.TimeoutExpired, FileNotFoundError):
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

        if proc_info.name.lower() in self.SUSPICIOUS_NAMES:
            alerts.append({
                "type": "suspicious_name",
                "severity": "high",
                "process": proc_info.to_dict(),
                "message": f"suspicious process: {proc_info.name}",
            })

        if "(deleted)" in proc_info.exe:
            alerts.append({
                "type": "deleted_binary",
                "severity": "critical",
                "process": proc_info.to_dict(),
                "message": f"running deleted binary: {proc_info.exe}",
            })

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
        print(f"process monitor started (interval: {self.interval}s, "
              f"platform: {self.os_type})")
        print(f"watching for: {', '.join(sorted(self.SUSPICIOUS_NAMES))}")
        print()

        current = self.scan_processes()
        self.known_pids = {pid: info for pid, info in current.items()}
        print(f"tracking {len(self.known_pids)} processes")

        if self.os_type != "windows":
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
        os_type = get_os()
        if os_type == "windows":
            print("syscall tracing not supported on windows", file=sys.stderr)
            sys.exit(1)
        tracer = "dtruss" if os_type == "darwin" else "strace"
        print(f"monitoring pid {args.pid} with {tracer}")
        strace = StraceMonitor(args.pid)
        if not strace.start():
            print(f"{tracer} not available", file=sys.stderr)
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
