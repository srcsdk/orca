#!/usr/bin/env python3
"""process injection and evasion testing framework"""

import argparse
import ctypes
import ctypes.util
import json
import os
import re
import signal
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


SAFETY_MARKER = "VADED_TEST_PROCESS"


def is_test_process(pid):
    """verify a process was started by this tool for testing"""
    try:
        environ = Path(f"/proc/{pid}/environ").read_bytes()
        return SAFETY_MARKER.encode() in environ
    except (FileNotFoundError, PermissionError):
        return False


def is_own_process(pid):
    """check if pid belongs to current user"""
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        match = re.search(r"Uid:\s+(\d+)", status)
        if match:
            return int(match.group(1)) == os.getuid()
    except (FileNotFoundError, PermissionError):
        pass
    return False


def spawn_test_process():
    """spawn a safe test target process"""
    env = os.environ.copy()
    env[SAFETY_MARKER] = "1"
    proc = subprocess.Popen(
        [sys.executable, "-c",
         "import time; time.sleep(300)"],
        env=env
    )
    return proc


class ProcessRenamer:
    """rename process via /proc/pid/comm"""

    def rename(self, pid, new_name):
        """rename a process (max 15 chars, own process only)"""
        if not is_own_process(pid):
            return False, "can only rename own processes"
        new_name = new_name[:15]
        try:
            old_name = Path(f"/proc/{pid}/comm").read_text().strip()
            Path(f"/proc/{pid}/comm").write_text(new_name)
            current = Path(f"/proc/{pid}/comm").read_text().strip()
            return True, {
                "pid": pid,
                "old_name": old_name,
                "new_name": current,
            }
        except (PermissionError, FileNotFoundError) as e:
            return False, str(e)

    def restore(self, pid, original_name):
        """restore original process name"""
        try:
            Path(f"/proc/{pid}/comm").write_text(original_name)
            return True
        except (PermissionError, FileNotFoundError):
            return False


class PtraceInjector:
    """demonstrate ptrace-based process attachment"""

    PTRACE_ATTACH = 16
    PTRACE_DETACH = 17
    PTRACE_PEEKDATA = 2

    def __init__(self):
        libc_name = ctypes.util.find_library("c")
        self.libc = ctypes.CDLL(libc_name, use_errno=True) if libc_name else None

    def attach(self, pid):
        """attach to a process (test processes only)"""
        if not is_test_process(pid):
            return False, "safety: can only attach to test processes"
        if not is_own_process(pid):
            return False, "safety: can only attach to own processes"
        if not self.libc:
            return False, "libc not available"
        result = self.libc.ptrace(self.PTRACE_ATTACH, pid, 0, 0)
        if result == -1:
            errno = ctypes.get_errno()
            return False, f"ptrace attach failed (errno {errno})"
        # wait for process to stop
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        return True, {"pid": pid, "status": "attached"}

    def detach(self, pid):
        """detach from a process"""
        if not self.libc:
            return False, "libc not available"
        result = self.libc.ptrace(self.PTRACE_DETACH, pid, 0, 0)
        if result == -1:
            return False, "ptrace detach failed"
        return True, {"pid": pid, "status": "detached"}

    def peek_memory(self, pid, address):
        """read a word from process memory (test processes only)"""
        if not is_test_process(pid):
            return False, "safety: can only read test process memory"
        if not self.libc:
            return False, "libc not available"
        self.libc.ptrace.restype = ctypes.c_long
        data = self.libc.ptrace(self.PTRACE_PEEKDATA, pid, address, 0)
        return True, {"pid": pid, "address": hex(address), "data": hex(data)}


class PreloadDemo:
    """demonstrate ld_preload technique"""

    def check_system_preloads(self):
        """check for existing ld_preload on the system"""
        results = {
            "etc_preload": None,
            "env_preload": os.environ.get("LD_PRELOAD", None),
            "process_preloads": [],
        }
        preload_path = Path("/etc/ld.so.preload")
        if preload_path.exists():
            try:
                results["etc_preload"] = preload_path.read_text().strip()
            except PermissionError:
                results["etc_preload"] = "permission denied"
        return results

    def scan_process_preloads(self):
        """check running processes for ld_preload"""
        findings = []
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            try:
                environ = Path(f"/proc/{pid}/environ").read_bytes()
                if b"LD_PRELOAD=" in environ:
                    parts = environ.split(b"\x00")
                    for part in parts:
                        if part.startswith(b"LD_PRELOAD="):
                            name = Path(f"/proc/{pid}/comm").read_text().strip()
                            findings.append({
                                "pid": pid,
                                "name": name,
                                "preload": part.decode("utf-8", errors="ignore"),
                            })
            except (FileNotFoundError, PermissionError):
                continue
        return findings


class MemoryWriter:
    """demonstrate /proc/pid/mem writing (test processes only)"""

    def read_maps(self, pid):
        """read process memory mappings"""
        if not is_test_process(pid) and not is_own_process(pid):
            return None, "safety: can only read test/own process maps"
        maps = []
        try:
            for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
                parts = line.split()
                if len(parts) >= 6:
                    addr_range = parts[0].split("-")
                    maps.append({
                        "start": int(addr_range[0], 16),
                        "end": int(addr_range[1], 16),
                        "perms": parts[1],
                        "path": parts[5] if len(parts) > 5 else "",
                    })
        except (FileNotFoundError, PermissionError) as e:
            return None, str(e)
        return maps, None


class EvasionTester:
    """run evasion techniques and report results"""

    def __init__(self):
        self.renamer = ProcessRenamer()
        self.ptrace = PtraceInjector()
        self.preload = PreloadDemo()
        self.mem_writer = MemoryWriter()
        self.results = []

    def run_test(self, name, func):
        """run a test and record result"""
        try:
            success, detail = func()
            result = {
                "test": name,
                "success": success,
                "detail": detail,
            }
        except Exception as e:
            result = {
                "test": name,
                "success": False,
                "detail": str(e),
            }
        self.results.append(result)
        status = "ok" if result["success"] else "fail"
        print(f"  [{status}] {name}")
        return result

    def test_rename(self):
        """test process renaming"""
        proc = spawn_test_process()
        time.sleep(0.2)
        try:
            success, detail = self.renamer.rename(proc.pid, "kworker/0:1")
            if success:
                time.sleep(0.5)
                self.renamer.restore(proc.pid, "python3")
            return success, detail
        finally:
            proc.terminate()
            proc.wait()

    def test_ptrace_attach(self):
        """test ptrace attachment"""
        proc = spawn_test_process()
        time.sleep(0.2)
        try:
            success, detail = self.ptrace.attach(proc.pid)
            if success:
                self.ptrace.detach(proc.pid)
            return success, detail
        finally:
            proc.terminate()
            proc.wait()

    def test_preload_scan(self):
        """scan for existing preloads"""
        findings = self.preload.scan_process_preloads()
        return True, {
            "processes_with_preload": len(findings),
            "findings": findings[:5],
        }

    def test_memory_maps(self):
        """test reading process memory maps"""
        proc = spawn_test_process()
        time.sleep(0.2)
        try:
            maps, err = self.mem_writer.read_maps(proc.pid)
            if err:
                return False, err
            return True, {
                "regions": len(maps),
                "writable": sum(1 for m in maps if "w" in m["perms"]),
            }
        finally:
            proc.terminate()
            proc.wait()

    def test_deleted_binary_detection(self):
        """check for processes running deleted binaries"""
        found = []
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                exe = os.readlink(f"/proc/{entry}/exe")
                if "(deleted)" in exe:
                    name = Path(f"/proc/{entry}/comm").read_text().strip()
                    found.append({"pid": int(entry), "name": name, "exe": exe})
            except (FileNotFoundError, PermissionError, OSError):
                continue
        return True, {"deleted_binaries": found}

    def run_all(self):
        """run complete test suite"""
        print("evasion test suite")
        print()

        print("process manipulation:")
        self.run_test("process_rename", self.test_rename)
        self.run_test("ptrace_attach", self.test_ptrace_attach)

        print("\nreconnaissance:")
        self.run_test("preload_scan", self.test_preload_scan)
        self.run_test("memory_map_read", self.test_memory_maps)

        print("\ndetection checks:")
        self.run_test("deleted_binary_scan", self.test_deleted_binary_detection)

        passed = sum(1 for r in self.results if r["success"])
        print(f"\n{passed}/{len(self.results)} tests passed")
        return self.results


def main():
    parser = argparse.ArgumentParser(
        description="process injection and evasion testing"
    )
    parser.add_argument("-m", "--mode",
                        choices=["test", "rename", "ptrace", "preload", "maps"],
                        default="test",
                        help="operation mode")
    parser.add_argument("-p", "--pid", type=int,
                        help="target pid (test processes only)")
    parser.add_argument("-n", "--name",
                        help="new name for rename mode")
    parser.add_argument("-o", "--output",
                        help="save results to json")
    args = parser.parse_args()

    tester = EvasionTester()

    if args.mode == "test":
        results = tester.run_all()
        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\nsaved to {args.output}")
        return

    if args.mode == "rename":
        if not args.pid or not args.name:
            print("rename requires --pid and --name")
            sys.exit(1)
        if not is_own_process(args.pid):
            print("safety: can only rename own processes")
            sys.exit(1)
        success, detail = tester.renamer.rename(args.pid, args.name)
        print(detail)
        return

    if args.mode == "ptrace":
        if not args.pid:
            print("ptrace requires --pid")
            sys.exit(1)
        success, detail = tester.ptrace.attach(args.pid)
        print(detail)
        if success:
            tester.ptrace.detach(args.pid)
        return

    if args.mode == "preload":
        info = tester.preload.check_system_preloads()
        findings = tester.preload.scan_process_preloads()
        print(f"system ld_preload: {info['etc_preload'] or 'none'}")
        print(f"env ld_preload: {info['env_preload'] or 'none'}")
        print(f"processes with preload: {len(findings)}")
        for f in findings:
            print(f"  pid={f['pid']} {f['name']}: {f['preload']}")
        return

    if args.mode == "maps":
        if not args.pid:
            print("maps requires --pid")
            sys.exit(1)
        maps, err = tester.mem_writer.read_maps(args.pid)
        if err:
            print(f"error: {err}")
            sys.exit(1)
        for m in maps:
            print(f"  {hex(m['start'])}-{hex(m['end'])} {m['perms']} {m['path']}")


if __name__ == "__main__":
    main()
