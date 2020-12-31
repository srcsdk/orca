#!/usr/bin/env python3
"""process injection and evasion testing framework"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path


SAFETY_MARKER = "VADED_TEST_PROCESS"


def get_os():
    return platform.system().lower()


def is_test_process(pid):
    """verify a process was started by this tool for testing"""
    os_type = get_os()
    if os_type == "linux":
        try:
            environ = Path(f"/proc/{pid}/environ").read_bytes()
            return SAFETY_MARKER.encode() in environ
        except (FileNotFoundError, PermissionError):
            return False
    return False


def is_own_process(pid):
    """check if pid belongs to current user"""
    os_type = get_os()
    if os_type == "linux":
        try:
            status = Path(f"/proc/{pid}/status").read_text()
            match = re.search(r"Uid:\s+(\d+)", status)
            if match:
                return int(match.group(1)) == os.getuid()
        except (FileNotFoundError, PermissionError):
            pass
        return False
    if os_type == "darwin":
        try:
            result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "uid="],
                capture_output=True, text=True, timeout=5
            )
            uid = result.stdout.strip()
            return uid.isdigit() and int(uid) == os.getuid()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    if os_type == "windows":
        return True
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
    """rename process via /proc/pid/comm (linux only)"""

    def rename(self, pid, new_name):
        """rename a process (max 15 chars, own process only)"""
        if get_os() != "linux":
            return False, "process renaming only supported on linux"
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
    """demonstrate ptrace-based process attachment (linux only)"""

    PTRACE_ATTACH = 16
    PTRACE_DETACH = 17
    PTRACE_PEEKDATA = 2

    def __init__(self):
        self.libc = None
        if get_os() == "linux":
            try:
                import ctypes
                import ctypes.util
                libc_name = ctypes.util.find_library("c")
                self.libc = ctypes.CDLL(libc_name, use_errno=True) if libc_name else None
            except (ImportError, OSError):
                pass

    def attach(self, pid):
        """attach to a process (test processes only)"""
        if get_os() != "linux":
            return False, "ptrace only supported on linux"
        if not is_test_process(pid):
            return False, "safety: can only attach to test processes"
        if not is_own_process(pid):
            return False, "safety: can only attach to own processes"
        if not self.libc:
            return False, "libc not available"
        import ctypes
        result = self.libc.ptrace(self.PTRACE_ATTACH, pid, 0, 0)
        if result == -1:
            errno = ctypes.get_errno()
            return False, f"ptrace attach failed (errno {errno})"
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
        import ctypes
        self.libc.ptrace.restype = ctypes.c_long
        data = self.libc.ptrace(self.PTRACE_PEEKDATA, pid, address, 0)
        return True, {"pid": pid, "address": hex(address), "data": hex(data)}


class PreloadDemo:
    """demonstrate ld_preload / dyld_insert technique detection"""

    def check_system_preloads(self):
        """check for existing preload configuration"""
        os_type = get_os()
        results = {
            "env_preload": None,
            "system_preload": None,
            "process_preloads": [],
        }

        if os_type == "linux":
            results["env_preload"] = os.environ.get("LD_PRELOAD", None)
            preload_path = Path("/etc/ld.so.preload")
            if preload_path.exists():
                try:
                    results["system_preload"] = preload_path.read_text().strip()
                except PermissionError:
                    results["system_preload"] = "permission denied"
        elif os_type == "darwin":
            results["env_preload"] = os.environ.get("DYLD_INSERT_LIBRARIES", None)
        elif os_type == "windows":
            results["env_preload"] = "n/a (windows uses dll injection)"

        return results

    def scan_process_preloads(self):
        """check running processes for preload libraries"""
        os_type = get_os()
        findings = []

        if os_type == "linux":
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
        elif os_type == "darwin":
            try:
                result = subprocess.run(
                    ["ps", "-eo", "pid=,comm="],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.strip().split("\n"):
                    parts = line.strip().split(None, 1)
                    if len(parts) == 2 and parts[0].isdigit():
                        pid = int(parts[0])
                        try:
                            env_result = subprocess.run(
                                ["ps", "-p", str(pid), "-wwE"],
                                capture_output=True, text=True, timeout=5
                            )
                            if "DYLD_INSERT_LIBRARIES" in env_result.stdout:
                                findings.append({
                                    "pid": pid,
                                    "name": parts[1],
                                    "preload": "DYLD_INSERT_LIBRARIES detected",
                                })
                        except (subprocess.TimeoutExpired, FileNotFoundError):
                            continue
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return findings


class MemoryWriter:
    """demonstrate /proc/pid/mem reading (test processes only)"""

    def read_maps(self, pid):
        """read process memory mappings"""
        os_type = get_os()
        if os_type == "linux":
            return self._read_linux_maps(pid)
        if os_type == "darwin":
            return self._read_darwin_maps(pid)
        return None, "memory map reading not supported on this platform"

    def _read_linux_maps(self, pid):
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

    def _read_darwin_maps(self, pid):
        if not is_own_process(pid):
            return None, "safety: can only read own process maps"
        maps = []
        try:
            result = subprocess.run(
                ["vmmap", str(pid)],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                match = re.search(
                    r'([0-9a-f]+)-([0-9a-f]+)\s+.*?([rwx-]{3})',
                    line, re.IGNORECASE
                )
                if match:
                    maps.append({
                        "start": int(match.group(1), 16),
                        "end": int(match.group(2), 16),
                        "perms": match.group(3),
                        "path": "",
                    })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
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
        self.os_type = get_os()

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
        """test process renaming (linux only)"""
        if self.os_type != "linux":
            return False, "process rename test requires linux"
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
        """test ptrace attachment (linux only)"""
        if self.os_type != "linux":
            return False, "ptrace test requires linux"
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
        if self.os_type != "linux":
            return True, {"deleted_binaries": [], "note": "linux-only check"}
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

    def test_environment_check(self):
        """check for suspicious environment variables"""
        suspicious_vars = [
            "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "LD_LIBRARY_PATH",
            "DYLD_LIBRARY_PATH", "PYTHONSTARTUP",
        ]
        found = {}
        for var in suspicious_vars:
            val = os.environ.get(var)
            if val:
                found[var] = val
        return True, {
            "suspicious_env_vars": found if found else "none found",
        }

    def test_temp_executables(self):
        """check for executable files in temp directories"""
        temp_dirs = [tempfile.gettempdir()]
        if self.os_type != "windows":
            temp_dirs.extend(["/tmp", "/var/tmp", "/dev/shm"])
        else:
            temp_dirs.append(os.environ.get("TEMP", "C:\\Temp"))

        executables = []
        for tmp in temp_dirs:
            if not os.path.isdir(tmp):
                continue
            try:
                for name in os.listdir(tmp):
                    fpath = os.path.join(tmp, name)
                    if not os.path.isfile(fpath):
                        continue
                    if self.os_type == "windows":
                        if name.lower().endswith((".exe", ".bat", ".ps1", ".vbs")):
                            executables.append(fpath)
                    else:
                        try:
                            if os.access(fpath, os.X_OK):
                                executables.append(fpath)
                        except OSError:
                            continue
            except PermissionError:
                continue

        return True, {
            "temp_executables": executables[:20],
            "count": len(executables),
        }

    def run_all(self):
        """run complete test suite"""
        print(f"evasion test suite (platform: {self.os_type})")
        print()

        print("process manipulation:")
        self.run_test("process_rename", self.test_rename)
        self.run_test("ptrace_attach", self.test_ptrace_attach)

        print("\nreconnaissance:")
        self.run_test("preload_scan", self.test_preload_scan)
        self.run_test("memory_map_read", self.test_memory_maps)
        self.run_test("environment_check", self.test_environment_check)

        print("\ndetection checks:")
        self.run_test("deleted_binary_scan", self.test_deleted_binary_detection)
        self.run_test("temp_executables", self.test_temp_executables)

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
                        help="operation mode (default: test)")
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
        print(f"system preload: {info.get('system_preload') or 'none'}")
        print(f"env preload: {info.get('env_preload') or 'none'}")
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
