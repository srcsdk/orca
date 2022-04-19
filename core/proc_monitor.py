#!/usr/bin/env python3
"""process monitoring for security anomaly detection"""

import os
import re


def list_processes():
    """list running processes from /proc."""
    processes = []
    if not os.path.isdir("/proc"):
        return processes
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            pid = int(entry)
            info = get_process_info(pid)
            if info:
                processes.append(info)
    return processes


def get_process_info(pid):
    """get detailed info for a process."""
    try:
        with open(f"/proc/{pid}/comm") as f:
            name = f.read().strip()
        with open(f"/proc/{pid}/status") as f:
            status = f.read()
        uid_match = re.search(r"Uid:\s+(\d+)", status)
        mem_match = re.search(r"VmRSS:\s+(\d+)", status)
        ppid_match = re.search(r"PPid:\s+(\d+)", status)
        return {
            "pid": pid,
            "name": name,
            "uid": int(uid_match.group(1)) if uid_match else -1,
            "memory_kb": int(mem_match.group(1)) if mem_match else 0,
            "ppid": int(ppid_match.group(1)) if ppid_match else 0,
        }
    except (FileNotFoundError, PermissionError):
        return None


def find_suspicious(processes, known_good=None):
    """find processes that might be suspicious."""
    if known_good is None:
        known_good = {
            "systemd", "sshd", "bash", "python3", "python",
            "init", "kthreadd", "cron", "rsyslogd",
        }
    suspicious = []
    for proc in processes:
        flags = []
        if proc["name"] not in known_good:
            if proc["uid"] == 0:
                flags.append("root_process")
        if proc["memory_kb"] > 500000:
            flags.append("high_memory")
        if flags:
            proc["flags"] = flags
            suspicious.append(proc)
    return suspicious


def check_listeners():
    """check network listening processes."""
    listeners = []
    try:
        with open("/proc/net/tcp") as f:
            lines = f.readlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) >= 4:
                local = parts[1]
                state = parts[3]
                if state == "0A":
                    addr_parts = local.split(":")
                    port = int(addr_parts[1], 16)
                    listeners.append({"port": port, "raw": local})
    except (FileNotFoundError, PermissionError):
        pass
    return listeners


def top_memory(processes, n=10):
    """return top n processes by memory usage."""
    sorted_procs = sorted(
        processes, key=lambda p: p.get("memory_kb", 0), reverse=True
    )
    return sorted_procs[:n]


if __name__ == "__main__":
    procs = list_processes()
    print(f"running processes: {len(procs)}")
    top = top_memory(procs, 5)
    print("\ntop memory:")
    for p in top:
        print(f"  {p['name']:>20} (pid {p['pid']}): "
              f"{p['memory_kb']} kb")
    listeners = check_listeners()
    print(f"\nlistening ports: {len(listeners)}")
    for l in listeners[:5]:
        print(f"  port {l['port']}")
