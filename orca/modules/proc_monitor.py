#!/usr/bin/env python3
"""process monitor for suspicious activity detection"""

import os
import re


def list_processes():
    """list running processes from /proc."""
    procs = []
    if not os.path.exists("/proc"):
        return procs
    for pid_dir in os.listdir("/proc"):
        if not pid_dir.isdigit():
            continue
        pid = int(pid_dir)
        try:
            with open(f"/proc/{pid}/comm") as f:
                name = f.read().strip()
            with open(f"/proc/{pid}/status") as f:
                status = f.read()
            uid_match = re.search(r"Uid:\s+(\d+)", status)
            mem_match = re.search(r"VmRSS:\s+(\d+)", status)
            procs.append({
                "pid": pid,
                "name": name,
                "uid": int(uid_match.group(1)) if uid_match else -1,
                "mem_kb": int(mem_match.group(1)) if mem_match else 0,
            })
        except (OSError, ValueError):
            continue
    return procs


def find_suspicious(procs, known_good=None):
    """flag processes that look suspicious."""
    if known_good is None:
        known_good = {
            "systemd", "sshd", "bash", "zsh", "python3", "node",
            "nginx", "postgres", "redis-server",
        }
    suspicious = []
    for proc in procs:
        flags = []
        if proc["uid"] == 0 and proc["name"] not in known_good:
            flags.append("root_process")
        if proc["mem_kb"] > 500000:
            flags.append("high_memory")
        name = proc["name"].lower()
        bad_patterns = ["nc", "ncat", "socat", "miner", "xmrig"]
        if any(p in name for p in bad_patterns):
            flags.append("suspicious_name")
        if flags:
            proc["flags"] = flags
            suspicious.append(proc)
    return suspicious


def cpu_hogs(procs, threshold_kb=200000):
    """find processes using excessive memory."""
    return [p for p in procs if p.get("mem_kb", 0) > threshold_kb]


if __name__ == "__main__":
    procs = list_processes()
    print(f"running processes: {len(procs)}")
    suspicious = find_suspicious(procs)
    if suspicious:
        print(f"suspicious: {len(suspicious)}")
        for p in suspicious:
            print(f"  pid={p['pid']} {p['name']} flags={p['flags']}")
    else:
        print("no suspicious processes detected")
