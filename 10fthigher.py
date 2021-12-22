#!/usr/bin/env python3
"""dynamic firewall rule management"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import time
from collections import defaultdict, deque
from datetime import datetime

PLATFORM = platform.system().lower()


def _detect_firewall_backend():
    """auto-detect available firewall backend for this platform"""
    if PLATFORM == "windows":
        return "netsh"
    elif PLATFORM == "darwin":
        return "pfctl"
    else:
        for cmd in ["iptables", "nft"]:
            try:
                result = subprocess.run(
                    [cmd, "--version"], capture_output=True, timeout=5
                )
                if result.returncode == 0:
                    return cmd
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return "iptables"


class FirewallBackend:
    """cross-platform firewall abstraction"""

    def __init__(self, backend=None):
        self.backend = backend or _detect_firewall_backend()
        self.chain = "DYNAMIC_BLOCK"

    def setup_chain(self):
        """create custom chain if it does not exist"""
        if self.backend == "iptables":
            subprocess.run(
                ["iptables", "-N", self.chain],
                capture_output=True
            )
            result = subprocess.run(
                ["iptables", "-C", "INPUT", "-j", self.chain],
                capture_output=True
            )
            if result.returncode != 0:
                subprocess.run(
                    ["iptables", "-I", "INPUT", "1", "-j", self.chain],
                    capture_output=True
                )
        elif self.backend == "pfctl":
            pass
        elif self.backend == "netsh":
            pass

    def block_ip(self, ip):
        """block an ip address"""
        if self.backend == "iptables":
            check = subprocess.run(
                ["iptables", "-C", self.chain, "-s", ip, "-j", "DROP"],
                capture_output=True
            )
            if check.returncode != 0:
                result = subprocess.run(
                    ["iptables", "-A", self.chain, "-s", ip, "-j", "DROP"],
                    capture_output=True
                )
                return result.returncode == 0
        elif self.backend == "pfctl":
            result = subprocess.run(
                ["pfctl", "-t", self.chain, "-T", "add", ip],
                capture_output=True
            )
            return result.returncode == 0
        elif self.backend == "netsh":
            result = subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=block_{ip}", "dir=in", "action=block",
                f"remoteip={ip}"
            ], capture_output=True)
            return result.returncode == 0
        return False

    def unblock_ip(self, ip):
        """remove block for an ip"""
        if self.backend == "iptables":
            result = subprocess.run(
                ["iptables", "-D", self.chain, "-s", ip, "-j", "DROP"],
                capture_output=True
            )
            return result.returncode == 0
        elif self.backend == "pfctl":
            result = subprocess.run(
                ["pfctl", "-t", self.chain, "-T", "delete", ip],
                capture_output=True
            )
            return result.returncode == 0
        elif self.backend == "netsh":
            result = subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name=block_{ip}"
            ], capture_output=True)
            return result.returncode == 0
        return False

    def rate_limit(self, ip, limit="10/minute"):
        """add rate limiting rule"""
        if self.backend == "iptables":
            subprocess.run([
                "iptables", "-A", self.chain, "-s", ip,
                "-m", "limit", "--limit", limit, "-j", "ACCEPT"
            ], capture_output=True)
            subprocess.run([
                "iptables", "-A", self.chain, "-s", ip, "-j", "DROP"
            ], capture_output=True)

    def list_rules(self):
        """list current firewall rules"""
        if self.backend == "iptables":
            result = subprocess.run(
                ["iptables", "-L", self.chain, "-n", "-v", "--line-numbers"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                return result.stdout
            result = subprocess.run(
                ["iptables", "-L", "-n", "-v", "--line-numbers"],
                capture_output=True, text=True
            )
            return result.stdout if result.returncode == 0 else ""
        elif self.backend == "pfctl":
            result = subprocess.run(
                ["pfctl", "-sr"], capture_output=True, text=True
            )
            return result.stdout if result.returncode == 0 else ""
        elif self.backend == "netsh":
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 "name=all"],
                capture_output=True, text=True
            )
            return result.stdout if result.returncode == 0 else ""
        return ""

    def flush(self):
        """remove all dynamic rules"""
        if self.backend == "iptables":
            subprocess.run(
                ["iptables", "-F", self.chain], capture_output=True
            )
        elif self.backend == "pfctl":
            subprocess.run(
                ["pfctl", "-t", self.chain, "-T", "flush"],
                capture_output=True
            )
        elif self.backend == "netsh":
            subprocess.run([
                "netsh", "advfirewall", "reset"
            ], capture_output=True)


class RuleManager:
    """manage firewall rules with persistence and automation"""

    def __init__(self, backend="iptables", state_file=None):
        self.firewall = FirewallBackend(backend)
        self.state_file = state_file or "/var/lib/dynfw/state.json"
        self.blocked = {}
        self.whitelist = set()
        self.rate_limited = {}
        self.history = []

    def load_state(self):
        """load persisted rules"""
        if not os.path.exists(self.state_file):
            return
        try:
            with open(self.state_file) as f:
                state = json.load(f)
            self.blocked = state.get("blocked", {})
            self.whitelist = set(state.get("whitelist", []))
            self.rate_limited = state.get("rate_limited", {})
        except (json.JSONDecodeError, PermissionError):
            pass

    def save_state(self):
        """persist current rules"""
        state_dir = os.path.dirname(self.state_file)
        if state_dir:
            os.makedirs(state_dir, exist_ok=True)
        with open(self.state_file, "w") as f:
            json.dump({
                "blocked": self.blocked,
                "whitelist": list(self.whitelist),
                "rate_limited": self.rate_limited,
                "last_saved": datetime.now().isoformat(),
            }, f, indent=2)

    def load_whitelist(self, path):
        """load whitelist from file"""
        if not os.path.exists(path):
            return 0
        with open(path) as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith("#"):
                    self.whitelist.add(ip)
        return len(self.whitelist)

    def load_blocklist(self, path):
        """load and apply blocklist"""
        if not os.path.exists(path):
            return 0
        count = 0
        with open(path) as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith("#"):
                    if self.block(ip, "blocklist"):
                        count += 1
        return count

    def block(self, ip, reason="manual"):
        """block an ip address"""
        if ip in self.whitelist:
            self.log(f"skipping whitelisted {ip}")
            return False
        if ip in self.blocked:
            return False
        self.firewall.block_ip(ip)
        self.blocked[ip] = {
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
        }
        self.log(f"blocked {ip} ({reason})")
        return True

    def unblock(self, ip):
        """remove block for an ip"""
        if ip not in self.blocked:
            return False
        self.firewall.unblock_ip(ip)
        del self.blocked[ip]
        self.log(f"unblocked {ip}")
        return True

    def log(self, message):
        """log an action"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "message": message,
        }
        self.history.append(entry)
        print(f"[{entry['timestamp'][:19]}] {message}")

    def stats(self):
        """return management statistics"""
        return {
            "blocked_count": len(self.blocked),
            "whitelisted_count": len(self.whitelist),
            "rate_limited_count": len(self.rate_limited),
            "history_count": len(self.history),
        }


class LogMonitor:
    """monitor log files for failed auth and auto-block"""

    AUTH_PATTERNS = [
        (r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)", "ssh_failed"),
        (r"authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)", "pam_failed"),
        (r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)", "ssh_invalid_user"),
        (r"Connection closed by authenticating user .* (\d+\.\d+\.\d+\.\d+)",
         "ssh_closed"),
    ]

    def __init__(self, rule_manager, threshold=5, window=300):
        self.manager = rule_manager
        self.threshold = threshold
        self.window = window
        self.attempts = defaultdict(deque)
        self.patterns = [
            (re.compile(p), name) for p, name in self.AUTH_PATTERNS
        ]

    def process_line(self, line):
        """check a log line for failed auth"""
        for pattern, name in self.patterns:
            match = pattern.search(line)
            if match:
                ip = match.group(1)
                self.record_attempt(ip, name)
                return ip, name
        return None, None

    def record_attempt(self, ip, reason):
        """record a failed auth attempt"""
        now = time.time()
        self.attempts[ip].append(now)
        cutoff = now - self.window
        while self.attempts[ip] and self.attempts[ip][0] < cutoff:
            self.attempts[ip].popleft()
        if len(self.attempts[ip]) >= self.threshold:
            self.manager.block(ip, f"{reason} x{len(self.attempts[ip])}")
            self.attempts[ip].clear()

    def monitor_file(self, path):
        """tail and monitor a log file"""
        with open(path) as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if line:
                    self.process_line(line)
                else:
                    time.sleep(0.5)


def _check_root():
    """check for root/admin privileges"""
    if PLATFORM == "windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (ImportError, AttributeError):
            return False
    return os.geteuid() == 0


def _default_state_path():
    """return platform-appropriate state file path"""
    if PLATFORM == "windows":
        appdata = os.environ.get("APPDATA", "C:\\ProgramData")
        return os.path.join(appdata, "dynfw", "state.json")
    return "/var/lib/dynfw/state.json"


def show_current_rules():
    """show current firewall rules without requiring root (best effort)"""
    print("dynamic firewall rule management")
    print(f"platform: {PLATFORM}, backend: {_detect_firewall_backend()}\n")
    print("current firewall rules:\n")
    try:
        if PLATFORM == "windows":
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 "name=all", "dir=in"],
                capture_output=True, text=True, timeout=10
            )
            # show first 40 lines to avoid flooding output
            lines = result.stdout.strip().split("\n")
            for line in lines[:40]:
                print(f"  {line}")
            if len(lines) > 40:
                print(f"  ... ({len(lines) - 40} more lines)")
        elif PLATFORM == "darwin":
            result = subprocess.run(
                ["pfctl", "-sr"], capture_output=True, text=True, timeout=5
            )
            output = result.stdout.strip() or result.stderr.strip()
            print(output or "  (no rules or requires root)")
        else:
            result = subprocess.run(
                ["iptables", "-L", "-n", "--line-numbers"],
                capture_output=True, text=True, timeout=5
            )
            print(result.stdout.strip() or "  (no rules or requires root)")
    except (subprocess.TimeoutExpired, OSError):
        print("  could not read firewall rules (may need root/admin)")
    print("\nuse --list with root/admin for full details")
    print("use --help to see all options")


def main():
    parser = argparse.ArgumentParser(
        description="dynamic firewall rule management"
    )
    parser.add_argument("-b", "--blocklist", help="load ip blocklist file")
    parser.add_argument("-w", "--whitelist", help="whitelist file")
    parser.add_argument("-m", "--monitor", help="monitor auth log file")
    parser.add_argument("--threshold", type=int, default=5,
                        help="failed auth threshold (default: 5)")
    parser.add_argument("--backend", default=None,
                        choices=["iptables", "nftables", "pfctl", "netsh"],
                        help="firewall backend (auto-detected)")
    parser.add_argument("--state", default=None,
                        help="state file for persistence")
    parser.add_argument("--block", help="block a single ip")
    parser.add_argument("--unblock", help="unblock a single ip")
    parser.add_argument("--list", action="store_true", help="list rules")
    parser.add_argument("--flush", action="store_true",
                        help="remove all dynamic rules")
    args = parser.parse_args()

    # default behavior: show rules without requiring root
    no_action = not any([
        args.blocklist, args.whitelist, args.monitor, args.block,
        args.unblock, args.list, args.flush
    ])
    if no_action:
        show_current_rules()
        return

    if not _check_root():
        print("requires root/admin for firewall management", file=sys.stderr)
        sys.exit(1)

    backend = args.backend or _detect_firewall_backend()
    state_file = args.state or _default_state_path()

    manager = RuleManager(backend=backend, state_file=state_file)
    manager.load_state()
    manager.firewall.setup_chain()

    if args.whitelist:
        count = manager.load_whitelist(args.whitelist)
        print(f"loaded {count} whitelisted ips")

    if args.list:
        print(manager.firewall.list_rules())
        stats = manager.stats()
        print(f"\nblocked: {stats['blocked_count']}")
        print(f"whitelisted: {stats['whitelisted_count']}")
        return

    if args.flush:
        manager.firewall.flush()
        manager.blocked.clear()
        manager.save_state()
        print("all dynamic rules flushed")
        return

    if args.block:
        manager.block(args.block, "manual")
        manager.save_state()
        return

    if args.unblock:
        manager.unblock(args.unblock)
        manager.save_state()
        return

    if args.blocklist:
        count = manager.load_blocklist(args.blocklist)
        print(f"blocked {count} ips from blocklist")

    if args.monitor:
        print(f"monitoring {args.monitor} (threshold: {args.threshold})")
        monitor = LogMonitor(manager, threshold=args.threshold)
        try:
            monitor.monitor_file(args.monitor)
        except KeyboardInterrupt:
            pass
        manager.save_state()
        stats = manager.stats()
        print(f"\nblocked: {stats['blocked_count']}")
        return

    manager.save_state()
    stats = manager.stats()
    print(f"blocked: {stats['blocked_count']}")
    print(f"whitelisted: {stats['whitelisted_count']}")


if __name__ == "__main__":
    main()
