#!/usr/bin/env python3
"""intrusion detection system with signature and anomaly detection"""

import argparse
import json
import os
import platform
import re
import signal
import subprocess
import sys
import time
from collections import defaultdict, deque
from datetime import datetime


def get_os():
    return platform.system().lower()


class Rule:
    """ids detection rule (snort-compatible format)"""

    def __init__(self, rule_id, action, protocol, src, dst,
                 msg="", content=None, flags=None, threshold=0,
                 severity="medium"):
        self.rule_id = rule_id
        self.action = action
        self.protocol = protocol
        self.src = src
        self.dst = dst
        self.msg = msg
        self.content = content
        self.flags = flags
        self.threshold = threshold
        self.severity = severity
        self.hit_count = 0

    @classmethod
    def from_snort_line(cls, line):
        """parse a basic snort rule"""
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        match = re.match(
            r'(\w+)\s+(\w+)\s+(\S+)\s+\S+\s+[<>-]+\s+(\S+)\s+\S+\s*\((.+)\)',
            line
        )
        if not match:
            return None
        action = match.group(1)
        protocol = match.group(2)
        src = match.group(3)
        dst = match.group(4)
        options = match.group(5)
        msg = ""
        content = None
        sid = 0
        msg_match = re.search(r'msg\s*:\s*"([^"]+)"', options)
        if msg_match:
            msg = msg_match.group(1)
        content_match = re.search(r'content\s*:\s*"([^"]+)"', options)
        if content_match:
            content = content_match.group(1)
        sid_match = re.search(r'sid\s*:\s*(\d+)', options)
        if sid_match:
            sid = int(sid_match.group(1))
        return cls(sid, action, protocol, src, dst,
                   msg=msg, content=content)


class AnomalyDetector:
    """statistical anomaly detection for network traffic"""

    def __init__(self, window=60):
        self.window = window
        self.packet_rates = defaultdict(deque)
        self.baselines = defaultdict(lambda: {"mean": 0, "count": 0})
        self.connection_tracker = defaultdict(set)

    def record_packet(self, src_ip, dst_ip, dst_port, timestamp):
        """record a packet and check for anomalies"""
        alerts = []
        key = src_ip

        self.packet_rates[key].append(timestamp)
        cutoff = timestamp - self.window
        while self.packet_rates[key] and self.packet_rates[key][0] < cutoff:
            self.packet_rates[key].popleft()
        current_rate = len(self.packet_rates[key])

        bl = self.baselines[key]
        bl["count"] += 1
        bl["mean"] += (current_rate - bl["mean"]) / bl["count"]

        if bl["count"] > 10 and current_rate > bl["mean"] * 3:
            alerts.append({
                "type": "rate_anomaly",
                "source": src_ip,
                "rate": current_rate,
                "baseline": round(bl["mean"], 1),
                "severity": "high",
            })

        self.connection_tracker[src_ip].add((dst_ip, dst_port))
        unique = len(self.connection_tracker[src_ip])
        if unique > 50:
            alerts.append({
                "type": "scan_anomaly",
                "source": src_ip,
                "unique_destinations": unique,
                "severity": "high",
            })

        return alerts


class AlertManager:
    """manage and deduplicate alerts"""

    def __init__(self, threshold_window=60):
        self.alerts = []
        self.recent = defaultdict(deque)
        self.threshold_window = threshold_window
        self.scores = defaultdict(float)

    def add_alert(self, alert):
        """add alert with deduplication and scoring"""
        key = f"{alert.get('source', '')}:{alert.get('type', '')}"
        now = time.time()

        while (self.recent[key] and
               self.recent[key][0] < now - self.threshold_window):
            self.recent[key].popleft()
        if len(self.recent[key]) > 3:
            return None

        self.recent[key].append(now)

        severity_scores = {
            "critical": 10, "high": 7, "medium": 4, "low": 1
        }
        score = severity_scores.get(alert.get("severity", "low"), 1)
        self.scores[alert.get("source", "")] += score

        alert["timestamp"] = datetime.fromtimestamp(now).isoformat()
        alert["score"] = self.scores[alert.get("source", "")]
        self.alerts.append(alert)
        return alert

    def get_high_risk_sources(self, min_score=20):
        """return sources exceeding score threshold"""
        return {ip: score for ip, score in self.scores.items()
                if score >= min_score}


class IDS:
    """main intrusion detection engine"""

    def __init__(self):
        self.rules = []
        self.anomaly = AnomalyDetector()
        self.alert_mgr = AlertManager()
        self.total_packets = 0
        self._load_builtin_rules()

    def _load_builtin_rules(self):
        builtins = [
            Rule(1, "alert", "tcp", "any", "any",
                 "syn flood", flags="S", threshold=100, severity="critical"),
            Rule(2, "alert", "tcp", "any", "any",
                 "xmas scan", flags="FPU", severity="high"),
            Rule(3, "alert", "tcp", "any", "any",
                 "null scan", flags="", severity="medium"),
            Rule(4, "alert", "tcp", "any", "any",
                 "fin scan", flags="F", severity="medium"),
            Rule(10, "alert", "tcp", "any", "any",
                 "shellcode nop sled", content="\\x90\\x90\\x90\\x90",
                 severity="critical"),
            Rule(11, "alert", "tcp", "any", "any",
                 "etc passwd access", content="/etc/passwd",
                 severity="critical"),
            Rule(12, "alert", "tcp", "any", "any",
                 "reverse shell", content="/bin/sh",
                 severity="critical"),
            Rule(13, "alert", "tcp", "any", "any",
                 "sql injection", content="UNION SELECT",
                 severity="high"),
        ]
        self.rules.extend(builtins)

    def load_rules_file(self, path):
        """load snort-format rules from file"""
        loaded = 0
        with open(path) as f:
            for line in f:
                rule = Rule.from_snort_line(line)
                if rule:
                    self.rules.append(rule)
                    loaded += 1
        return loaded

    def process_packet(self, src_ip, dst_ip, dst_port, flags="",
                       payload="", timestamp=None):
        """analyze a single packet"""
        timestamp = timestamp or time.time()
        self.total_packets += 1

        for rule in self.rules:
            matched = False
            if rule.content and payload:
                if rule.content.lower() in payload.lower():
                    matched = True
            if rule.flags and flags:
                if all(f in flags for f in rule.flags):
                    matched = True
            if matched:
                rule.hit_count += 1
                alert = {
                    "type": "signature",
                    "rule_id": rule.rule_id,
                    "message": rule.msg,
                    "source": src_ip,
                    "destination": f"{dst_ip}:{dst_port}",
                    "severity": rule.severity,
                }
                result = self.alert_mgr.add_alert(alert)
                if result:
                    self.print_alert(result)

        anomalies = self.anomaly.record_packet(
            src_ip, dst_ip, dst_port, timestamp
        )
        for anomaly in anomalies:
            result = self.alert_mgr.add_alert(anomaly)
            if result:
                self.print_alert(result)

    def print_alert(self, alert):
        """display alert"""
        sev = alert["severity"].upper()
        atype = alert["type"]
        src = alert.get("source", "unknown")
        msg = alert.get("message", atype)
        score = alert.get("score", 0)
        print(f"[{sev}] {msg} from {src} (score: {score})")

    def stats(self):
        """return ids statistics"""
        return {
            "total_packets": self.total_packets,
            "total_alerts": len(self.alert_mgr.alerts),
            "high_risk": self.alert_mgr.get_high_risk_sources(),
            "rule_hits": {r.msg: r.hit_count for r in self.rules
                         if r.hit_count > 0},
        }


def parse_tcpdump_line(line):
    """extract packet info from tcpdump output"""
    ip_match = re.search(
        r'(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+'
        r'(\d+\.\d+\.\d+\.\d+)\.(\d+)',
        line
    )
    if not ip_match:
        return None
    flags = ""
    flag_match = re.search(r'Flags \[([^\]]+)\]', line)
    if flag_match:
        flags = flag_match.group(1)
    return {
        "src_ip": ip_match.group(1),
        "src_port": int(ip_match.group(2)),
        "dst_ip": ip_match.group(3),
        "dst_port": int(ip_match.group(4)),
        "flags": flags,
        "raw": line,
    }


def monitor_interface(interface, ids_engine, bpf_filter=None):
    """monitor live traffic"""
    cmd = ["tcpdump", "-i", interface, "-nn", "-l"]
    if bpf_filter:
        cmd.extend(bpf_filter.split())

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    def stop(sig, frame):
        proc.terminate()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    for line in proc.stdout:
        pkt = parse_tcpdump_line(line)
        if pkt:
            ids_engine.process_packet(
                pkt["src_ip"], pkt["dst_ip"], pkt["dst_port"],
                flags=pkt["flags"], payload=pkt["raw"]
            )

    proc.wait()


def show_security_events():
    """show recent security-related events from system logs"""
    os_type = get_os()
    print(f"[weewoo] recent security events ({platform.system()})")
    print()

    if os_type == "linux":
        _show_linux_events()
    elif os_type == "darwin":
        _show_macos_events()
    elif os_type == "windows":
        _show_windows_events()


def _show_linux_events():
    """show security events from journalctl or log files"""
    events = []

    try:
        result = subprocess.run(
            ["journalctl", "--no-pager", "-n", "50", "-p", "warning",
             "--since", "24 hours ago"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    events.append(line)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    if not events:
        for log_path in ["/var/log/auth.log", "/var/log/secure",
                         "/var/log/syslog"]:
            try:
                with open(log_path) as f:
                    lines = f.readlines()
                for line in lines[-50:]:
                    lower = line.lower()
                    if any(kw in lower for kw in [
                        "failed", "error", "denied", "invalid",
                        "unauthorized", "attack"
                    ]):
                        events.append(line.strip())
            except (FileNotFoundError, PermissionError):
                continue

    if not events:
        print("  no recent security events found")
        return

    for event in events[-30:]:
        print(f"  {event}")
    print(f"\n  total events shown: {min(len(events), 30)}")


def _show_macos_events():
    """show security events from macos log system"""
    try:
        result = subprocess.run(
            ["log", "show", "--predicate",
             'eventMessage CONTAINS "error" OR eventMessage CONTAINS "denied" '
             'OR eventMessage CONTAINS "failed"',
             "--last", "1h", "--style", "compact"],
            capture_output=True, text=True, timeout=30
        )
        if result.stdout.strip():
            lines = result.stdout.strip().split("\n")
            for line in lines[-30:]:
                print(f"  {line}")
            print(f"\n  total events: {len(lines)}")
        else:
            print("  no recent security events found")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("  could not query macos log system")


def _show_windows_events():
    """show security events from windows event log"""
    try:
        result = subprocess.run(
            ["wevtutil", "qe", "Security", "/c:30", "/rd:true",
             "/f:text"],
            capture_output=True, text=True, timeout=15
        )
        if result.stdout.strip():
            print(result.stdout)
        else:
            result = subprocess.run(
                ["wevtutil", "qe", "System", "/c:30", "/rd:true",
                 "/f:text"],
                capture_output=True, text=True, timeout=15
            )
            if result.stdout.strip():
                print(result.stdout)
            else:
                print("  no recent events found")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("  could not query windows event log")


def check_listening_ports():
    """show listening ports as a quick security check"""
    os_type = get_os()
    print("\n[weewoo] listening ports")
    print()

    if os_type == "linux":
        try:
            result = subprocess.run(
                ["ss", "-tulnp"],
                capture_output=True, text=True, timeout=10
            )
            print(result.stdout)
            return
        except FileNotFoundError:
            pass

    if os_type == "darwin":
        try:
            result = subprocess.run(
                ["lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"],
                capture_output=True, text=True, timeout=10
            )
            print(result.stdout)
            return
        except FileNotFoundError:
            pass

    if os_type == "windows":
        try:
            result = subprocess.run(
                ["netstat", "-ano", "-p", "tcp"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split("\n"):
                if "LISTENING" in line:
                    print(f"  {line.strip()}")
            return
        except FileNotFoundError:
            pass

    try:
        result = subprocess.run(
            ["netstat", "-tulnp"],
            capture_output=True, text=True, timeout=10
        )
        print(result.stdout)
    except FileNotFoundError:
        print("  no network tools available")


def main():
    parser = argparse.ArgumentParser(description="intrusion detection system")
    parser.add_argument("-i", "--interface",
                        help="network interface for live capture")
    parser.add_argument("-r", "--rules", help="snort rules file")
    parser.add_argument("-f", "--filter", help="bpf filter")
    parser.add_argument("-o", "--output", help="save alerts to json")
    parser.add_argument("-e", "--events", action="store_true",
                        help="show recent security events")
    parser.add_argument("-l", "--listen", action="store_true",
                        help="show listening ports")
    args = parser.parse_args()

    if args.events or (not args.interface and not args.listen):
        show_security_events()
        if not args.interface:
            check_listening_ports()
            return

    if args.listen:
        check_listening_ports()
        return

    is_root = (os.getuid() == 0) if hasattr(os, "getuid") else True
    if not is_root:
        print("requires root for live capture", file=sys.stderr)
        sys.exit(1)

    ids = IDS()

    if args.rules:
        loaded = ids.load_rules_file(args.rules)
        print(f"loaded {loaded} rules from {args.rules}")

    print(f"ids monitoring {args.interface}")
    print(f"{len(ids.rules)} rules active")
    print()

    try:
        monitor_interface(args.interface, ids, args.filter)
    except KeyboardInterrupt:
        pass

    stats = ids.stats()
    print(f"\n--- ids summary ---")
    print(f"packets: {stats['total_packets']}")
    print(f"alerts:  {stats['total_alerts']}")
    if stats["high_risk"]:
        print(f"high risk sources:")
        for ip, score in stats["high_risk"].items():
            print(f"  {ip}: score {score}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump({
                "stats": stats,
                "alerts": ids.alert_mgr.alerts,
            }, f, indent=2, default=str)
        print(f"saved to {args.output}")


if __name__ == "__main__":
    main()
