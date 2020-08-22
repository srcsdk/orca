#!/usr/bin/env python3
"""intrusion detection system with signature and anomaly detection"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from collections import defaultdict, deque
from datetime import datetime


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

        # track packet rate
        self.packet_rates[key].append(timestamp)
        cutoff = timestamp - self.window
        while self.packet_rates[key] and self.packet_rates[key][0] < cutoff:
            self.packet_rates[key].popleft()
        current_rate = len(self.packet_rates[key])

        # update baseline
        bl = self.baselines[key]
        bl["count"] += 1
        bl["mean"] += (current_rate - bl["mean"]) / bl["count"]

        # detect rate anomaly (3x baseline after warmup)
        if bl["count"] > 10 and current_rate > bl["mean"] * 3:
            alerts.append({
                "type": "rate_anomaly",
                "source": src_ip,
                "rate": current_rate,
                "baseline": round(bl["mean"], 1),
                "severity": "high",
            })

        # track unique destinations per source (scan detection)
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

        # deduplicate within window
        while (self.recent[key] and
               self.recent[key][0] < now - self.threshold_window):
            self.recent[key].popleft()
        if len(self.recent[key]) > 3:
            return None

        self.recent[key].append(now)

        # calculate score
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

        # signature-based checks
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

        # anomaly-based checks
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


def main():
    parser = argparse.ArgumentParser(description="intrusion detection system")
    parser.add_argument("-i", "--interface", default="eth0",
                        help="network interface")
    parser.add_argument("-r", "--rules", help="snort rules file")
    parser.add_argument("-f", "--filter", help="bpf filter")
    parser.add_argument("-o", "--output", help="save alerts to json")
    args = parser.parse_args()

    if os.geteuid() != 0:
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
