#!/usr/bin/env python3
"""event correlation and alert engine with sigma-compatible rules"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


class Rule:
    def __init__(self, name, pattern, severity="medium", threshold=1,
                 window=300, description=""):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE) if isinstance(pattern, str) else pattern
        self.severity = severity
        self.threshold = threshold
        self.window = window
        self.description = description


DEFAULT_RULES = [
    Rule("brute_force", r"failed password|authentication failure|invalid user",
         severity="high", threshold=5, window=300,
         description="multiple failed auth attempts"),
    Rule("break_in", r"POSSIBLE BREAK.IN",
         severity="critical", threshold=1,
         description="possible break-in attempt detected"),
    Rule("port_scan", r"port scan|scan detected",
         severity="high", threshold=1,
         description="port scan activity detected"),
    Rule("privilege_escalation", r"sudo.*FAILED|su.*DENIED|unauthorized",
         severity="critical", threshold=1,
         description="privilege escalation attempt"),
    Rule("service_crash", r"segfault|core dumped|oom.killer",
         severity="high", threshold=1,
         description="service crash or oom event"),
    Rule("syn_flood", r"SYN_RECV|possible SYN flood",
         severity="high", threshold=3, window=60,
         description="syn flood indicators"),
    Rule("connection_refused", r"refused connect|connection refused",
         severity="low", threshold=10, window=300,
         description="multiple connection refusals"),
    Rule("permission_denied", r"permission denied|access denied",
         severity="medium", threshold=3, window=300,
         description="permission denied events"),
    Rule("suspicious_command", r"wget.*\|.*sh|curl.*\|.*bash|base64.*decode",
         severity="critical", threshold=1,
         description="suspicious command execution"),
    Rule("ssh_root", r"Accepted.*root|session opened.*root",
         severity="high", threshold=1,
         description="root ssh session"),
]


def load_sigma_rules(rules_path):
    """load rules from sigma-compatible yaml format"""
    rules = []
    try:
        import yaml
    except ImportError:
        print("[warn] pyyaml not available, using default rules", file=sys.stderr)
        return rules

    path = Path(rules_path)
    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = list(path.glob("*.yml")) + list(path.glob("*.yaml"))
    else:
        return rules

    for rule_file in files:
        try:
            with open(rule_file) as f:
                data = yaml.safe_load(f)
            if not data or "detection" not in data:
                continue
            detection = data["detection"]
            keywords = detection.get("keywords", [])
            if isinstance(keywords, list) and keywords:
                pattern = "|".join(re.escape(k) for k in keywords)
                rules.append(Rule(
                    name=data.get("title", rule_file.stem),
                    pattern=pattern,
                    severity=data.get("level", "medium"),
                    threshold=detection.get("threshold", 1),
                    window=detection.get("timeframe", 300),
                    description=data.get("description", ""),
                ))
        except Exception as e:
            print(f"[warn] failed to load {rule_file}: {e}", file=sys.stderr)

    return rules


class Alert:
    def __init__(self, rule_name, severity, message, source, count=1):
        self.rule_name = rule_name
        self.severity = severity
        self.message = message
        self.source = source
        self.count = count
        self.timestamp = datetime.now()
        self.dedup_key = hashlib.md5(
            f"{rule_name}:{source}:{message[:50]}".encode()
        ).hexdigest()[:12]

    def to_dict(self):
        return {
            "timestamp": self.timestamp.isoformat(),
            "rule": self.rule_name,
            "severity": self.severity,
            "source": self.source,
            "count": self.count,
            "message": self.message,
            "dedup_key": self.dedup_key,
        }


class EventCorrelator:
    def __init__(self, rules=None, dedup_window=600):
        self.rules = rules or DEFAULT_RULES
        self.events = defaultdict(list)
        self.alerts = []
        self.dedup_cache = {}
        self.dedup_window = dedup_window
        self.stats = {"events_processed": 0, "alerts_generated": 0}

    def process_event(self, line, source="unknown", timestamp=None):
        """process a single log event against all rules"""
        self.stats["events_processed"] += 1
        ts = timestamp or datetime.now()

        for rule in self.rules:
            if rule.pattern.search(line):
                key = f"{rule.name}:{source}"
                self.events[key].append({
                    "timestamp": ts,
                    "line": line,
                    "source": source,
                })
                self._prune_window(key, rule.window)

                if len(self.events[key]) >= rule.threshold:
                    self._generate_alert(rule, source, line, len(self.events[key]))

    def _prune_window(self, key, window):
        """remove events outside the time window"""
        cutoff = datetime.now() - timedelta(seconds=window)
        self.events[key] = [e for e in self.events[key] if e["timestamp"] > cutoff]

    def _generate_alert(self, rule, source, sample, count):
        """generate alert with deduplication"""
        alert = Alert(rule.name, rule.severity, sample.strip(), source, count)

        if alert.dedup_key in self.dedup_cache:
            last_alert_time = self.dedup_cache[alert.dedup_key]
            if (datetime.now() - last_alert_time).total_seconds() < self.dedup_window:
                return

        self.dedup_cache[alert.dedup_key] = datetime.now()
        self.alerts.append(alert)
        self.stats["alerts_generated"] += 1

    def process_file(self, filepath):
        """process all events in a log file"""
        source = Path(filepath).name
        try:
            with open(filepath, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        ts = self._extract_timestamp(line)
                        self.process_event(line, source, ts)
        except (PermissionError, FileNotFoundError) as e:
            print(f"[error] {filepath}: {e}", file=sys.stderr)

    def _extract_timestamp(self, line):
        """try to extract timestamp from log line"""
        # syslog
        match = re.match(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
        if match:
            try:
                year = datetime.now().year
                return datetime.strptime(f"{year} {match.group(1)}", "%Y %b %d %H:%M:%S")
            except ValueError:
                pass

        # iso format
        match = re.match(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', line)
        if match:
            try:
                return datetime.fromisoformat(match.group(1))
            except ValueError:
                pass

        return datetime.now()

    def correlate_across_sources(self):
        """find patterns that appear across multiple sources"""
        rule_sources = defaultdict(set)
        rule_counts = defaultdict(int)

        for key, events in self.events.items():
            rule_name, source = key.rsplit(":", 1)
            if events:
                rule_sources[rule_name].add(source)
                rule_counts[rule_name] += len(events)

        for rule_name, sources in rule_sources.items():
            if len(sources) > 1:
                alert = Alert(
                    f"cross_source_{rule_name}",
                    "high",
                    f"pattern '{rule_name}' detected across {len(sources)} sources: "
                    f"{', '.join(sorted(sources))}",
                    "correlator",
                    rule_counts[rule_name],
                )
                if alert.dedup_key not in self.dedup_cache:
                    self.alerts.append(alert)
                    self.dedup_cache[alert.dedup_key] = datetime.now()

    def get_report(self):
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_alerts = sorted(
            self.alerts,
            key=lambda a: severity_order.get(a.severity, 5)
        )
        return {
            "stats": self.stats,
            "alerts": [a.to_dict() for a in sorted_alerts],
            "severity_counts": {
                s: sum(1 for a in self.alerts if a.severity == s)
                for s in severity_order
            },
        }


def print_report(report, as_json=False):
    if as_json:
        print(json.dumps(report, indent=2, default=str))
        return

    stats = report["stats"]
    print(f"\nevents processed: {stats['events_processed']}")
    print(f"alerts generated: {stats['alerts_generated']}")
    print(f"severity breakdown: {report['severity_counts']}")
    print()

    for alert in report["alerts"]:
        severity = alert["severity"].upper().ljust(8)
        print(f"  [{severity}] [{alert['rule']}] {alert['message'][:120]}")
        print(f"           source={alert['source']} count={alert['count']}")


def main():
    parser = argparse.ArgumentParser(description="event correlation engine")
    parser.add_argument("-f", "--file", action="append", help="log file (repeatable)")
    parser.add_argument("-r", "--rules", help="sigma rules file or directory")
    parser.add_argument("-w", "--window", type=int, default=300, help="correlation window (seconds)")
    parser.add_argument("--dedup", type=int, default=600, help="dedup window (seconds)")
    parser.add_argument("-o", "--output", help="output alerts to file")
    parser.add_argument("--json", action="store_true", help="json output")
    parser.add_argument("--tail", action="store_true", help="tail mode")
    args = parser.parse_args()

    if not args.file:
        parser.print_help()
        sys.exit(1)

    rules = list(DEFAULT_RULES)
    if args.rules:
        sigma_rules = load_sigma_rules(args.rules)
        if sigma_rules:
            rules.extend(sigma_rules)
            print(f"[supertect] loaded {len(sigma_rules)} sigma rules", file=sys.stderr)

    for rule in rules:
        rule.window = args.window

    correlator = EventCorrelator(rules=rules, dedup_window=args.dedup)

    for filepath in args.file:
        correlator.process_file(filepath)

    correlator.correlate_across_sources()
    report = correlator.get_report()
    print_report(report, args.json)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[supertect] report saved to {args.output}", file=sys.stderr)

    if args.tail:
        print("[supertect] entering tail mode (ctrl+c to stop)", file=sys.stderr)
        positions = {}
        for fp in args.file:
            try:
                positions[fp] = os.path.getsize(fp)
            except OSError:
                positions[fp] = 0
        try:
            while True:
                for fp in args.file:
                    try:
                        size = os.path.getsize(fp)
                        if size > positions.get(fp, 0):
                            source = Path(fp).name
                            with open(fp, "r") as f:
                                f.seek(positions[fp])
                                for line in f:
                                    correlator.process_event(line.strip(), source)
                            positions[fp] = size
                    except (OSError, PermissionError):
                        continue
                time.sleep(1)
        except KeyboardInterrupt:
            report = correlator.get_report()
            print_report(report, args.json)


if __name__ == "__main__":
    main()
