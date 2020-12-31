#!/usr/bin/env python3
"""centralized log collection and normalization engine"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


SYSLOG_RE = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*'
    r'(?P<message>.*)'
)

APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+(?P<bytes>\S+)'
)

ISO_RE = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+'
    r'(?P<message>.*)'
)

JSON_RE = re.compile(r'^\s*\{.*\}\s*$')

SEVERITY_PATTERNS = [
    (re.compile(r'\b(emerg|panic|fatal)\b', re.IGNORECASE), "critical"),
    (re.compile(r'\b(error|err|crit)\b', re.IGNORECASE), "error"),
    (re.compile(r'\b(warn|warning)\b', re.IGNORECASE), "warning"),
    (re.compile(r'\b(notice|info)\b', re.IGNORECASE), "info"),
    (re.compile(r'\b(debug|trace)\b', re.IGNORECASE), "debug"),
]


def parse_syslog_timestamp(ts_str):
    """parse syslog timestamp (assumes current year)"""
    year = datetime.now().year
    try:
        dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
        return dt.isoformat()
    except ValueError:
        return ts_str


def parse_apache_timestamp(ts_str):
    """parse apache/nginx combined log timestamp"""
    try:
        dt = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
        return dt.isoformat()
    except (ValueError, IndexError):
        return ts_str


def extract_severity(text):
    for pattern, level in SEVERITY_PATTERNS:
        if pattern.search(text):
            return level
    return "info"


def parse_line(line, source):
    """parse a log line into normalized schema"""
    line = line.rstrip()
    if not line:
        return None

    record = {
        "timestamp": datetime.now().isoformat(),
        "source": source,
        "severity": "info",
        "message": line,
        "raw": line,
    }

    if JSON_RE.match(line):
        try:
            data = json.loads(line)
            record["message"] = data.get("message", data.get("msg", line))
            record["severity"] = data.get("level", data.get("severity", "info")).lower()
            ts = data.get("timestamp", data.get("time", data.get("@timestamp")))
            if ts:
                record["timestamp"] = ts
            record["fields"] = {k: v for k, v in data.items()
                                if k not in ("message", "msg", "level", "severity",
                                             "timestamp", "time", "@timestamp")}
            return record
        except json.JSONDecodeError:
            pass

    match = SYSLOG_RE.match(line)
    if match:
        record["timestamp"] = parse_syslog_timestamp(match.group("timestamp"))
        record["host"] = match.group("host")
        record["process"] = match.group("process")
        record["pid"] = match.group("pid")
        record["message"] = match.group("message")
        record["severity"] = extract_severity(record["message"])
        return record

    match = APACHE_RE.match(line)
    if match:
        record["timestamp"] = parse_apache_timestamp(match.group("timestamp"))
        record["source_ip"] = match.group("ip")
        record["method"] = match.group("method")
        record["path"] = match.group("path")
        record["status"] = int(match.group("status"))
        record["message"] = f"{match.group('method')} {match.group('path')} {match.group('status')}"
        status = record["status"]
        if status >= 500:
            record["severity"] = "error"
        elif status >= 400:
            record["severity"] = "warning"
        return record

    match = ISO_RE.match(line)
    if match:
        record["timestamp"] = match.group("timestamp")
        record["message"] = match.group("message")
        record["severity"] = extract_severity(record["message"])
        return record

    record["severity"] = extract_severity(line)
    return record


class LogCollector:
    def __init__(self, output_file=None, json_output=True):
        self.output_file = output_file
        self.json_output = json_output
        self.file_positions = {}
        self.stats = {"total": 0, "by_severity": {}, "by_source": {}}
        self._out_handle = None

    def _open_output(self):
        if self.output_file:
            self._out_handle = open(self.output_file, "a")

    def _close_output(self):
        if self._out_handle:
            self._out_handle.close()

    def emit(self, record):
        if record is None:
            return
        self.stats["total"] += 1
        sev = record.get("severity", "info")
        self.stats["by_severity"][sev] = self.stats["by_severity"].get(sev, 0) + 1
        src = record.get("source", "unknown")
        self.stats["by_source"][src] = self.stats["by_source"].get(src, 0) + 1

        if self.json_output:
            line = json.dumps(record, default=str)
        else:
            line = (f"[{record.get('timestamp', '')}] "
                    f"[{record.get('severity', '').upper():8s}] "
                    f"[{record.get('source', '')}] "
                    f"{record.get('message', '')}")

        print(line)
        if self._out_handle:
            self._out_handle.write(line + "\n")
            self._out_handle.flush()

    def collect_file(self, filepath):
        """read and parse entire file"""
        source = Path(filepath).name
        try:
            with open(filepath, "r", errors="replace") as f:
                for line in f:
                    record = parse_line(line, source)
                    self.emit(record)
            self.file_positions[filepath] = os.path.getsize(filepath)
        except (PermissionError, FileNotFoundError) as e:
            print(f"[error] {filepath}: {e}", file=sys.stderr)

    def collect_directory(self, dirpath, pattern="*.log"):
        """collect all matching log files in directory"""
        path = Path(dirpath)
        if not path.is_dir():
            print(f"[error] not a directory: {dirpath}", file=sys.stderr)
            return
        for logfile in sorted(path.glob(pattern)):
            if logfile.is_file():
                self.collect_file(str(logfile))

    def tail_files(self, filepaths):
        """tail multiple files for new entries"""
        for fp in filepaths:
            if fp not in self.file_positions:
                try:
                    self.file_positions[fp] = os.path.getsize(fp)
                except OSError:
                    self.file_positions[fp] = 0

        print(f"[logma] tailing {len(filepaths)} files", file=sys.stderr)
        try:
            while True:
                for fp in filepaths:
                    try:
                        current_size = os.path.getsize(fp)
                        last_pos = self.file_positions.get(fp, 0)

                        if current_size < last_pos:
                            last_pos = 0

                        if current_size > last_pos:
                            source = Path(fp).name
                            with open(fp, "r", errors="replace") as f:
                                f.seek(last_pos)
                                for line in f:
                                    record = parse_line(line, source)
                                    self.emit(record)
                            self.file_positions[fp] = current_size
                    except (PermissionError, FileNotFoundError):
                        continue
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    def print_stats(self):
        print(f"\n[logma] processed {self.stats['total']} records", file=sys.stderr)
        if self.stats["by_severity"]:
            print("[logma] by severity:", file=sys.stderr)
            for sev, count in sorted(self.stats["by_severity"].items()):
                print(f"  {sev}: {count}", file=sys.stderr)


def get_default_log_sources():
    """return default log file paths for the current platform"""
    system = platform.system()
    sources = []

    if system == "Linux":
        candidates = [
            "/var/log/syslog", "/var/log/messages", "/var/log/auth.log",
            "/var/log/kern.log", "/var/log/dmesg",
        ]
        for path in candidates:
            if os.path.isfile(path) and os.access(path, os.R_OK):
                sources.append(path)
    elif system == "Darwin":
        candidates = [
            "/var/log/system.log", "/var/log/install.log",
            "/var/log/wifi.log",
        ]
        for path in candidates:
            if os.path.isfile(path) and os.access(path, os.R_OK):
                sources.append(path)

    return sources


def collect_windows_events(collector, max_events=200):
    """collect recent windows event log entries via wevtutil"""
    channels = ["System", "Application", "Security"]
    for channel in channels:
        try:
            result = subprocess.run(
                ["wevtutil", "qe", channel, "/c:" + str(max_events),
                 "/rd:true", "/f:text"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                continue
            current_entry = []
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("Event["):
                    if current_entry:
                        combined = " ".join(current_entry)
                        record = parse_line(combined, f"eventlog:{channel}")
                        collector.emit(record)
                    current_entry = []
                elif line:
                    current_entry.append(line)
            if current_entry:
                combined = " ".join(current_entry)
                record = parse_line(combined, f"eventlog:{channel}")
                collector.emit(record)
        except (subprocess.TimeoutExpired, OSError):
            print(f"[error] failed to read {channel} event log",
                  file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="centralized log collector")
    parser.add_argument("-f", "--file", action="append", help="log file (repeatable)")
    parser.add_argument("-d", "--directory", help="directory of log files")
    parser.add_argument("-o", "--output", help="output file")
    parser.add_argument("--tail", action="store_true", help="tail mode (follow new entries)")
    parser.add_argument("--text", action="store_true", help="text output instead of json")
    parser.add_argument("--pattern", default="*.log", help="glob pattern for directory mode")
    args = parser.parse_args()

    files = args.file or []
    has_explicit_source = bool(files) or bool(args.directory)

    collector = LogCollector(
        output_file=args.output,
        json_output=not args.text,
    )
    collector._open_output()

    try:
        if args.directory:
            collector.collect_directory(args.directory, args.pattern)

        for fp in files:
            collector.collect_file(fp)

        # default behavior: scan system logs when no args given
        if not has_explicit_source:
            system = platform.system()
            if system == "Windows":
                print("[logma] collecting windows event logs",
                      file=sys.stderr)
                collect_windows_events(collector)
            else:
                defaults = get_default_log_sources()
                if defaults:
                    print(f"[logma] scanning {len(defaults)} system logs",
                          file=sys.stderr)
                    for fp in defaults:
                        collector.collect_file(fp)
                else:
                    log_dir = "/var/log"
                    if os.path.isdir(log_dir):
                        print(f"[logma] scanning {log_dir}",
                              file=sys.stderr)
                        collector.collect_directory(log_dir, "*.log")
                    else:
                        print("[logma] no readable log sources found",
                              file=sys.stderr)

        if args.tail and files:
            collector.tail_files(files)
    finally:
        collector.print_stats()
        collector._close_output()


if __name__ == "__main__":
    main()
