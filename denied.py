#!/usr/bin/env python3
"""web application firewall - http request analyzer"""

import argparse
import json
import logging
import os
import platform
import re
import sys
import time
from collections import defaultdict
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote, parse_qs, urlparse

PLATFORM = platform.system().lower()


class WafRule:
    """single waf detection rule"""

    def __init__(self, rule_id, name, pattern, category, severity,
                 targets=None):
        self.rule_id = rule_id
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.category = category
        self.severity = severity
        self.targets = targets or ["uri", "body", "headers"]
        self.hit_count = 0

    def match(self, content):
        """check if content matches this rule"""
        if self.pattern.search(content):
            self.hit_count += 1
            return True
        return False

    def to_dict(self):
        return {
            "id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "hits": self.hit_count,
        }


class RuleEngine:
    """owasp crs-inspired rule engine"""

    def __init__(self):
        self.rules = []
        self._load_default_rules()

    def _load_default_rules(self):
        # sql injection rules
        sqli_rules = [
            (1001, "sqli_union", r"union\s+(all\s+)?select", "sqli", "critical"),
            (1002, "sqli_or_bypass", r"['\"]\s*or\s+['\"0-9]", "sqli", "critical"),
            (1003, "sqli_drop", r"drop\s+(table|database)", "sqli", "critical"),
            (1004, "sqli_insert", r"insert\s+into\s+\w+", "sqli", "high"),
            (1005, "sqli_update_set", r"update\s+\w+\s+set", "sqli", "high"),
            (1006, "sqli_comment", r"(--|#|/\*)", "sqli", "medium"),
            (1007, "sqli_benchmark", r"benchmark\s*\(", "sqli", "high"),
            (1008, "sqli_sleep", r"sleep\s*\(\s*\d+", "sqli", "high"),
            (1009, "sqli_concat", r"concat\s*\(", "sqli", "medium"),
            (1010, "sqli_hex", r"0x[0-9a-f]{8,}", "sqli", "medium"),
        ]

        # xss rules
        xss_rules = [
            (2001, "xss_script_tag", r"<\s*script[\s>]", "xss", "critical"),
            (2002, "xss_event_handler", r"on(error|load|click|mouse)\s*=", "xss", "high"),
            (2003, "xss_javascript_uri", r"javascript\s*:", "xss", "high"),
            (2004, "xss_img_tag", r"<\s*img[^>]+onerror", "xss", "high"),
            (2005, "xss_iframe", r"<\s*iframe", "xss", "high"),
            (2006, "xss_svg_onload", r"<\s*svg[^>]+onload", "xss", "high"),
            (2007, "xss_data_uri", r"data\s*:\s*text/html", "xss", "medium"),
        ]

        # path traversal rules
        traversal_rules = [
            (3001, "traversal_dotdot", r"\.\./", "traversal", "high"),
            (3002, "traversal_encoded", r"%2e%2e[%2f/]", "traversal", "high"),
            (3003, "traversal_etc", r"/etc/(passwd|shadow|hosts)", "traversal", "critical"),
            (3004, "traversal_proc", r"/proc/(self|version|cpuinfo)", "traversal", "high"),
            (3005, "traversal_null_byte", r"%00", "traversal", "critical"),
        ]

        # command injection rules
        cmdi_rules = [
            (4001, "cmdi_pipe", r"\|\s*(cat|ls|id|whoami|uname)", "cmdi", "critical"),
            (4002, "cmdi_semicolon", r";\s*(cat|ls|id|whoami|wget|curl)", "cmdi", "critical"),
            (4003, "cmdi_backtick", r"`[^`]+`", "cmdi", "high"),
            (4004, "cmdi_subshell", r"\$\([^)]+\)", "cmdi", "high"),
            (4005, "cmdi_nc_reverse", r"(nc|ncat|netcat)\s+-\w*e", "cmdi", "critical"),
        ]

        all_rules = sqli_rules + xss_rules + traversal_rules + cmdi_rules
        for rule_id, name, pattern, category, severity in all_rules:
            self.rules.append(WafRule(rule_id, name, pattern, category, severity))

    def analyze(self, request_data):
        """analyze request against all rules"""
        matches = []
        decoded = unquote(request_data)
        for rule in self.rules:
            if rule.match(decoded):
                matches.append(rule)
        return matches


class RequestAnalyzer:
    """analyze http requests for attacks"""

    def __init__(self, rule_engine=None):
        self.engine = rule_engine or RuleEngine()
        self.blocked = []
        self.allowed = 0
        self.rate_tracker = defaultdict(list)
        self.rate_limit = 100
        self.rate_window = 60

    def analyze_request(self, method, uri, headers, body="", src_ip=""):
        """analyze a complete http request"""
        findings = []

        # check uri
        uri_matches = self.engine.analyze(uri)
        findings.extend(uri_matches)

        # check body
        if body:
            body_matches = self.engine.analyze(body)
            findings.extend(body_matches)

        # check headers
        for name, value in headers.items():
            header_matches = self.engine.analyze(f"{name}: {value}")
            findings.extend(header_matches)

        # rate limiting
        if src_ip:
            now = time.time()
            self.rate_tracker[src_ip].append(now)
            cutoff = now - self.rate_window
            self.rate_tracker[src_ip] = [
                t for t in self.rate_tracker[src_ip] if t > cutoff
            ]
            if len(self.rate_tracker[src_ip]) > self.rate_limit:
                findings.append(WafRule(
                    9001, "rate_limit", ".*", "rate", "medium"
                ))

        if findings:
            max_severity = max(
                findings,
                key=lambda r: {"critical": 4, "high": 3,
                               "medium": 2, "low": 1}[r.severity]
            )
            entry = {
                "timestamp": datetime.now().isoformat(),
                "source": src_ip,
                "method": method,
                "uri": uri,
                "rules_matched": [r.to_dict() for r in findings],
                "action": "block",
                "severity": max_severity.severity,
            }
            self.blocked.append(entry)
            return False, entry

        self.allowed += 1
        return True, None

    def stats(self):
        """return waf statistics"""
        category_counts = defaultdict(int)
        for entry in self.blocked:
            for rule in entry["rules_matched"]:
                category_counts[rule["category"]] += 1
        return {
            "total_allowed": self.allowed,
            "total_blocked": len(self.blocked),
            "categories": dict(category_counts),
            "rule_stats": [r.to_dict() for r in self.engine.rules if r.hit_count > 0],
        }


def analyze_log_file(log_path, analyzer):
    """analyze an access log file"""
    log_pattern = re.compile(
        r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)'
    )
    with open(log_path) as f:
        for line in f:
            match = log_pattern.match(line)
            if not match:
                continue
            src_ip = match.group(1)
            method = match.group(3)
            uri = match.group(4)
            allowed, entry = analyzer.analyze_request(
                method, uri, {}, src_ip=src_ip
            )
            if not allowed:
                sev = entry["severity"].upper()
                rules = ", ".join(r["name"] for r in entry["rules_matched"])
                print(f"[{sev}] {src_ip} {method} {uri} -> {rules}")


def run_self_test(analyzer):
    """run waf self-test with common attack payloads"""
    print(f"web application firewall - self-test")
    print(f"platform: {PLATFORM}")
    print(f"loaded {len(analyzer.engine.rules)} rules\n")

    test_payloads = [
        ("GET", "/search?q=normal+query", "benign request"),
        ("GET", "/page?id=1' OR '1'='1", "sql injection (or bypass)"),
        ("GET", "/api?q=<script>alert(1)</script>", "xss (script tag)"),
        ("GET", "/file?path=../../../etc/passwd", "path traversal"),
        ("GET", "/cmd?exec=;cat /etc/shadow", "command injection"),
        ("GET", "/api?id=1 UNION SELECT * FROM users", "sql injection (union)"),
        ("GET", "/page?cb=javascript:alert(1)", "xss (javascript uri)"),
        ("GET", "/download?f=%2e%2e%2fetc/shadow", "encoded traversal"),
        ("POST", "/login", "benign post"),
        ("GET", "/api?q=benchmark(10000000,sha1('test'))", "sqli (benchmark)"),
    ]

    print(f"{'result':<10} {'payload':<45} {'description'}")
    print("-" * 85)

    for method, uri, desc in test_payloads:
        allowed, entry = analyzer.analyze_request(method, uri, {}, src_ip="test")
        status = "allowed" if allowed else "blocked"
        rules = ""
        if entry:
            rules = ", ".join(r["name"] for r in entry["rules_matched"][:3])
        display_uri = uri[:43] + ".." if len(uri) > 45 else uri
        print(f"{status:<10} {display_uri:<45} {desc}")
        if rules:
            print(f"{'':>10} rules: {rules}")

    print()
    stats = analyzer.stats()
    print(f"allowed: {stats['total_allowed']}")
    print(f"blocked: {stats['total_blocked']}")
    for cat, count in sorted(stats["categories"].items()):
        print(f"  {cat}: {count}")


def main():
    parser = argparse.ArgumentParser(description="web application firewall")
    parser.add_argument("-l", "--log", help="analyze access log file")
    parser.add_argument("-t", "--test", help="test a single request string")
    parser.add_argument("--rate-limit", type=int, default=100,
                        help="requests per minute per ip (default: 100)")
    parser.add_argument("-o", "--output", help="save results to json")
    parser.add_argument("--list-rules", action="store_true",
                        help="list all rules")
    args = parser.parse_args()

    analyzer = RequestAnalyzer()
    analyzer.rate_limit = args.rate_limit

    if args.list_rules:
        for rule in analyzer.engine.rules:
            print(f"[{rule.rule_id}] {rule.name} ({rule.category}) "
                  f"severity={rule.severity}")
        return

    if args.test:
        allowed, entry = analyzer.analyze_request(
            "GET", args.test, {}, src_ip="test"
        )
        if allowed:
            print("request allowed")
        else:
            print(f"request blocked:")
            for rule in entry["rules_matched"]:
                print(f"  [{rule['severity']}] {rule['name']} "
                      f"({rule['category']})")
        return

    if args.log:
        print(f"analyzing {args.log}")
        print()
        analyze_log_file(args.log, analyzer)
        print()
        stats = analyzer.stats()
        print(f"allowed: {stats['total_allowed']}")
        print(f"blocked: {stats['total_blocked']}")
        for cat, count in stats["categories"].items():
            print(f"  {cat}: {count}")
        if args.output:
            with open(args.output, "w") as f:
                json.dump({"stats": stats, "blocked": analyzer.blocked},
                          f, indent=2)
            print(f"\nsaved to {args.output}")
        return

    run_self_test(analyzer)


if __name__ == "__main__":
    main()
