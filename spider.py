#!/usr/bin/env python3
__version__ = "1.1.0"
"""web application scanner and fuzzer"""

import argparse
import json
import os
import platform
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from html.parser import HTMLParser


class LinkParser(HTMLParser):
    """extract links and forms from html"""

    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.forms = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and "href" in attrs:
            url = urllib.parse.urljoin(self.base_url, attrs["href"])
            self.links.add(url)
        elif tag == "form":
            self._current_form = {
                "action": urllib.parse.urljoin(
                    self.base_url, attrs.get("action", "")
                ),
                "method": attrs.get("method", "get").upper(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attrs.get("name", ""),
                "type": attrs.get("type", "text"),
                "value": attrs.get("value", ""),
            })

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class VulnScanner:
    """test for common web vulnerabilities"""

    XSS_PATTERNS = [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        "'-alert(1)-'",
    ]

    SQLI_PATTERNS = [
        "' OR '1'='1",
        "1 UNION SELECT NULL--",
        "' AND 1=1--",
        "1; DROP TABLE users--",
        "' OR 1=1#",
    ]

    SQLI_ERRORS = [
        "sql syntax", "mysql_fetch", "sqlite3", "pg_query",
        "unclosed quotation", "syntax error", "odbc",
        "microsoft ole db", "ora-01756",
    ]

    XSS_REFLECTION = [
        "<script>", "onerror=", "javascript:", "alert(1)",
    ]

    def test_xss(self, url, param_name):
        """test a parameter for reflected xss"""
        findings = []
        for payload in self.XSS_PATTERNS:
            test_url = self._inject_param(url, param_name, payload)
            try:
                response = self._fetch(test_url)
                if response and any(p in response for p in self.XSS_REFLECTION):
                    findings.append({
                        "type": "xss",
                        "url": url,
                        "param": param_name,
                        "payload": payload,
                    })
                    break
            except Exception:
                continue
        return findings

    def test_sqli(self, url, param_name):
        """test a parameter for sql injection"""
        findings = []
        for payload in self.SQLI_PATTERNS:
            test_url = self._inject_param(url, param_name, payload)
            try:
                response = self._fetch(test_url)
                if response:
                    lower = response.lower()
                    for error in self.SQLI_ERRORS:
                        if error in lower:
                            findings.append({
                                "type": "sqli",
                                "url": url,
                                "param": param_name,
                                "payload": payload,
                                "indicator": error,
                            })
                            break
                    if findings:
                        break
            except Exception:
                continue
        return findings

    def _inject_param(self, url, param, value):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _fetch(self, url, timeout=5):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "spider/1.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="ignore")
        except (urllib.error.URLError, OSError):
            return None


class WebSpider:
    """crawl and scan web applications"""

    COMMON_PATHS = [
        "admin", "login", "wp-admin", "wp-login.php", "administrator",
        ".env", ".git/config", "robots.txt", "sitemap.xml",
        "api", "api/v1", "swagger.json", "graphql",
        "phpmyadmin", "server-status", "server-info",
        "backup.zip", "dump.sql", "config.php",
        ".DS_Store", "web.config", "crossdomain.xml",
        "console", "dashboard", "debug", "trace",
    ]

    def __init__(self, target, max_depth=3, timeout=5, delay=0.1):
        self.target = target.rstrip("/")
        self.max_depth = max_depth
        self.timeout = timeout
        self.delay = delay
        self.visited = set()
        self.found = []
        self.forms = []
        self.scanner = VulnScanner()
        self.findings = []
        parsed = urllib.parse.urlparse(self.target)
        self.target_domain = parsed.netloc

    def fetch(self, url):
        """fetch a url and return status code, headers, body"""
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "spider/1.0"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as e:
            return e.code, {}, ""
        except (urllib.error.URLError, OSError):
            return 0, {}, ""

    def is_same_domain(self, url):
        """check if url belongs to target domain"""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc == self.target_domain

    def enumerate_dirs(self):
        """check common paths"""
        results = []
        for path in self.COMMON_PATHS:
            url = f"{self.target}/{path}"
            status, headers, _ = self.fetch(url)
            if status in (200, 301, 302, 403):
                result = {"url": url, "status": status}
                results.append(result)
                print(f"  [{status}] /{path}")
            time.sleep(self.delay)
        return results

    def crawl(self, url=None, depth=0):
        """recursively crawl links"""
        if url is None:
            url = self.target
        if depth > self.max_depth or url in self.visited:
            return
        if not self.is_same_domain(url):
            return

        self.visited.add(url)
        status, headers, body = self.fetch(url)
        if status == 0 or not body:
            return

        self.found.append({"url": url, "status": status})

        parser = LinkParser(url)
        try:
            parser.feed(body)
        except Exception:
            return

        for form in parser.forms:
            self.forms.append(form)

        # extract parameters from urls for testing
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        for param in params:
            self.findings.extend(self.scanner.test_xss(url, param))
            self.findings.extend(self.scanner.test_sqli(url, param))

        for link in parser.links:
            if link not in self.visited:
                time.sleep(self.delay)
                self.crawl(link, depth + 1)

    def scan_forms(self):
        """test discovered forms for vulnerabilities"""
        for form in self.forms:
            for inp in form["inputs"]:
                if inp["name"] and inp["type"] not in ("hidden", "submit"):
                    url = form["action"]
                    self.findings.extend(
                        self.scanner.test_xss(url, inp["name"])
                    )
                    self.findings.extend(
                        self.scanner.test_sqli(url, inp["name"])
                    )

    def report(self):
        """generate scan report"""
        return {
            "target": self.target,
            "pages_crawled": len(self.visited),
            "forms_found": len(self.forms),
            "findings": self.findings,
            "directory_results": self.found,
        }


def print_usage_demo():
    """show usage information with example commands"""
    print("web application scanner and fuzzer")
    print()
    print("usage examples:")
    print(f"  {sys.argv[0]} http://localhost")
    print(f"  {sys.argv[0]} http://localhost:8080 -d 2")
    print(f"  {sys.argv[0]} http://target.local --dirs-only")
    print(f"  {sys.argv[0]} http://target.local --no-fuzz -o report.json")
    print()
    print("features:")
    print("  - directory enumeration (common paths)")
    print("  - recursive link crawling with depth control")
    print("  - form discovery and parameter extraction")
    print("  - xss and sql injection testing")
    print()
    os_name = platform.system()
    print(f"platform: {os_name}")
    print(f"uses urllib (cross-platform, no external dependencies)")


def main():
    parser = argparse.ArgumentParser(description="web application scanner")
    parser.add_argument("url", nargs="?", default=None,
                        help="target url (default: show usage)")
    parser.add_argument("-d", "--depth", type=int, default=3,
                        help="max crawl depth (default: 3)")
    parser.add_argument("--dirs-only", action="store_true",
                        help="only enumerate directories")
    parser.add_argument("--no-fuzz", action="store_true",
                        help="skip vulnerability testing")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="delay between requests in seconds")
    parser.add_argument("-t", "--timeout", type=int, default=5,
                        help="request timeout")
    parser.add_argument("-o", "--output", help="save report to json file")
    args = parser.parse_args()

    if args.url is None:
        print_usage_demo()
        sys.exit(0)

    spider = WebSpider(
        args.url, max_depth=args.depth,
        timeout=args.timeout, delay=args.delay
    )

    print(f"target: {args.url}")
    print()

    print("directory enumeration:")
    dir_results = spider.enumerate_dirs()
    print(f"found {len(dir_results)} accessible paths")
    print()

    if not args.dirs_only:
        print("crawling...")
        spider.crawl()
        print(f"crawled {len(spider.visited)} pages, "
              f"found {len(spider.forms)} forms")
        print()

        if not args.no_fuzz and spider.forms:
            print("testing forms for vulnerabilities...")
            spider.scan_forms()

        if spider.findings:
            print(f"\nfindings ({len(spider.findings)}):")
            for f in spider.findings:
                print(f"  [{f['type'].upper()}] {f['url']} "
                      f"param={f['param']}")
        else:
            print("no vulnerabilities detected")

    if args.output:
        report = spider.report()
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nreport saved to {args.output}")


if __name__ == "__main__":
    main()
