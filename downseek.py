#!/usr/bin/env python3
"""tls configuration auditor and certificate monitoring"""

import argparse
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path


MOZILLA_MODERN = {
    "min_protocol": "TLSv1.2",
    "ciphers": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
    ],
    "curves": ["X25519", "prime256v1", "secp384r1"],
}

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT",
    "aNULL", "eNULL", "ADH", "AECDH", "DES-CBC3",
    "RC2", "SEED", "IDEA", "CAMELLIA",
]

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]


class TlsAuditor:
    def __init__(self):
        self.findings = []
        self.score = 100

    def add_finding(self, severity, category, message):
        penalties = {"critical": 25, "high": 15, "medium": 10, "low": 5, "info": 0}
        self.score = max(0, self.score - penalties.get(severity, 0))
        self.findings.append({
            "severity": severity,
            "category": category,
            "message": message,
            "timestamp": datetime.now().isoformat(),
        })

    def audit_config_file(self, config_path):
        """audit nginx or apache tls configuration"""
        path = Path(config_path)
        if not path.exists():
            self.add_finding("critical", "config", f"config file not found: {config_path}")
            return

        content = path.read_text()
        lines = content.splitlines()

        self._check_cipher_config(content)
        self._check_protocol_config(content)
        self._check_headers(content)
        self._check_stapling(content)
        self._check_session_config(content)
        self._check_key_config(content, lines)

    def _check_cipher_config(self, content):
        cipher_match = re.search(
            r'(?:ssl_ciphers|SSLCipherSuite)\s+["\']?([^;"\']+)', content, re.IGNORECASE
        )
        if not cipher_match:
            self.add_finding("high", "ciphers", "no cipher suite configuration found")
            return

        cipher_str = cipher_match.group(1)
        for weak in WEAK_CIPHERS:
            if re.search(rf'\b{re.escape(weak)}\b', cipher_str, re.IGNORECASE):
                if not re.search(rf'!{re.escape(weak)}', cipher_str, re.IGNORECASE):
                    self.add_finding("high", "ciphers", f"weak cipher enabled: {weak}")

        if re.search(r'ssl_prefer_server_ciphers\s+on|SSLHonorCipherOrder\s+on',
                      content, re.IGNORECASE):
            self.add_finding("info", "ciphers", "server cipher preference enabled")
        else:
            self.add_finding("medium", "ciphers", "server cipher preference not enabled")

    def _check_protocol_config(self, content):
        for proto in ["SSLv2", "SSLv3"]:
            if re.search(rf'\b{proto}\b', content, re.IGNORECASE):
                if not re.search(rf'-{proto}', content, re.IGNORECASE):
                    self.add_finding("critical", "protocol", f"legacy protocol enabled: {proto}")

        if re.search(r'TLSv1\.3|tls1_3', content, re.IGNORECASE):
            self.add_finding("info", "protocol", "tls 1.3 configured")

    def _check_headers(self, content):
        if re.search(r'Strict-Transport-Security|HSTS', content, re.IGNORECASE):
            hsts_match = re.search(r'max-age=(\d+)', content)
            if hsts_match:
                max_age = int(hsts_match.group(1))
                if max_age < 31536000:
                    self.add_finding("medium", "headers", f"hsts max-age too short: {max_age}s")
                else:
                    self.add_finding("info", "headers", f"hsts configured: max-age={max_age}")
        else:
            self.add_finding("high", "headers", "hsts not configured")

    def _check_stapling(self, content):
        if re.search(r'ssl_stapling\s+on|SSLUseStapling\s+on', content, re.IGNORECASE):
            self.add_finding("info", "stapling", "ocsp stapling enabled")
        else:
            self.add_finding("medium", "stapling", "ocsp stapling not configured")

    def _check_session_config(self, content):
        if re.search(r'ssl_session_tickets\s+off', content, re.IGNORECASE):
            self.add_finding("info", "session", "session tickets disabled (good for pfs)")
        elif re.search(r'ssl_session_tickets\s+on', content, re.IGNORECASE):
            self.add_finding("low", "session", "session tickets enabled (may weaken pfs)")

    def _check_key_config(self, content, lines):
        for line in lines:
            key_match = re.search(r'ssl_certificate_key\s+(\S+)', line)
            if key_match:
                key_path = key_match.group(1).strip(';')
                if os.path.exists(key_path):
                    mode = os.stat(key_path).st_mode
                    perms = oct(mode)[-3:]
                    if perms not in ("600", "400"):
                        self.add_finding("high", "keys",
                                         f"key file permissions too open: {key_path} ({perms})")

    def scan_host(self, host, port=443):
        """scan remote host tls configuration"""
        self._test_certificate(host, port)
        self._test_protocols(host, port)
        self._test_cipher_strength(host, port)

    def _test_certificate(self, host, port):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    self._analyze_cert(cert, host)
                    cipher = ssock.cipher()
                    if cipher:
                        self.add_finding("info", "negotiated",
                                         f"cipher: {cipher[0]}, protocol: {cipher[1]}")
        except ssl.SSLCertVerificationError as e:
            self.add_finding("critical", "certificate", f"cert verification failed: {e}")
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            self.add_finding("critical", "connection", f"cannot connect to {host}:{port}: {e}")

    def _analyze_cert(self, cert, host):
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.utcnow()).days

        if days_left < 0:
            self.add_finding("critical", "certificate",
                             f"certificate expired {abs(days_left)} days ago")
        elif days_left < 14:
            self.add_finding("critical", "certificate",
                             f"certificate expires in {days_left} days")
        elif days_left < 30:
            self.add_finding("high", "certificate",
                             f"certificate expires in {days_left} days")
        elif days_left < 90:
            self.add_finding("medium", "certificate",
                             f"certificate expires in {days_left} days")
        else:
            self.add_finding("info", "certificate",
                             f"certificate valid for {days_left} days")

        subject = dict(x[0] for x in cert.get("subject", ()))
        cn = subject.get("commonName", "")
        sans = []
        for ext_type, ext_val in cert.get("subjectAltName", ()):
            if ext_type == "DNS":
                sans.append(ext_val)

        if host not in sans and not any(
            self._match_wildcard(host, san) for san in sans
        ):
            if cn != host and not self._match_wildcard(host, cn):
                self.add_finding("high", "certificate",
                                 f"hostname mismatch: {host} not in {sans}")

        issuer = dict(x[0] for x in cert.get("issuer", ()))
        self.add_finding("info", "certificate",
                         f"issuer: {issuer.get('organizationName', 'unknown')}")

    def _match_wildcard(self, hostname, pattern):
        if pattern.startswith("*."):
            suffix = pattern[2:]
            parts = hostname.split(".", 1)
            return len(parts) == 2 and parts[1] == suffix
        return hostname == pattern

    def _test_protocols(self, host, port):
        import warnings
        protocol_map = {
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            if hasattr(ssl.TLSVersion, "TLSv1"):
                protocol_map["TLSv1"] = ssl.TLSVersion.TLSv1
            if hasattr(ssl.TLSVersion, "TLSv1_1"):
                protocol_map["TLSv1.1"] = ssl.TLSVersion.TLSv1_1

        for name, version in protocol_map.items():
            supported = self._test_protocol_version(host, port, version)
            if name in WEAK_PROTOCOLS and supported:
                self.add_finding("high", "protocol", f"{name} is supported (insecure)")
            elif name not in WEAK_PROTOCOLS and supported:
                self.add_finding("info", "protocol", f"{name} is supported")
            elif name not in WEAK_PROTOCOLS and not supported:
                self.add_finding("medium", "protocol", f"{name} is not supported")

    def _test_protocol_version(self, host, port, version):
        import warnings
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = version
                ctx.maximum_version = version
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
        except (ssl.SSLError, OSError):
            return False

    def _test_cipher_strength(self, host, port):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher_name, proto, bits = ssock.cipher()
                    if bits < 128:
                        self.add_finding("critical", "cipher", f"weak key length: {bits} bits")
                    elif bits < 256:
                        self.add_finding("info", "cipher", f"key length: {bits} bits")
                    else:
                        self.add_finding("info", "cipher", f"strong key length: {bits} bits")
        except (ssl.SSLError, OSError):
            pass

    def check_mozilla_compliance(self, host, port=443):
        """check against mozilla modern compatibility"""
        for cipher in MOZILLA_MODERN["ciphers"]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_ciphers(cipher)
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        self.add_finding("info", "mozilla",
                                         f"supports recommended cipher: {cipher}")
            except (ssl.SSLError, OSError, ValueError):
                pass

    def get_report(self):
        grade = "A+" if self.score >= 95 else \
                "A" if self.score >= 90 else \
                "B" if self.score >= 80 else \
                "C" if self.score >= 70 else \
                "D" if self.score >= 60 else "F"

        return {
            "score": self.score,
            "grade": grade,
            "findings": self.findings,
            "summary": {
                "critical": sum(1 for f in self.findings if f["severity"] == "critical"),
                "high": sum(1 for f in self.findings if f["severity"] == "high"),
                "medium": sum(1 for f in self.findings if f["severity"] == "medium"),
                "low": sum(1 for f in self.findings if f["severity"] == "low"),
                "info": sum(1 for f in self.findings if f["severity"] == "info"),
            },
        }


def print_report(report, as_json=False):
    if as_json:
        print(json.dumps(report, indent=2))
        return

    print(f"\nscore: {report['score']}/100 (grade: {report['grade']})")
    print(f"findings: {report['summary']}")
    print()
    for f in report["findings"]:
        severity = f["severity"].upper().ljust(8)
        print(f"  [{severity}] [{f['category']}] {f['message']}")


def _detect_tls_configs():
    """find tls config files based on platform"""
    os_name = platform.system()
    candidates = []
    if os_name == "Linux":
        candidates = [
            "/etc/nginx/nginx.conf",
            "/etc/nginx/conf.d/default.conf",
            "/etc/nginx/sites-enabled/default",
            "/etc/apache2/sites-enabled/default-ssl.conf",
            "/etc/httpd/conf.d/ssl.conf",
        ]
    elif os_name == "Darwin":
        candidates = [
            "/usr/local/etc/nginx/nginx.conf",
            "/opt/homebrew/etc/nginx/nginx.conf",
            "/etc/apache2/extra/httpd-ssl.conf",
        ]
    elif os_name == "Windows":
        candidates = [
            os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"),
                         "nginx", "conf", "nginx.conf"),
        ]
    return [c for c in candidates if os.path.isfile(c)]


def _default_scan():
    """scan localhost tls and any detected config files"""
    os_name = platform.system()
    print(f"[downseek] tls auditor")
    print(f"[downseek] platform: {os_name} {platform.release()}")
    print()

    auditor = TlsAuditor()

    configs = _detect_tls_configs()
    if configs:
        for config in configs:
            print(f"[downseek] auditing config: {config}")
            auditor.audit_config_file(config)

    print("[downseek] scanning localhost:443...")
    auditor.scan_host("localhost", 443)

    report = auditor.get_report()
    print_report(report)


def main():
    parser = argparse.ArgumentParser(description="tls configuration auditor")
    parser.add_argument("-t", "--target", help="target host to scan")
    parser.add_argument("-p", "--port", type=int, default=443, help="target port")
    parser.add_argument("-c", "--config", help="config file to audit")
    parser.add_argument("--mozilla", action="store_true", help="check mozilla compliance")
    parser.add_argument("--json", action="store_true", help="json output")
    args = parser.parse_args()

    if not args.target and not args.config:
        _default_scan()
        return

    auditor = TlsAuditor()

    if args.config:
        auditor.audit_config_file(args.config)

    if args.target:
        auditor.scan_host(args.target, args.port)
        if args.mozilla:
            auditor.check_mozilla_compliance(args.target, args.port)

    report = auditor.get_report()
    print_report(report, args.json)


if __name__ == "__main__":
    main()
