#!/usr/bin/env python3
"""tls/ssl scanner and certificate analyzer"""

import argparse
import json
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# weak ciphers to flag
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
}

# protocol versions in order of preference
TLS_VERSIONS = [
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None),
    ("TLSv1.0", ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None),
]


def test_tls_version(host, port, version_name, version_const, timeout=5):
    """test if server supports a specific tls version"""
    if version_const is None:
        return False

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version_const
        ctx.maximum_version = version_const

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        wrapped = ctx.wrap_socket(sock, server_hostname=host)
        wrapped.connect((host, port))
        actual = wrapped.version()
        wrapped.close()
        return True
    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
        return False


def get_certificate(host, port, timeout=5):
    """get certificate details"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        wrapped = ctx.wrap_socket(sock, server_hostname=host)
        wrapped.connect((host, port))

        cert = wrapped.getpeercert()
        cipher = wrapped.cipher()
        protocol = wrapped.version()
        wrapped.close()

        if not cert:
            return {"protocol": protocol, "cipher": cipher}

        # parse cert dates
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")

        # check expiry
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.utcnow()).days
        except (ValueError, TypeError):
            days_left = None

        # extract subject and issuer
        subject = {}
        for entry in cert.get("subject", ()):
            for key, value in entry:
                subject[key] = value

        issuer = {}
        for entry in cert.get("issuer", ()):
            for key, value in entry:
                issuer[key] = value

        # subject alt names
        san = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]

        return {
            "protocol": protocol,
            "cipher": cipher[0] if cipher else None,
            "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else None,
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "days_until_expiry": days_left,
            "san": san,
            "serial": cert.get("serialNumber"),
            "version": cert.get("version"),
        }
    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"error": str(e)}


def get_supported_ciphers(host, port, timeout=5):
    """enumerate supported cipher suites"""
    supported = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # get the list of ciphers our client supports
    all_ciphers = ctx.get_ciphers()

    for cipher_info in all_ciphers:
        name = cipher_info["name"]
        try:
            test_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            test_ctx.check_hostname = False
            test_ctx.verify_mode = ssl.CERT_NONE
            test_ctx.set_ciphers(name)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            wrapped = test_ctx.wrap_socket(sock, server_hostname=host)
            wrapped.connect((host, port))
            negotiated = wrapped.cipher()
            wrapped.close()

            is_weak = any(w in name for w in WEAK_CIPHERS)
            supported.append({
                "name": name,
                "bits": cipher_info.get("alg_bits", 0),
                "protocol": cipher_info.get("protocol", ""),
                "weak": is_weak,
            })
        except (ssl.SSLError, socket.timeout, OSError):
            continue

    return supported


def analyze_security(cert_info, supported_versions, ciphers):
    """analyze tls configuration for issues"""
    issues = []

    # check protocol versions
    if supported_versions.get("TLSv1.0"):
        issues.append({
            "severity": "high",
            "issue": "tlsv1.0 supported (deprecated, vulnerable to beast/poodle)",
        })
    if supported_versions.get("TLSv1.1"):
        issues.append({
            "severity": "medium",
            "issue": "tlsv1.1 supported (deprecated since 2021)",
        })
    if not supported_versions.get("TLSv1.3"):
        issues.append({
            "severity": "low",
            "issue": "tlsv1.3 not supported (recommended for best security)",
        })

    # check certificate
    if cert_info.get("days_until_expiry") is not None:
        days = cert_info["days_until_expiry"]
        if days < 0:
            issues.append({
                "severity": "critical",
                "issue": f"certificate expired {abs(days)} days ago",
            })
        elif days < 30:
            issues.append({
                "severity": "high",
                "issue": f"certificate expires in {days} days",
            })

    # check ciphers
    weak = [c for c in ciphers if c.get("weak")]
    if weak:
        names = [c["name"] for c in weak[:3]]
        issues.append({
            "severity": "high",
            "issue": f"weak ciphers supported: {', '.join(names)}",
        })

    return issues


def scan_host(host, port, timeout=5, check_ciphers=False):
    """full tls scan of a host"""
    result = {
        "host": host,
        "port": port,
        "certificate": None,
        "supported_versions": {},
        "ciphers": [],
        "issues": [],
    }

    # get certificate
    result["certificate"] = get_certificate(host, port, timeout)

    # test protocol versions
    for name, const in TLS_VERSIONS:
        supported = test_tls_version(host, port, name, const, timeout)
        result["supported_versions"][name] = supported

    # enumerate ciphers
    if check_ciphers:
        result["ciphers"] = get_supported_ciphers(host, port, timeout)

    # analyze
    result["issues"] = analyze_security(
        result["certificate"],
        result["supported_versions"],
        result["ciphers"]
    )

    return result


def print_results(result):
    """display scan results"""
    print(f"\n{'='*60}")
    print(f"tls scan: {result['host']}:{result['port']}")
    print(f"{'='*60}")

    cert = result["certificate"]
    if cert and "error" not in cert:
        print(f"\ncertificate:")
        if cert.get("subject"):
            cn = cert["subject"].get("commonName", "n/a")
            print(f"  common name: {cn}")
        if cert.get("issuer"):
            issuer_cn = cert["issuer"].get("commonName", "n/a")
            org = cert["issuer"].get("organizationName", "")
            print(f"  issuer:      {issuer_cn} ({org})")
        if cert.get("san"):
            print(f"  san:         {', '.join(cert['san'][:5])}")
        print(f"  valid:       {cert.get('not_before', 'n/a')} - {cert.get('not_after', 'n/a')}")
        if cert.get("days_until_expiry") is not None:
            print(f"  expires in:  {cert['days_until_expiry']} days")
        print(f"  protocol:    {cert.get('protocol', 'n/a')}")
        print(f"  cipher:      {cert.get('cipher', 'n/a')}")

    print(f"\nprotocol support:")
    for name, supported in result["supported_versions"].items():
        status = "yes" if supported else "no"
        print(f"  {name}: {status}")

    if result["ciphers"]:
        print(f"\nsupported ciphers ({len(result['ciphers'])}):")
        for c in result["ciphers"]:
            weak = " [WEAK]" if c["weak"] else ""
            print(f"  {c['name']} ({c['bits']} bits){weak}")

    if result["issues"]:
        print(f"\nissues ({len(result['issues'])}):")
        for issue in result["issues"]:
            sev = issue["severity"].upper()
            print(f"  [{sev}] {issue['issue']}")
    else:
        print(f"\nno issues found")


def main():
    parser = argparse.ArgumentParser(description="tls/ssl scanner")
    parser.add_argument("host", help="target host")
    parser.add_argument("-p", "--port", type=int, default=443,
                        help="port (default: 443)")
    parser.add_argument("--ciphers", action="store_true",
                        help="enumerate all supported ciphers")
    parser.add_argument("-T", "--timeout", type=float, default=5,
                        help="timeout (default: 5)")
    parser.add_argument("-o", "--output", type=str,
                        help="save results to json")

    args = parser.parse_args()

    print(f"scanning {args.host}:{args.port}...")

    start = time.time()
    result = scan_host(args.host, args.port, args.timeout, args.ciphers)
    elapsed = time.time() - start

    print_results(result)
    print(f"\ncompleted in {elapsed:.1f}s")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"saved to {args.output}")


if __name__ == "__main__":
    main()
