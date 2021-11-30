#!/usr/bin/env python3
"""ssl certificate checker with expiry warnings"""

import ssl
import socket
from datetime import datetime


def check_cert(hostname, port=443, timeout=5):
    """check ssl certificate for a hostname."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return parse_cert(cert, hostname)
    except (ssl.SSLError, socket.error, OSError) as e:
        return {"hostname": hostname, "valid": False, "error": str(e)}


def parse_cert(cert, hostname):
    """parse certificate dict into useful info."""
    not_after = cert.get("notAfter", "")
    not_before = cert.get("notBefore", "")
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        issued = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.utcnow()).days
    except ValueError:
        expiry = None
        issued = None
        days_left = -1
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    return {
        "hostname": hostname,
        "valid": True,
        "subject": subject.get("commonName", ""),
        "issuer": issuer.get("organizationName", ""),
        "expires": not_after,
        "days_left": days_left,
        "warning": days_left < 30,
        "expired": days_left < 0,
    }


def check_multiple(hostnames):
    """check certificates for multiple hosts."""
    results = []
    for host in hostnames:
        result = check_cert(host)
        results.append(result)
    return results


def format_cert_report(results):
    """format certificate check results."""
    lines = [f"ssl certificate check: {len(results)} hosts"]
    for r in results:
        status = "EXPIRED" if r.get("expired") else (
            "WARNING" if r.get("warning") else "OK"
        )
        host = r["hostname"]
        days = r.get("days_left", "?")
        lines.append(f"  [{status}] {host}: {days} days left")
    return "\n".join(lines)


if __name__ == "__main__":
    hosts = ["google.com", "github.com"]
    results = check_multiple(hosts)
    print(format_cert_report(results))
