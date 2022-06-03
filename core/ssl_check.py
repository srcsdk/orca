#!/usr/bin/env python3
"""ssl certificate validation and monitoring"""

import ssl
import socket
import datetime


def check_certificate(hostname, port=443, timeout=5):
    """check ssl certificate for a hostname."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection(
            (hostname, port), timeout=timeout
        ) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return _parse_cert(cert, hostname)
    except (ssl.SSLError, socket.error, OSError) as e:
        return {"hostname": hostname, "valid": False, "error": str(e)}


def _parse_cert(cert, hostname):
    """parse certificate details."""
    not_after = cert.get("notAfter", "")
    not_before = cert.get("notBefore", "")
    try:
        expiry = datetime.datetime.strptime(
            not_after, "%b %d %H:%M:%S %Y %Z"
        )
        days_left = (expiry - datetime.datetime.utcnow()).days
    except (ValueError, TypeError):
        expiry = None
        days_left = -1
    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    return {
        "hostname": hostname,
        "valid": True,
        "subject": subject.get("commonName", ""),
        "issuer": issuer.get("organizationName", ""),
        "expires": not_after,
        "days_until_expiry": days_left,
        "serial": cert.get("serialNumber", ""),
        "version": cert.get("version", 0),
    }


def check_expiry_warning(cert_info, warn_days=30):
    """check if certificate is expiring soon."""
    days = cert_info.get("days_until_expiry", -1)
    if days < 0:
        return "expired"
    elif days <= warn_days:
        return f"expiring in {days} days"
    return "ok"


def check_multiple(hostnames, port=443):
    """check certificates for multiple hostnames."""
    results = []
    for hostname in hostnames:
        info = check_certificate(hostname, port)
        info["status"] = check_expiry_warning(info)
        results.append(info)
    return results


def format_cert_report(results):
    """format certificate check results."""
    lines = ["ssl certificate report:"]
    for r in results:
        status = r.get("status", "unknown")
        hostname = r.get("hostname", "")
        if r.get("valid"):
            days = r.get("days_until_expiry", -1)
            lines.append(
                f"  {hostname}: {status} "
                f"(expires in {days} days, issuer: {r.get('issuer', '')})"
            )
        else:
            lines.append(f"  {hostname}: INVALID - {r.get('error', '')}")
    return "\n".join(lines)


if __name__ == "__main__":
    print("ssl checker initialized")
    print("usage: check_certificate('example.com')")
    print("supported: single host, multiple hosts, expiry warnings")
