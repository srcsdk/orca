#!/usr/bin/env python3
__version__ = "1.1.0"
"""service fingerprinting and banner grabbing"""

import argparse
import json
import platform
import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# protocol-specific probes
PROBES = {
    "http": b"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    "https": b"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
    "smtp": None,  # smtp sends banner on connect
    "ftp": None,
    "ssh": None,
    "pop3": None,
    "imap": None,
}

# ports to probe type mapping
PORT_PROBES = {
    21: "ftp", 22: "ssh", 25: "smtp", 80: "http", 110: "pop3",
    143: "imap", 443: "https", 465: "smtp", 587: "smtp",
    993: "imap", 995: "pop3", 8080: "http", 8443: "https",
}


def grab_banner(host, port, timeout=3):
    """connect to a port and grab the banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # try to receive immediate banner
        sock.settimeout(2)
        try:
            data = sock.recv(1024)
            if data:
                sock.close()
                return data.decode("utf-8", errors="replace").strip()
        except socket.timeout:
            pass

        # send probe if we know the protocol
        probe_type = PORT_PROBES.get(port)
        if probe_type and probe_type in PROBES:
            probe = PROBES[probe_type]
            if probe:
                probe = probe.replace(b"{host}", host.encode())
                sock.sendall(probe)
                data = sock.recv(4096)
                sock.close()
                return data.decode("utf-8", errors="replace").strip()

        sock.close()
        return None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def get_ssl_info(host, port, timeout=3):
    """get ssl certificate details"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        wrapped = context.wrap_socket(sock, server_hostname=host)
        wrapped.connect((host, port))

        cert = wrapped.getpeercert(binary_form=False)
        cipher = wrapped.cipher()
        version = wrapped.version()
        wrapped.close()

        if not cert:
            # get cert info from binary form
            wrapped.getpeercert(binary_form=True)
            return {
                "tls_version": version,
                "cipher": cipher[0] if cipher else None,
            }

        return {
            "tls_version": version,
            "cipher": cipher[0] if cipher else None,
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [
                v for t, v in cert.get("subjectAltName", [])
                if t == "DNS"
            ],
        }
    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
        return None


def parse_banner(banner):
    """extract version info from banner"""
    if not banner:
        return None

    patterns = [
        (r"SSH-[\d.]+-(\S+)", "ssh"),
        (r"Server:\s*(.+)", "http_server"),
        (r"Apache/([\d.]+)", "apache"),
        (r"nginx/([\d.]+)", "nginx"),
        (r"OpenSSH_([\d.p]+)", "openssh"),
        (r"220.*?([\w.-]+\s+FTP)", "ftp"),
        (r"220.*?ESMTP\s+(\S+)", "smtp"),
        (r"ProFTPD\s+([\d.]+)", "proftpd"),
        (r"vsftpd\s+([\d.]+)", "vsftpd"),
    ]

    for pattern, name in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return {"product": name, "version": match.group(1)}

    return {"product": "unknown", "version": banner[:60]}


def analyze_http_headers(host, port=80, timeout=3):
    """check http response headers for security misconfigurations"""
    security_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "x-xss-protection",
        "referrer-policy",
    ]
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())
        response = sock.recv(4096).decode("utf-8", errors="replace")
        sock.close()

        headers = {}
        for line in response.split("\r\n")[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        missing = []
        present = []
        for h in security_headers:
            if h in headers:
                present.append(h)
            else:
                missing.append(h)

        return {
            "headers": headers,
            "security_present": present,
            "security_missing": missing,
        }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def fingerprint(host, port, timeout=3):
    """full fingerprint of a service"""
    result = {
        "port": port,
        "service": socket.getservbyport(port, "tcp") if port < 49152 else "unknown",
        "banner": None,
        "version": None,
        "ssl": None,
    }

    try:
        result["service"] = socket.getservbyport(port, "tcp")
    except OSError:
        result["service"] = "unknown"

    banner = grab_banner(host, port, timeout)
    if banner:
        result["banner"] = banner[:200]
        result["version"] = parse_banner(banner)

    if port in (443, 8443, 993, 995, 465):
        result["ssl"] = get_ssl_info(host, port, timeout)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="service fingerprinting and banner grabbing"
    )
    parser.add_argument("host", nargs="?", default=None,
                        help="target host (default: localhost)")
    parser.add_argument("-p", "--ports", type=str, default=None,
                        help="ports to scan (comma-separated or range)")
    parser.add_argument("-t", "--threads", type=int, default=20,
                        help="threads (default: 20)")
    parser.add_argument("-T", "--timeout", type=float, default=3,
                        help="timeout (default: 3)")
    parser.add_argument("-o", "--output", type=str,
                        help="save results to json")
    parser.add_argument("--headers", action="store_true",
                        help="analyze http security headers")

    args = parser.parse_args()

    # default to localhost common ports when no args given
    if args.host is None:
        args.host = "127.0.0.1"
        print("no target specified, scanning localhost common ports")
    if args.ports is None:
        args.ports = "21,22,25,80,443"

    # reduce threads on windows
    if platform.system() == "Windows":
        args.threads = min(args.threads, 15)

    # parse port specification
    ports = []
    for part in args.ports.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"could not resolve {args.host}", file=sys.stderr)
        sys.exit(1)

    print(f"fingerprinting {args.host} ({ip}) - {len(ports)} ports\n")

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(fingerprint, ip, p, args.timeout): p
            for p in ports
        }
        for future in as_completed(futures):
            result = future.result()
            if result["banner"] or result["ssl"]:
                results.append(result)

    results.sort(key=lambda r: r["port"])

    for r in results:
        print(f"{r['port']}/tcp  {r['service']}")
        if r["version"]:
            print(f"  version: {r['version']}")
        if r["banner"]:
            print(f"  banner:  {r['banner'][:80]}")
        if r["ssl"]:
            s = r["ssl"]
            print(f"  tls:     {s.get('tls_version')} {s.get('cipher', '')}")
            if s.get("subject"):
                print(f"  cn:      {s['subject'].get('commonName', '')}")
        print()

    if args.headers:
        for port in [80, 8080, 443, 8443]:
            if port in [int(p) for p in args.ports.split(",") if p.strip().isdigit()]:
                analysis = analyze_http_headers(ip, port, args.timeout)
                if analysis:
                    print(f"http header analysis ({port}):")
                    if analysis["security_present"]:
                        print(f"  present: {', '.join(analysis['security_present'])}")
                    if analysis["security_missing"]:
                        print(f"  missing: {', '.join(analysis['security_missing'])}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"saved to {args.output}")


if __name__ == "__main__":
    main()


SERVICE_SIGNATURES = {
    b"SSH-": "ssh",
    b"220 ": "ftp/smtp",
    b"HTTP/": "http",
    b"+OK": "pop3",
    b"* OK": "imap",
    b"MySQL": "mysql",
    b"PostgreSQL": "postgresql",
}


def identify_service(banner):
    """identify service from banner using known signatures"""
    if not banner:
        return "unknown"
    for sig, name in SERVICE_SIGNATURES.items():
        if banner.startswith(sig):
            return name
    return "unknown"
