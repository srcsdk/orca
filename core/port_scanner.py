#!/usr/bin/env python3
"""basic port scanning for network reconnaissance"""

import socket


COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    3306: "mysql", 3389: "rdp", 5432: "postgresql",
    6379: "redis", 8080: "http-alt", 8443: "https-alt",
    27017: "mongodb",
}


def scan_port(host, port, timeout=1.0):
    """check if a single port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except (socket.error, OSError):
        return False


def scan_ports(host, ports=None, timeout=1.0):
    """scan multiple ports on a host."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    results = []
    for port in ports:
        is_open = scan_port(host, port, timeout)
        if is_open:
            service = COMMON_PORTS.get(port, "unknown")
            results.append({
                "port": port,
                "state": "open",
                "service": service,
            })
    return results


def scan_range(host, start=1, end=1024, timeout=0.5):
    """scan a range of ports."""
    return scan_ports(host, list(range(start, end + 1)), timeout)


def grab_banner(host, port, timeout=2.0):
    """attempt to grab service banner from open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b"\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        sock.close()
        return banner
    except (socket.error, OSError):
        return ""


def format_results(host, results):
    """format scan results for display."""
    lines = [f"scan results for {host}:"]
    lines.append(f"  {len(results)} open ports found")
    for r in results:
        banner = ""
        if r.get("banner"):
            banner = f" [{r['banner'][:40]}]"
        lines.append(
            f"  {r['port']:>5}/tcp  {r['state']:<6}  "
            f"{r['service']}{banner}"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print("common ports database:")
    for port, service in sorted(COMMON_PORTS.items()):
        print(f"  {port}: {service}")
    print(f"\ntotal common ports: {len(COMMON_PORTS)}")
