#!/usr/bin/env python3
"""network topology mapping and device discovery"""

import socket
import subprocess
import re


def get_local_ip():
    """get local ip address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except socket.error:
        return "127.0.0.1"


def get_subnet():
    """determine local subnet."""
    ip = get_local_ip()
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def arp_scan():
    """discover devices on local network using arp table."""
    try:
        output = subprocess.check_output(
            ["arp", "-a"], stderr=subprocess.DEVNULL, text=True,
        )
        devices = []
        for line in output.splitlines():
            match = re.search(
                r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)", line
            )
            if match:
                devices.append({
                    "ip": match.group(1),
                    "mac": match.group(2),
                })
        return devices
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def resolve_hostname(ip):
    """resolve ip to hostname."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return ""


def ping_host(ip, timeout=1):
    """check if host is reachable."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def build_network_map():
    """build map of local network."""
    local_ip = get_local_ip()
    subnet = get_subnet()
    devices = arp_scan()
    network = {
        "local_ip": local_ip,
        "subnet": subnet,
        "devices": [],
    }
    for device in devices:
        hostname = resolve_hostname(device["ip"])
        device["hostname"] = hostname
        device["is_self"] = device["ip"] == local_ip
        network["devices"].append(device)
    return network


def format_network_map(network):
    """format network map for display."""
    lines = [
        f"local network: {network['subnet']}",
        f"local ip: {network['local_ip']}",
        f"devices found: {len(network['devices'])}",
        "",
    ]
    for device in network["devices"]:
        name = device.get("hostname", "") or "unknown"
        marker = " (self)" if device.get("is_self") else ""
        lines.append(
            f"  {device['ip']:>15}  {device['mac']:>17}  "
            f"{name}{marker}"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    ip = get_local_ip()
    subnet = get_subnet()
    print(f"local ip: {ip}")
    print(f"subnet: {subnet}")
    devices = arp_scan()
    print(f"arp devices: {len(devices)}")
    for d in devices[:5]:
        print(f"  {d['ip']} - {d['mac']}")
