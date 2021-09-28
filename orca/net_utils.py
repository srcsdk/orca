#!/usr/bin/env python3
"""network utility functions for orca modules"""

import socket
import struct


def ip_to_int(ip):
    """convert dotted ip string to integer."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(n):
    """convert integer to dotted ip string."""
    return socket.inet_ntoa(struct.pack("!I", n))


def cidr_to_range(cidr):
    """convert cidr notation to (start_ip, end_ip) tuple."""
    if "/" not in cidr:
        return cidr, cidr
    ip, prefix = cidr.split("/")
    prefix = int(prefix)
    ip_int = ip_to_int(ip)
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    network = ip_int & mask
    broadcast = network | (~mask & 0xFFFFFFFF)
    return int_to_ip(network), int_to_ip(broadcast)


def is_private_ip(ip):
    """check if ip is in private range (rfc1918)."""
    ip_int = ip_to_int(ip)
    private_ranges = [
        (ip_to_int("10.0.0.0"), ip_to_int("10.255.255.255")),
        (ip_to_int("172.16.0.0"), ip_to_int("172.31.255.255")),
        (ip_to_int("192.168.0.0"), ip_to_int("192.168.255.255")),
    ]
    return any(start <= ip_int <= end for start, end in private_ranges)


def resolve_hostname(hostname):
    """resolve hostname to ip address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def reverse_dns(ip):
    """perform reverse dns lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def check_port(host, port, timeout=2):
    """check if a specific port is open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        return result == 0
    finally:
        sock.close()


if __name__ == "__main__":
    start, end = cidr_to_range("192.168.1.0/24")
    print(f"range: {start} - {end}")
    print(f"192.168.1.1 private: {is_private_ip('192.168.1.1')}")
    print(f"8.8.8.8 private: {is_private_ip('8.8.8.8')}")
