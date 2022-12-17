#!/usr/bin/env python3
"""shared data models for orca security platform"""

import time


class Host:
    """represents a discovered network host."""

    def __init__(self, ip, mac=None, hostname=None):
        self.ip = ip
        self.mac = mac
        self.hostname = hostname
        self.os_guess = None
        self.ports = []
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.tags = []

    def add_port(self, port, protocol="tcp", state="open", service=None):
        """add a discovered port."""
        self.ports.append({
            "port": port,
            "protocol": protocol,
            "state": state,
            "service": service,
        })

    def to_dict(self):
        """convert to dictionary."""
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "os_guess": self.os_guess,
            "ports": self.ports,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tags": self.tags,
        }


class Alert:
    """represents a security alert."""

    def __init__(self, module, severity, title, detail=None):
        self.module = module
        self.severity = severity
        self.title = title
        self.detail = detail
        self.timestamp = time.time()
        self.status = "new"
        self.attck_id = None
        self.source_ip = None
        self.dest_ip = None

    def acknowledge(self):
        """mark alert as acknowledged."""
        self.status = "acknowledged"

    def resolve(self, resolution=""):
        """mark alert as resolved."""
        self.status = "resolved"
        self.resolution = resolution

    def to_dict(self):
        """convert to dictionary."""
        return {
            "module": self.module,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "timestamp": self.timestamp,
            "status": self.status,
            "attck_id": self.attck_id,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
        }


class Flow:
    """represents a network flow."""

    def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol="tcp"):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.packets = 0
        self.bytes_count = 0
        self.start_time = time.time()
        self.end_time = None
        self.label = "unknown"

    def update(self, packets=1, byte_count=0):
        """update flow counters."""
        self.packets += packets
        self.bytes_count += byte_count
        self.end_time = time.time()

    def duration(self):
        """get flow duration in seconds."""
        end = self.end_time or time.time()
        return round(end - self.start_time, 2)

    def to_dict(self):
        """convert to dictionary."""
        return {
            "src": f"{self.src_ip}:{self.src_port}",
            "dst": f"{self.dst_ip}:{self.dst_port}",
            "protocol": self.protocol,
            "packets": self.packets,
            "bytes": self.bytes_count,
            "duration": self.duration(),
            "label": self.label,
        }


class ScanResult:
    """represents a scan result with hosts and findings."""

    def __init__(self, scan_type, target):
        self.scan_type = scan_type
        self.target = target
        self.hosts = []
        self.start_time = time.time()
        self.end_time = None

    def add_host(self, host):
        """add a discovered host."""
        self.hosts.append(host)

    def finish(self):
        """mark scan as complete."""
        self.end_time = time.time()

    def summary(self):
        """get scan summary."""
        total_ports = sum(len(h.ports) for h in self.hosts)
        return {
            "type": self.scan_type,
            "target": self.target,
            "hosts": len(self.hosts),
            "ports": total_ports,
            "duration": round(
                (self.end_time or time.time()) - self.start_time, 2
            ),
        }


if __name__ == "__main__":
    host = Host("192.168.1.1", hostname="router")
    host.add_port(22, service="ssh")
    host.add_port(80, service="http")
    print(f"host: {host.ip} ({len(host.ports)} ports)")

    alert = Alert("port_scanner", "HIGH", "new host detected")
    print(f"alert: [{alert.severity}] {alert.title}")
