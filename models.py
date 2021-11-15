#!/usr/bin/env python3
"""data models for orcasec platform"""

import json
import time
from dataclasses import dataclass, field, asdict


@dataclass
class Port:
    """network port with service information"""
    number: int
    protocol: str = "tcp"
    state: str = "unknown"
    service: str = ""
    banner: str = ""
    version: str = ""

    def __str__(self):
        svc = f" ({self.service})" if self.service else ""
        return f"{self.number}/{self.protocol} {self.state}{svc}"

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class Host:
    """discovered network host"""
    ip: str
    mac: str = ""
    hostname: str = ""
    os_guess: str = ""
    ports: list = field(default_factory=list)
    last_seen: float = 0.0
    alive: bool = True

    def __post_init__(self):
        if not self.last_seen:
            self.last_seen = time.time()

    def __str__(self):
        name = self.hostname or self.ip
        port_count = len(self.ports)
        return f"{name} ({self.ip}) - {port_count} ports"

    def open_ports(self):
        """return list of open ports"""
        return [p for p in self.ports if isinstance(p, Port) and p.state == "open"]

    def to_dict(self):
        d = asdict(self)
        d["ports"] = [p.to_dict() if isinstance(p, Port) else p for p in self.ports]
        return d

    @classmethod
    def from_dict(cls, data):
        data = dict(data)
        if "ports" in data:
            data["ports"] = [Port.from_dict(p) if isinstance(p, dict) else p
                             for p in data["ports"]]
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class Vulnerability:
    """security vulnerability finding"""
    cve_id: str = ""
    severity: str = "unknown"
    description: str = ""
    affected_host: str = ""
    affected_port: int = 0
    affected_service: str = ""
    cvss_score: float = 0.0
    references: list = field(default_factory=list)
    remediation: str = ""

    def __str__(self):
        return f"[{self.severity.upper()}] {self.cve_id}: {self.description[:80]}"

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class Alert:
    """security alert from monitoring or detection"""
    timestamp: float = 0.0
    source: str = ""
    severity: str = "info"
    message: str = ""
    details: dict = field(default_factory=dict)
    acknowledged: bool = False

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = time.time()

    def __str__(self):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        return f"[{ts}] [{self.severity.upper()}] {self.source}: {self.message}"

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ScanResult:
    """complete scan result container"""
    target: str = ""
    scan_type: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    hosts: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)
    alerts: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.start_time:
            self.start_time = time.time()

    def duration(self):
        """scan duration in seconds"""
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time

    def finish(self):
        """mark scan as complete"""
        self.end_time = time.time()
        return self

    def host_count(self):
        return len(self.hosts)

    def vuln_count(self):
        return len(self.vulnerabilities)

    def summary(self):
        """brief text summary"""
        dur = f"{self.duration():.1f}s"
        return (f"scan of {self.target}: {self.host_count()} hosts, "
                f"{self.vuln_count()} vulnerabilities in {dur}")

    def to_dict(self):
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration(),
            "hosts": [h.to_dict() if isinstance(h, Host) else h for h in self.hosts],
            "vulnerabilities": [v.to_dict() if isinstance(v, Vulnerability) else v
                                for v in self.vulnerabilities],
            "alerts": [a.to_dict() if isinstance(a, Alert) else a for a in self.alerts],
            "metadata": self.metadata,
        }

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data):
        data = dict(data)
        if "hosts" in data:
            data["hosts"] = [Host.from_dict(h) if isinstance(h, dict) else h
                             for h in data["hosts"]]
        if "vulnerabilities" in data:
            data["vulnerabilities"] = [Vulnerability.from_dict(v) if isinstance(v, dict) else v
                                       for v in data["vulnerabilities"]]
        if "alerts" in data:
            data["alerts"] = [Alert.from_dict(a) if isinstance(a, dict) else a
                              for a in data["alerts"]]
        valid = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**valid)


def main():
    """demonstrate data models"""
    host = Host(ip="192.168.1.1", hostname="gateway",
                ports=[Port(80, state="open", service="http"),
                       Port(443, state="open", service="https")])
    vuln = Vulnerability(cve_id="CVE-2024-1234", severity="high",
                         description="remote code execution via crafted request",
                         affected_host="192.168.1.1", affected_port=80)
    result = ScanResult(target="192.168.1.0/24", scan_type="full")
    result.hosts.append(host)
    result.vulnerabilities.append(vuln)
    result.finish()
    print(result.summary())
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()


def severity_summary(vulnerabilities):
    """count vulnerabilities by severity level"""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulnerabilities:
        sev = v.severity.lower() if hasattr(v, 'severity') else v.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["info"] += 1
    return counts


def deduplicate_alerts(alerts):
    """remove duplicate alerts based on source and message"""
    seen = set()
    unique = []
    for alert in alerts:
        key = (alert.source, alert.message) if hasattr(alert, 'source') else (alert.get("source"), alert.get("message"))
        if key not in seen:
            seen.add(key)
            unique.append(alert)
    return unique
