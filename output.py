#!/usr/bin/env python3
"""output formatters for orcasec scan results"""

import csv
import io
import json
import os
import time

from models import ScanResult, Host, Port, Vulnerability, Alert
from utils import format_table, colorize, SEVERITY_COLORS


def json_output(result, indent=2, file=None):
    """format scan result as json"""
    data = result.to_dict() if isinstance(result, ScanResult) else result
    text = json.dumps(data, indent=indent, default=str)
    if file:
        with open(file, "w") as f:
            f.write(text)
        return file
    return text


def csv_output(result, file=None):
    """format scan result hosts and ports as csv"""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ip", "hostname", "mac", "os", "port", "protocol",
                     "state", "service", "banner"])
    hosts = result.hosts if isinstance(result, ScanResult) else result
    for host in hosts:
        if isinstance(host, Host):
            if not host.ports:
                writer.writerow([host.ip, host.hostname, host.mac, host.os_guess,
                                 "", "", "", "", ""])
            for port in host.ports:
                if isinstance(port, Port):
                    writer.writerow([host.ip, host.hostname, host.mac, host.os_guess,
                                     port.number, port.protocol, port.state,
                                     port.service, port.banner])
                else:
                    writer.writerow([host.ip, host.hostname, host.mac, host.os_guess,
                                     port, "", "", "", ""])
        elif isinstance(host, dict):
            writer.writerow([host.get("ip", ""), host.get("hostname", ""),
                             host.get("mac", ""), host.get("os_guess", ""),
                             "", "", "", "", ""])
    text = buf.getvalue()
    if file:
        with open(file, "w") as f:
            f.write(text)
        return file
    return text


def table_output(result):
    """format scan result as aligned text table"""
    lines = []
    if isinstance(result, ScanResult):
        lines.append(colorize(f"scan: {result.target} ({result.scan_type})", "bold"))
        lines.append(f"duration: {result.duration():.1f}s")
        lines.append("")
        if result.hosts:
            lines.append(colorize("hosts", "cyan"))
            headers = ["ip", "hostname", "mac", "os", "ports"]
            rows = []
            for host in result.hosts:
                if isinstance(host, Host):
                    open_ports = [str(p.number) for p in host.ports
                                  if isinstance(p, Port) and p.state == "open"]
                    rows.append([host.ip, host.hostname or "-", host.mac or "-",
                                 host.os_guess or "-", ",".join(open_ports) or "-"])
                elif isinstance(host, dict):
                    rows.append([host.get("ip", ""), host.get("hostname", "-"),
                                 host.get("mac", "-"), host.get("os_guess", "-"), "-"])
            lines.append(format_table(headers, rows))
            lines.append("")
        if result.vulnerabilities:
            lines.append(colorize("vulnerabilities", "red"))
            headers = ["severity", "cve", "host", "port", "description"]
            rows = []
            for vuln in result.vulnerabilities:
                if isinstance(vuln, Vulnerability):
                    sev = vuln.severity.upper()
                    color = SEVERITY_COLORS.get(vuln.severity.lower(), "reset")
                    sev_colored = colorize(sev, color)
                    rows.append([sev_colored, vuln.cve_id, vuln.affected_host,
                                 vuln.affected_port or "-", vuln.description[:60]])
                elif isinstance(vuln, dict):
                    rows.append([vuln.get("severity", ""), vuln.get("cve_id", ""),
                                 vuln.get("affected_host", ""), vuln.get("affected_port", ""),
                                 vuln.get("description", "")[:60]])
            lines.append(format_table(headers, rows))
            lines.append("")
        if result.alerts:
            lines.append(colorize("alerts", "yellow"))
            headers = ["time", "severity", "source", "message"]
            rows = []
            for alert in result.alerts:
                if isinstance(alert, Alert):
                    ts = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
                    rows.append([ts, alert.severity.upper(), alert.source,
                                 alert.message[:60]])
            lines.append(format_table(headers, rows))
            lines.append("")
        lines.append(result.summary())
    return "\n".join(lines)


def html_report(result, file=None, title="orcasec scan report"):
    """generate html report from scan result"""
    data = result.to_dict() if isinstance(result, ScanResult) else result
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    html = [
        "<!doctype html>",
        "<html><head>",
        f"<title>{title}</title>",
        "<style>",
        "body { font-family: monospace; margin: 20px; background: #1a1a2e; color: #e0e0e0; }",
        "h1, h2 { color: #00d4ff; }",
        "table { border-collapse: collapse; width: 100%; margin: 10px 0; }",
        "th { background: #16213e; color: #00d4ff; padding: 8px; text-align: left; }",
        "td { padding: 6px 8px; border-bottom: 1px solid #333; }",
        "tr:hover { background: #1a1a3e; }",
        ".critical, .high { color: #ff4444; }",
        ".medium { color: #ffaa00; }",
        ".low { color: #00ccff; }",
        ".info { color: #44ff44; }",
        ".summary { background: #16213e; padding: 15px; margin: 10px 0; }",
        "</style>",
        "</head><body>",
        f"<h1>{title}</h1>",
        f"<p>generated: {ts}</p>",
        f"<div class='summary'><p>target: {data.get('target', '')}</p>",
        f"<p>duration: {data.get('duration', 0):.1f}s</p>",
        f"<p>hosts: {len(data.get('hosts', []))}</p>",
        f"<p>vulnerabilities: {len(data.get('vulnerabilities', []))}</p></div>",
    ]
    hosts = data.get("hosts", [])
    if hosts:
        html.append("<h2>hosts</h2>")
        html.append("<table><tr><th>ip</th><th>hostname</th><th>mac</th><th>os</th><th>ports</th></tr>")
        for h in hosts:
            ports = h.get("ports", [])
            port_str = ", ".join(str(p.get("number", p) if isinstance(p, dict) else p) for p in ports)
            html.append(f"<tr><td>{h.get('ip', '')}</td><td>{h.get('hostname', '')}</td>"
                        f"<td>{h.get('mac', '')}</td><td>{h.get('os_guess', '')}</td>"
                        f"<td>{port_str}</td></tr>")
        html.append("</table>")
    vulns = data.get("vulnerabilities", [])
    if vulns:
        html.append("<h2>vulnerabilities</h2>")
        html.append("<table><tr><th>severity</th><th>cve</th><th>host</th><th>description</th></tr>")
        for v in vulns:
            sev = v.get("severity", "").lower()
            html.append(f"<tr><td class='{sev}'>{sev}</td><td>{v.get('cve_id', '')}</td>"
                        f"<td>{v.get('affected_host', '')}</td>"
                        f"<td>{v.get('description', '')}</td></tr>")
        html.append("</table>")
    html.append("</body></html>")
    text = "\n".join(html)
    if file:
        os.makedirs(os.path.dirname(file) if os.path.dirname(file) else ".", exist_ok=True)
        with open(file, "w") as f:
            f.write(text)
        return file
    return text


def format_result(result, fmt="table", file=None):
    """dispatch to appropriate formatter"""
    formatters = {
        "json": lambda r: json_output(r, file=file),
        "csv": lambda r: csv_output(r, file=file),
        "table": lambda r: table_output(r),
        "html": lambda r: html_report(r, file=file),
    }
    formatter = formatters.get(fmt, formatters["table"])
    return formatter(result)


def main():
    """demo output formatters"""
    result = ScanResult(target="192.168.1.0/24", scan_type="demo")
    result.hosts = [
        Host(ip="192.168.1.1", hostname="router", mac="aa:bb:cc:dd:ee:ff",
             ports=[Port(80, state="open", service="http"),
                    Port(443, state="open", service="https")]),
        Host(ip="192.168.1.100", hostname="workstation"),
    ]
    result.vulnerabilities = [
        Vulnerability(cve_id="CVE-2024-1234", severity="high",
                      description="buffer overflow in http handler",
                      affected_host="192.168.1.1", affected_port=80),
    ]
    result.finish()
    print(table_output(result))


if __name__ == "__main__":
    main()


def summary_report(scan_result, include_hosts=True, include_vulns=True):
    """generate a text summary of scan results"""
    lines = []
    lines.append(f"scan target: {scan_result.target}")
    lines.append(f"duration: {scan_result.end_time - scan_result.start_time:.1f}s")
    lines.append(f"hosts found: {len(scan_result.hosts)}")
    lines.append(f"vulnerabilities: {len(scan_result.vulnerabilities)}")
    if include_hosts and scan_result.hosts:
        lines.append("\nhosts:")
        for h in scan_result.hosts:
            lines.append(f"  {h.ip} ({h.hostname or 'unknown'})")
    if include_vulns and scan_result.vulnerabilities:
        lines.append("\nvulnerabilities:")
        for v in scan_result.vulnerabilities:
            lines.append(f"  [{v.severity}] {v.cve_id}: {v.description[:60]}")
    return "\n".join(lines)
