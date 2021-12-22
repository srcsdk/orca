#!/usr/bin/env python3
__version__ = "1.1.0"
"""network traffic flow analysis"""

import argparse
import json
import os
import platform
import signal
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime


class Flow:
    """represents a network flow (5-tuple)"""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        self.packets = 0
        self.bytes_est = 0
        self.first_seen = time.time()
        self.last_seen = time.time()

    @property
    def key(self):
        return (self.src_ip, self.dst_ip, self.src_port,
                self.dst_port, self.proto)

    @property
    def bidir_key(self):
        """bidirectional flow key (sorted endpoints)"""
        a = (self.src_ip, self.src_port)
        b = (self.dst_ip, self.dst_port)
        if a > b:
            a, b = b, a
        return (a[0], b[0], a[1], b[1], self.proto)

    @property
    def duration(self):
        return max(self.last_seen - self.first_seen, 0.001)

    def update(self, timestamp=None):
        self.packets += 1
        self.bytes_est += 64  # rough estimate without actual byte counts
        self.last_seen = timestamp or time.time()

    def to_dict(self):
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "packets": self.packets,
            "duration": round(self.duration, 2),
            "first_seen": datetime.fromtimestamp(self.first_seen).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen).isoformat(),
        }


class FlowTracker:
    """aggregate packets into flows and analyze"""

    def __init__(self, timeout=30):
        self.flows = {}
        self.bidirectional = {}
        self.timeout = timeout
        self.proto_stats = Counter()
        self.port_stats = Counter()

    def process(self, src_ip, dst_ip, src_port, dst_port, proto,
                timestamp=None):
        """process a packet into a flow"""
        key = (src_ip, dst_ip, src_port, dst_port, proto)

        if key not in self.flows:
            self.flows[key] = Flow(src_ip, dst_ip, src_port, dst_port, proto)

        flow = self.flows[key]
        flow.update(timestamp)

        self.proto_stats[proto] += 1
        if dst_port > 0:
            self.port_stats[dst_port] += 1

        # bidirectional tracking
        bidir_key = flow.bidir_key
        if bidir_key not in self.bidirectional:
            self.bidirectional[bidir_key] = {
                "forward": 0, "reverse": 0,
                "endpoints": [src_ip, dst_ip],
                "ports": [src_port, dst_port],
                "proto": proto,
            }
        if (src_ip, src_port) <= (dst_ip, dst_port):
            self.bidirectional[bidir_key]["forward"] += 1
        else:
            self.bidirectional[bidir_key]["reverse"] += 1

    def expire_flows(self, current_time=None):
        """remove flows that have timed out"""
        now = current_time or time.time()
        expired = [
            k for k, f in self.flows.items()
            if now - f.last_seen > self.timeout
        ]
        for k in expired:
            del self.flows[k]
        return len(expired)

    def top_flows(self, n=10):
        """get top flows by packet count"""
        return sorted(
            self.flows.values(),
            key=lambda f: f.packets,
            reverse=True
        )[:n]

    def top_conversations(self, n=10):
        """get top bidirectional conversations"""
        return sorted(
            self.bidirectional.items(),
            key=lambda x: x[1]["forward"] + x[1]["reverse"],
            reverse=True
        )[:n]

    def stats(self):
        """return overall flow statistics"""
        total_packets = sum(f.packets for f in self.flows.values())
        return {
            "active_flows": len(self.flows),
            "total_packets": total_packets,
            "protocols": dict(self.proto_stats.most_common()),
            "top_ports": dict(self.port_stats.most_common(20)),
            "top_flows": [f.to_dict() for f in self.top_flows(10)],
        }

    def print_stats(self):
        """display flow analysis"""
        s = self.stats()
        print("\n--- flow summary ---")
        print(f"active flows:  {s['active_flows']}")
        print(f"total packets: {s['total_packets']}")

        print("\nprotocols:")
        total = sum(s["protocols"].values())
        for proto, count in s["protocols"].items():
            pct = count / max(total, 1) * 100
            print(f"  {proto:<8} {count:>8} ({pct:.1f}%)")

        print("\ntop destination ports:")
        for port, count in list(s["top_ports"].items())[:10]:
            svc = ""
            try:
                import socket
                svc = socket.getservbyport(int(port), "tcp")
            except (OSError, ValueError):
                pass
            print(f"  {port:>6}  {count:>8}  {svc}")

        print("\ntop flows:")
        for flow in s["top_flows"][:5]:
            print(f"  {flow['src_ip']}:{flow['src_port']} -> "
                  f"{flow['dst_ip']}:{flow['dst_port']} "
                  f"{flow['proto']} {flow['packets']} pkts "
                  f"({flow['duration']}s)")

        print("\ntop conversations:")
        for key, conv in self.top_conversations(5):
            total = conv["forward"] + conv["reverse"]
            ratio = conv["forward"] / max(conv["reverse"], 1)
            print(f"  {conv['endpoints'][0]} <-> {conv['endpoints'][1]} "
                  f"({conv['proto']}) {total} pkts (ratio: {ratio:.1f})")


def get_default_interface():
    """detect default network interface for current platform"""
    system = platform.system()
    try:
        if system == "Linux":
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            for part in result.stdout.split():
                if part == "dev":
                    idx = result.stdout.split().index("dev")
                    return result.stdout.split()[idx + 1]
        elif system == "Darwin":
            result = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "interface:" in line:
                    return line.split()[-1]
        elif system == "Windows":
            result = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "Connected" in line:
                    return line.split()[-1]
    except (subprocess.TimeoutExpired, OSError, IndexError):
        pass

    defaults = {"Linux": "eth0", "Darwin": "en0", "Windows": "Ethernet"}
    return defaults.get(system, "eth0")


def is_admin():
    """check if running with admin/root privileges"""
    system = platform.system()
    if system == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


def run_demo(tracker):
    """generate demo flow data for testing without root"""
    import random
    print("running demo mode (no root privileges)")
    print("generating synthetic flow data...\n")

    hosts = [
        "192.168.1.10", "192.168.1.20", "192.168.1.30",
        "10.0.0.1", "10.0.0.5",
    ]
    externals = [
        "8.8.8.8", "1.1.1.1", "93.184.216.34",
        "151.101.1.140", "172.217.14.206",
    ]
    protos = ["TCP", "UDP", "TCP", "TCP", "ICMP"]
    ports = [80, 443, 53, 22, 8080, 3306, 25, 110, 993, 8443]

    base_time = time.time() - 120
    for i in range(200):
        src = random.choice(hosts)
        dst = random.choice(externals)
        proto = random.choice(protos)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(ports)
        ts = base_time + i * 0.6

        tracker.process(src, dst, src_port, dst_port, proto, ts)

        if random.random() < 0.3:
            tracker.process(dst, src, dst_port, src_port, proto, ts + 0.01)

    tracker.print_stats()


def monitor_tcpdump(interface, tracker, bpf_filter=None):
    """monitor traffic with tcpdump"""
    system = platform.system()
    if system == "Windows":
        print("tcpdump not available on windows", file=sys.stderr)
        print("use windump or install npcap with tshark", file=sys.stderr)
        sys.exit(1)

    cmd = ["tcpdump", "-i", interface, "-nn", "-l", "-tttt"]
    if bpf_filter:
        cmd.extend(bpf_filter.split())

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    def stop(sig, frame):
        proc.terminate()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    for line in proc.stdout:
        parts = line.split()
        if "IP" not in parts:
            continue

        try:
            ip_idx = parts.index("IP")
            src = parts[ip_idx + 1]
            dst = parts[ip_idx + 3].rstrip(":")

            src_ip = src.rsplit(".", 1)[0] if "." in src else src
            src_port = int(src.rsplit(".", 1)[1]) if "." in src else 0
            dst_ip = dst.rsplit(".", 1)[0] if "." in dst else dst
            dst_port = int(dst.rsplit(".", 1)[1]) if "." in dst else 0

            proto = "TCP"
            if "UDP" in line:
                proto = "UDP"
            elif "ICMP" in line:
                proto = "ICMP"

            tracker.process(src_ip, dst_ip, src_port, dst_port, proto)
        except (ValueError, IndexError):
            continue

    proc.wait()


def main():
    default_iface = get_default_interface()
    parser = argparse.ArgumentParser(description="network flow analysis")
    parser.add_argument("-i", "--interface", default=default_iface,
                        help=f"capture interface (default: {default_iface})")
    parser.add_argument("-f", "--filter", type=str,
                        help="bpf filter")
    parser.add_argument("--timeout", type=int, default=30,
                        help="flow timeout in seconds (default: 30)")
    parser.add_argument("-o", "--output", type=str,
                        help="save flow data to json")
    parser.add_argument("--demo", action="store_true",
                        help="run with synthetic demo data")

    args = parser.parse_args()

    tracker = FlowTracker(timeout=args.timeout)

    if args.demo or not is_admin():
        run_demo(tracker)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(tracker.stats(), f, indent=2)
            print(f"\nsaved to {args.output}")
        return

    print(f"tracking flows on {args.interface} (timeout: {args.timeout}s)")
    print("ctrl+c to stop\n")

    try:
        monitor_tcpdump(args.interface, tracker, args.filter)
    except KeyboardInterrupt:
        pass

    tracker.print_stats()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(tracker.stats(), f, indent=2)
        print(f"\nsaved to {args.output}")


if __name__ == "__main__":
    main()


def conversation_durations(tracker):
    """calculate duration stats for all bidirectional conversations.

    returns a list of conversations with timing information
    sorted by total duration descending.
    """
    results = []
    for key, conv in tracker.bidirectional.items():
        # find matching flows to get timing
        total_packets = conv["forward"] + conv["reverse"]
        endpoints = conv["endpoints"]
        proto = conv["proto"]

        # look up actual flow objects for timing data
        best_duration = 0
        for fkey, flow in tracker.flows.items():
            if (flow.src_ip in endpoints and flow.dst_ip in endpoints
                    and flow.proto == proto):
                if flow.duration > best_duration:
                    best_duration = flow.duration

        results.append({
            "endpoints": endpoints,
            "proto": proto,
            "packets": total_packets,
            "duration_seconds": round(best_duration, 2),
            "forward": conv["forward"],
            "reverse": conv["reverse"],
        })

    results.sort(key=lambda c: c["duration_seconds"], reverse=True)
    return results


def print_conversation_durations(tracker, limit=10):
    """display conversation duration report"""
    durations = conversation_durations(tracker)
    print(f"\nconversation durations (top {limit}):")
    for conv in durations[:limit]:
        ep = " <-> ".join(conv["endpoints"])
        dur = conv["duration_seconds"]
        pkts = conv["packets"]
        print(f"  {ep} ({conv['proto']}) "
              f"{dur:.1f}s {pkts} pkts")
