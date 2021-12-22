#!/usr/bin/env python3
__version__ = "1.1.0"
"""packet capture and protocol analysis"""

import argparse
import json
import os
import platform
import signal
import subprocess
import sys
from collections import defaultdict, Counter
from datetime import datetime


def run_tcpdump(interface, count=0, timeout=None, bpf_filter=None,
                output_file=None):
    """capture packets using tcpdump"""
    cmd = ["tcpdump", "-i", interface, "-nn", "-l"]

    if count > 0:
        cmd.extend(["-c", str(count)])
    if output_file:
        cmd.extend(["-w", output_file])
    else:
        cmd.append("-tttt")  # human-readable timestamps
    if bpf_filter:
        cmd.extend(bpf_filter.split())

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1
        )
        return proc
    except (FileNotFoundError, PermissionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return None


def parse_tcpdump_line(line):
    """parse a tcpdump output line into structured data"""
    parts = line.split()
    if len(parts) < 5:
        return None

    try:
        # try to extract timestamp and protocol info
        entry = {"raw": line.strip()}

        # look for IP indicator
        if "IP" in parts or "IP6" in parts:
            ip_idx = parts.index("IP") if "IP" in parts else parts.index("IP6")
            entry["proto_family"] = parts[ip_idx]

            # source > destination
            if ">" in parts:
                gt_idx = parts.index(">")
                entry["src"] = parts[gt_idx - 1].rstrip(":")
                entry["dst"] = parts[gt_idx + 1].rstrip(":")

            # detect protocol from port or content
            for part in parts:
                if "Flags" in part:
                    entry["proto"] = "TCP"
                    break
            else:
                if "UDP" in line or "udp" in line:
                    entry["proto"] = "UDP"
                elif "ICMP" in line or "icmp" in line:
                    entry["proto"] = "ICMP"
                else:
                    entry["proto"] = "OTHER"

        elif "ARP" in parts:
            entry["proto"] = "ARP"
            entry["proto_family"] = "ARP"

        return entry
    except (ValueError, IndexError):
        return None


class PacketAnalyzer:
    """analyze captured packets"""

    def __init__(self):
        self.packets = []
        self.proto_counts = Counter()
        self.src_counts = Counter()
        self.dst_counts = Counter()
        self.conversations = defaultdict(int)

    def process(self, entry):
        """process a parsed packet entry"""
        if not entry:
            return

        self.packets.append(entry)
        proto = entry.get("proto", "UNKNOWN")
        self.proto_counts[proto] += 1

        src = entry.get("src", "")
        dst = entry.get("dst", "")
        if src:
            self.src_counts[src] += 1
        if dst:
            self.dst_counts[dst] += 1
        if src and dst:
            key = tuple(sorted([src, dst]))
            self.conversations[key] += 1

    def stats(self):
        """return analysis statistics"""
        return {
            "total_packets": len(self.packets),
            "protocols": dict(self.proto_counts.most_common()),
            "top_sources": dict(self.src_counts.most_common(10)),
            "top_destinations": dict(self.dst_counts.most_common(10)),
            "top_conversations": [
                {"pair": list(k), "packets": v}
                for k, v in sorted(
                    self.conversations.items(),
                    key=lambda x: x[1], reverse=True
                )[:10]
            ],
        }

    def print_stats(self):
        """display analysis results"""
        s = self.stats()
        print("\n--- capture summary ---")
        print(f"total packets: {s['total_packets']}")

        print("\nprotocols:")
        for proto, count in s["protocols"].items():
            pct = count / s["total_packets"] * 100
            print(f"  {proto:<8} {count:>6} ({pct:.1f}%)")

        print("\ntop sources:")
        for src, count in list(s["top_sources"].items())[:5]:
            print(f"  {src:<30} {count}")

        print("\ntop destinations:")
        for dst, count in list(s["top_destinations"].items())[:5]:
            print(f"  {dst:<30} {count}")

        print("\ntop conversations:")
        for conv in s["top_conversations"][:5]:
            pair = " <-> ".join(conv["pair"])
            print(f"  {pair:<40} {conv['packets']}")


def export_pcap(analyzer, output_file):
    """export captured data to a simplified text format.

    writes packet summaries to a file for later analysis
    or import into other tools.
    """
    if not analyzer.packets:
        print("no packets to export", file=sys.stderr)
        return False

    with open(output_file, "w") as f:
        f.write(f"# packet export - {datetime.now().isoformat()}\n")
        f.write(f"# total packets: {len(analyzer.packets)}\n\n")

        for i, pkt in enumerate(analyzer.packets):
            src = pkt.get("src", "unknown")
            dst = pkt.get("dst", "unknown")
            proto = pkt.get("proto", "?")
            raw = pkt.get("raw", "")
            f.write(f"{i+1}\t{proto}\t{src}\t{dst}\t{raw[:120]}\n")

    print(f"exported {len(analyzer.packets)} packets to {output_file}")
    return True


def analyze_pcap(filename):
    """analyze an existing pcap file"""
    cmd = ["tcpdump", "-nn", "-r", filename, "-tttt"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
        analyzer = PacketAnalyzer()
        for line in result.stdout.split("\n"):
            entry = parse_tcpdump_line(line)
            analyzer.process(entry)
        return analyzer
    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"error reading pcap: {e}", file=sys.stderr)
        return None


def get_default_interface():
    """detect default network interface for current platform"""
    system = platform.system()
    try:
        if system == "Linux":
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            parts = result.stdout.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
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
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


def run_demo():
    """generate demo capture data for testing without root"""
    import random
    print("running demo mode (no root privileges)")
    print("generating synthetic packet data...\n")

    analyzer = PacketAnalyzer()
    hosts = ["192.168.1.10", "192.168.1.20", "10.0.0.1", "10.0.0.5"]
    externals = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "172.217.14.206"]
    protos = ["TCP", "UDP", "TCP", "TCP", "ICMP", "ARP"]

    for i in range(150):
        src = random.choice(hosts)
        dst = random.choice(externals)
        proto = random.choice(protos)
        entry = {
            "raw": f"demo packet {i}",
            "proto_family": "IP",
            "src": f"{src}.{random.randint(1024, 65535)}",
            "dst": f"{dst}.{random.choice([80, 443, 53, 22, 8080])}",
            "proto": proto,
        }
        analyzer.process(entry)
        print(f"  {proto:<6} {entry['src']} -> {entry['dst']}")

    analyzer.print_stats()
    return analyzer


def main():
    default_iface = get_default_interface()
    parser = argparse.ArgumentParser(description="packet capture and analysis")
    parser.add_argument("-i", "--interface", default=default_iface,
                        help=f"capture interface (default: {default_iface})")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="number of packets to capture (0=unlimited)")
    parser.add_argument("-f", "--filter", type=str,
                        help="bpf filter expression")
    parser.add_argument("-w", "--write", type=str,
                        help="write packets to pcap file")
    parser.add_argument("-r", "--read", type=str,
                        help="read and analyze existing pcap")
    parser.add_argument("-e", "--export", type=str,
                        help="export packets to text file")
    parser.add_argument("-o", "--output", type=str,
                        help="save stats to json")
    parser.add_argument("--demo", action="store_true",
                        help="run with synthetic demo data")

    args = parser.parse_args()

    # analyze existing pcap
    if args.read:
        print(f"analyzing {args.read}...")
        analyzer = analyze_pcap(args.read)
        if analyzer:
            analyzer.print_stats()
            if args.output:
                with open(args.output, "w") as f:
                    json.dump(analyzer.stats(), f, indent=2)
                print(f"\nsaved stats to {args.output}")
            if args.export:
                export_pcap(analyzer, args.export)
        return

    # demo mode when no root or explicitly requested
    if args.demo or not is_admin():
        analyzer = run_demo()
        if args.output:
            with open(args.output, "w") as f:
                json.dump(analyzer.stats(), f, indent=2)
            print(f"\nsaved stats to {args.output}")
        return

    # live capture
    if platform.system() == "Windows":
        print("tcpdump not available on windows", file=sys.stderr)
        print("use windump or install npcap with tshark", file=sys.stderr)
        sys.exit(1)

    analyzer = PacketAnalyzer()
    proc = run_tcpdump(args.interface, args.count, bpf_filter=args.filter,
                       output_file=args.write)

    if not proc:
        sys.exit(1)

    def stop(sig, frame):
        proc.terminate()
        print()

    signal.signal(signal.SIGINT, stop)

    count_str = str(args.count) if args.count > 0 else "unlimited"
    print(f"capturing on {args.interface} ({count_str} packets)...")
    if args.filter:
        print(f"filter: {args.filter}")
    if args.write:
        print(f"writing to {args.write}")
    print()

    try:
        for line in proc.stdout:
            entry = parse_tcpdump_line(line)
            if entry:
                analyzer.process(entry)
                if not args.write:
                    src = entry.get("src", "?")
                    dst = entry.get("dst", "?")
                    proto = entry.get("proto", "?")
                    print(f"  {proto:<6} {src} -> {dst}")
    except KeyboardInterrupt:
        pass

    proc.wait()
    analyzer.print_stats()

    if args.export:
        export_pcap(analyzer, args.export)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(analyzer.stats(), f, indent=2)
        print(f"\nsaved stats to {args.output}")


if __name__ == "__main__":
    main()
