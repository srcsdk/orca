#!/usr/bin/env python3
"""packet capture and protocol analysis"""

import argparse
import json
import os
import signal
import struct
import subprocess
import sys
import time
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
        print(f"\n--- capture summary ---")
        print(f"total packets: {s['total_packets']}")

        print(f"\nprotocols:")
        for proto, count in s["protocols"].items():
            pct = count / s["total_packets"] * 100
            print(f"  {proto:<8} {count:>6} ({pct:.1f}%)")

        print(f"\ntop sources:")
        for src, count in list(s["top_sources"].items())[:5]:
            print(f"  {src:<30} {count}")

        print(f"\ntop destinations:")
        for dst, count in list(s["top_destinations"].items())[:5]:
            print(f"  {dst:<30} {count}")

        print(f"\ntop conversations:")
        for conv in s["top_conversations"][:5]:
            pair = " <-> ".join(conv["pair"])
            print(f"  {pair:<40} {conv['packets']}")


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


def main():
    parser = argparse.ArgumentParser(description="packet capture and analysis")
    parser.add_argument("-i", "--interface", default="eth0",
                        help="capture interface")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="number of packets to capture (0=unlimited)")
    parser.add_argument("-f", "--filter", type=str,
                        help="bpf filter expression")
    parser.add_argument("-w", "--write", type=str,
                        help="write packets to pcap file")
    parser.add_argument("-r", "--read", type=str,
                        help="read and analyze existing pcap")
    parser.add_argument("-o", "--output", type=str,
                        help="save stats to json")

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
        return

    # live capture
    if os.geteuid() != 0:
        print("live capture requires root", file=sys.stderr)
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

    if args.output:
        with open(args.output, "w") as f:
            json.dump(analyzer.stats(), f, indent=2)
        print(f"\nsaved stats to {args.output}")


if __name__ == "__main__":
    main()
