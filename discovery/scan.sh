#!/bin/bash
# network host discovery - ping sweep and arp scan modes

show_usage() {
    echo "usage: ./scan.sh [-o outfile] [-t threads] [-m mode] [subnet]"
    echo "modes: ping (default), arp"
}

get_subnet() {
    ip route | grep default | head -1 | awk '{print $3}' | sed 's/\.[0-9]*$//'
}

get_interface() {
    ip route | grep default | head -1 | awk '{print $5}'
}

ping_host() {
    local ip="$1"
    ping -c 1 -W 1 "$ip" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        mac=$(arp -n "$ip" 2>/dev/null | grep "$ip" | awk '{print $3}')
        [ -z "$mac" ] || [ "$mac" = "(incomplete)" ] && mac="unknown"
        hostname=$(host "$ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | sed 's/\.$//')
        [ -z "$hostname" ] && hostname="-"
        printf "%-16s %-18s %s\n" "$ip" "$mac" "$hostname"
    fi
}

export -f ping_host

arp_scan() {
    local subnet="$1"
    local iface=$(get_interface)
    if ! command -v arping &>/dev/null; then
        echo "arping not found, falling back to ping mode"
        ping_scan "$subnet"
        return
    fi
    for i in $(seq 1 254); do
        ip="$subnet.$i"
        result=$(arping -c 1 -w 1 -I "$iface" "$ip" 2>/dev/null | grep "reply from")
        if [ -n "$result" ]; then
            mac=$(echo "$result" | grep -oP '\[.*?\]' | tr -d '[]')
            hostname=$(host "$ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | sed 's/\.$//')
            [ -z "$hostname" ] && hostname="-"
            printf "%-16s %-18s %s\n" "$ip" "$mac" "$hostname"
        fi
    done
}

outfile=""
threads=20
mode="ping"
while getopts "o:t:m:h" opt; do
    case $opt in
        o) outfile="$OPTARG" ;;
        t) threads="$OPTARG" ;;
        m) mode="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

subnet="$1"
if [ -z "$subnet" ]; then
    subnet=$(get_subnet)
    if [ -z "$subnet" ]; then
        echo "could not detect subnet"
        show_usage
        exit 1
    fi
fi

echo "scanning $subnet.0/24 (mode: $mode)..."
printf "\n%-16s %-18s %s\n" "ip" "mac" "hostname"
echo "------------------------------------------------"

if [ "$mode" = "arp" ]; then
    results=$(arp_scan "$subnet")
else
    results=$(seq 1 254 | xargs -I{} -P "$threads" bash -c "ping_host $subnet.{}")
fi

echo "$results" | sort -t. -k4 -n
count=$(echo "$results" | grep -c "\S")

echo ""
echo "$count hosts found"

if [ -n "$outfile" ]; then
    echo "$results" | sort -t. -k4 -n > "$outfile"
    echo "saved to $outfile"
fi
