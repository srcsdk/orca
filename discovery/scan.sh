#!/bin/bash
# network host discovery - ping sweep and arp scan

show_usage() {
    echo "usage: ./scan.sh [-o outfile] [-t threads] [-m mode] [-v] [target]"
    echo "target: subnet base (192.168.1) or cidr (192.168.1.0/24)"
    echo "modes: ping (default), arp"
    echo "  -v  verbose (show unreachable hosts)"
}

get_subnet() {
    ip route | grep default | head -1 | awk '{print $3}' | sed 's/\.[0-9]*$//'
}

get_interface() {
    ip route | grep default | head -1 | awk '{print $5}'
}

parse_cidr() {
    local cidr="$1"
    local base=$(echo "$cidr" | cut -d/ -f1 | sed 's/\.[0-9]*$//')
    local mask=$(echo "$cidr" | cut -d/ -f2)
    case "$mask" in
        24) echo "$base 1 254" ;;
        25) echo "$base 1 126" ;;
        26) echo "$base 1 62" ;;
        27) echo "$base 1 30" ;;
        28) echo "$base 1 14" ;;
        *)  echo "$base 1 254" ;;
    esac
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
    local start="$2"
    local end="$3"
    local iface=$(get_interface)
    if ! command -v arping &>/dev/null; then
        echo "arping not found, using ping" >&2
        for i in $(seq "$start" "$end"); do
            ping_host "$subnet.$i"
        done
        return
    fi
    for i in $(seq "$start" "$end"); do
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
verbose=0
while getopts "o:t:m:vh" opt; do
    case $opt in
        o) outfile="$OPTARG" ;;
        t) threads="$OPTARG" ;;
        m) mode="$OPTARG" ;;
        v) verbose=1 ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

target="$1"
start_host=1
end_host=254

if [ -z "$target" ]; then
    subnet=$(get_subnet)
elif echo "$target" | grep -q "/"; then
    read -r subnet start_host end_host <<< "$(parse_cidr "$target")"
else
    subnet="$target"
fi

[ -z "$subnet" ] && { echo "could not determine target"; show_usage; exit 1; }

range_size=$((end_host - start_host + 1))
echo "scanning $subnet.0 ($range_size hosts, mode: $mode, threads: $threads)..."
printf "\n%-16s %-18s %s\n" "ip" "mac" "hostname"
echo "------------------------------------------------"

start_time=$(date +%s)

if [ "$mode" = "arp" ]; then
    results=$(arp_scan "$subnet" "$start_host" "$end_host")
else
    results=$(seq "$start_host" "$end_host" | xargs -I{} -P "$threads" bash -c "ping_host $subnet.{}")
fi

echo "$results" | sort -t. -k4 -n
count=$(echo "$results" | grep -c "\S")

end_time=$(date +%s)
elapsed=$((end_time - start_time))

echo ""
echo "$count hosts found (scanned $range_size in ${elapsed}s)"

if [ -n "$outfile" ]; then
    {
        printf "%-16s %-18s %s\n" "ip" "mac" "hostname"
        echo "------------------------------------------------"
        echo "$results" | sort -t. -k4 -n
        echo ""
        echo "$count hosts found"
    } > "$outfile"
    echo "saved to $outfile"
fi
