#!/bin/bash
# intrusion detection from tcpdump output

show_usage() {
    echo "usage: ./weewoo.sh [-i iface] [-r pcap_file] [-l logfile] [-t threshold]"
    echo "  -i  interface for live capture"
    echo "  -r  read from pcap file"
    echo "  -l  log alerts to file"
    echo "  -t  syn flood threshold per second (default: 100)"
}

iface=""
pcap=""
logfile=""
syn_threshold=100
total_packets=0
total_alerts=0

while getopts "i:r:l:t:h" opt; do
    case $opt in
        i) iface="$OPTARG" ;;
        r) pcap="$OPTARG" ;;
        l) logfile="$OPTARG" ;;
        t) syn_threshold="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

[ -z "$iface" ] && [ -z "$pcap" ] && iface="eth0"

log_msg() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$msg"
    [ -n "$logfile" ] && echo "$msg" >> "$logfile"
}

alert() {
    local severity="$1"
    local msg="$2"
    total_alerts=$((total_alerts + 1))
    log_msg "[$severity] $msg"
}

declare -A syn_count
declare -A syn_window
last_reset=$(date +%s)

check_signatures() {
    local line="$1"
    local src_ip="$2"

    # shellcode nop sled
    if echo "$line" | grep -qE '(0x90){4,}|\\x90\\x90\\x90\\x90'; then
        alert "CRITICAL" "possible nop sled from $src_ip"
    fi

    # port scan detection (christmas tree scan)
    if echo "$line" | grep -q "Flags \[FPU\]"; then
        alert "HIGH" "xmas scan detected from $src_ip"
    fi

    # null scan
    if echo "$line" | grep -q "Flags \[\.\]" && echo "$line" | grep -qv "ack"; then
        alert "MEDIUM" "possible null scan from $src_ip"
    fi

    # fin scan
    if echo "$line" | grep -q "Flags \[F\]"; then
        alert "MEDIUM" "fin scan detected from $src_ip"
    fi
}

analyze_packet() {
    local line="$1"
    total_packets=$((total_packets + 1))

    local src_ip=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
    [ -z "$src_ip" ] && return

    now=$(date +%s)

    # reset counters every second
    if [ $((now - last_reset)) -ge 1 ]; then
        for ip in "${!syn_count[@]}"; do
            if [ "${syn_count[$ip]}" -ge "$syn_threshold" ]; then
                alert "CRITICAL" "syn flood from $ip: ${syn_count[$ip]} syns/sec"
            fi
        done
        unset syn_count
        declare -gA syn_count
        last_reset=$now
    fi

    # track syn packets
    if echo "$line" | grep -q "Flags \[S\]"; then
        syn_count["$src_ip"]=$(( ${syn_count[$src_ip]:-0} + 1 ))
    fi

    check_signatures "$line" "$src_ip"
}

trap 'echo ""; echo "packets: $total_packets, alerts: $total_alerts"; exit 0' INT TERM

log_msg "ids started"

if [ -n "$pcap" ]; then
    log_msg "reading from $pcap"
    tcpdump -nn -r "$pcap" 2>/dev/null | while read -r line; do
        analyze_packet "$line"
    done
else
    log_msg "monitoring $iface"
    tcpdump -i "$iface" -nn -l 2>/dev/null | while read -r line; do
        analyze_packet "$line"
    done
fi

echo ""
echo "packets analyzed: $total_packets"
echo "alerts generated: $total_alerts"
