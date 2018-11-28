#!/bin/bash
# network scan detection and connection logging

show_usage() {
    echo "usage: ./detect.sh [-t threshold] [-w window] [-l logfile] [-i iface] [-s] [-b blocklist]"
    echo "  -t  port threshold (default 15)"
    echo "  -w  time window seconds (default 10)"
    echo "  -l  log file"
    echo "  -i  interface"
    echo "  -s  print stats on exit"
    echo "  -b  export blocked ips to file (for use with iptables)"
}

threshold=15
window=10
logfile=""
iface=""
show_stats=0
blocklist=""
total_packets=0
total_alerts=0

while getopts "t:w:l:i:sb:h" opt; do
    case $opt in
        t) threshold="$OPTARG" ;;
        w) window="$OPTARG" ;;
        l) logfile="$OPTARG" ;;
        i) iface="$OPTARG" ;;
        s) show_stats=1 ;;
        b) blocklist="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

if ! command -v tcpdump &>/dev/null; then
    echo "tcpdump not found"
    exit 1
fi

log_msg() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$msg"
    [ -n "$logfile" ] && echo "$msg" >> "$logfile"
}

alert() {
    local severity="$1"
    local src="$2"
    local msg="$3"
    log_msg "[$severity] $msg"
    total_alerts=$((total_alerts + 1))

    if [ -n "$blocklist" ]; then
        if ! grep -q "^$src$" "$blocklist" 2>/dev/null; then
            echo "$src" >> "$blocklist"
            log_msg "added $src to blocklist"
        fi
    fi
}

print_stats() {
    echo ""
    echo "=== session stats ==="
    echo "packets analyzed: $total_packets"
    echo "alerts generated: $total_alerts"
    echo "unique sources:   ${#src_first_seen[@]}"
    if [ -n "$blocklist" ] && [ -f "$blocklist" ]; then
        echo "blocked ips:      $(wc -l < "$blocklist")"
    fi
}

[ $show_stats -eq 1 ] && trap print_stats EXIT

log_msg "scan detector started"
log_msg "config: threshold=$threshold window=${window}s"
[ -n "$blocklist" ] && log_msg "blocklist: $blocklist"

declare -A src_ports
declare -A src_first_seen
declare -A alerted

cmd="tcpdump -n -l --immediate-mode"
[ -n "$iface" ] && cmd="$cmd -i $iface"
cmd="$cmd 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'"

eval "$cmd" 2>/dev/null | while read -r line; do
    src_ip=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
    dst_ip=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | tail -1)
    dst_port=$(echo "$line" | grep -oP '\.\d+:' | tail -1 | tr -d '.:'  )

    [ -z "$src_ip" ] || [ -z "$dst_port" ] && continue

    total_packets=$((total_packets + 1))
    now=$(date +%s)

    if [ -z "${src_first_seen[$src_ip]}" ] || [ $((now - ${src_first_seen[$src_ip]})) -gt $window ]; then
        src_ports["$src_ip"]=""
        src_first_seen["$src_ip"]="$now"
        unset alerted["$src_ip"]
    fi

    src_ports["$src_ip"]="${src_ports[$src_ip]} $dst_port"
    unique=$(echo "${src_ports[$src_ip]}" | tr ' ' '\n' | sort -u | grep -c "\S")

    [ -n "${alerted[$src_ip]}" ] && continue

    if [ "$unique" -ge $((threshold * 3)) ]; then
        alert "CRITICAL" "$src_ip" "aggressive scan from $src_ip -> $dst_ip ($unique ports in ${window}s)"
        alerted["$src_ip"]=1
    elif [ "$unique" -ge "$threshold" ]; then
        alert "WARNING" "$src_ip" "possible scan from $src_ip -> $dst_ip ($unique ports in ${window}s)"
        alerted["$src_ip"]=1
    fi
done
