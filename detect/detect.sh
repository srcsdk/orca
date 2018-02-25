#!/bin/bash
# detect port scanning by watching connection attempts

show_usage() {
    echo "usage: ./detect.sh [-t threshold] [-w window] [-l logfile]"
    echo "  -t  port threshold per source (default 15)"
    echo "  -w  time window in seconds (default 10)"
    echo "  -l  log alerts to file"
}

threshold=15
window=10
logfile=""

while getopts "t:w:l:h" opt; do
    case $opt in
        t) threshold="$OPTARG" ;;
        w) window="$OPTARG" ;;
        l) logfile="$OPTARG" ;;
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

log_msg "scan detector started (threshold: $threshold ports in ${window}s)"

declare -A src_ports
declare -A src_first_seen

tcpdump -n -q --immediate-mode 'tcp[tcpflags] & tcp-syn != 0' 2>/dev/null | while read -r line; do
    src_ip=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
    dst_port=$(echo "$line" | grep -oP '(?<=\.)\d+:' | tail -1 | tr -d ':')

    [ -z "$src_ip" ] || [ -z "$dst_port" ] && continue

    now=$(date +%s)

    if [ -z "${src_first_seen[$src_ip]}" ] || [ $((now - ${src_first_seen[$src_ip]})) -gt $window ]; then
        src_ports["$src_ip"]=""
        src_first_seen["$src_ip"]="$now"
    fi

    src_ports["$src_ip"]="${src_ports[$src_ip]} $dst_port"
    unique=$(echo "${src_ports[$src_ip]}" | tr ' ' '\n' | sort -u | grep -c "\S")

    if [ "$unique" -ge "$threshold" ]; then
        log_msg "[ALERT] port scan detected from $src_ip ($unique ports in ${window}s)"
        src_ports["$src_ip"]=""
        src_first_seen["$src_ip"]="$now"
    fi
done
