#!/bin/bash
# arp monitor - detect new hosts and mac address changes

show_usage() {
    echo "usage: ./watch.sh [-i interval] [-l logfile]"
    echo "  -i  check interval in seconds (default 5)"
    echo "  -l  log changes to file"
}

interval=5
logfile=""
while getopts "i:l:h" opt; do
    case $opt in
        i) interval="$OPTARG" ;;
        l) logfile="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

log_msg() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$msg"
    [ -n "$logfile" ] && echo "$msg" >> "$logfile"
}

declare -A known_hosts

parse_arp() {
    arp -n 2>/dev/null | tail -n +2 | while read -r ip type mac flags iface; do
        [ "$mac" = "(incomplete)" ] && continue
        echo "$ip $mac"
    done
}

log_msg "starting arp monitor (interval: ${interval}s)"

while read -r ip mac; do
    known_hosts["$ip"]="$mac"
    log_msg "baseline: $ip -> $mac"
done < <(parse_arp)

echo ""
log_msg "monitoring..."

while true; do
    while read -r ip mac; do
        if [ -z "${known_hosts[$ip]}" ]; then
            log_msg "NEW HOST: $ip ($mac)"
            known_hosts["$ip"]="$mac"
        elif [ "${known_hosts[$ip]}" != "$mac" ]; then
            log_msg "MAC CHANGE: $ip was ${known_hosts[$ip]} now $mac"
            known_hosts["$ip"]="$mac"
        fi
    done < <(parse_arp)
    sleep "$interval"
done
