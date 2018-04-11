#!/bin/bash
# arp monitor - detect spoofing and anomalies

show_usage() {
    echo "usage: ./watch.sh [-i interval] [-l logfile] [-g gateway] [-b baseline]"
    echo "  -i  check interval in seconds (default 3)"
    echo "  -l  log to file"
    echo "  -g  gateway ip to watch"
    echo "  -b  baseline file (save on first run, compare on subsequent)"
}

interval=3
logfile=""
gateway=""
baseline_file=""
while getopts "i:l:g:b:h" opt; do
    case $opt in
        i) interval="$OPTARG" ;;
        l) logfile="$OPTARG" ;;
        g) gateway="$OPTARG" ;;
        b) baseline_file="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

[ -z "$gateway" ] && gateway=$(ip route | grep default | head -1 | awk '{print $3}')

log_msg() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$msg"
    [ -n "$logfile" ] && echo "$msg" >> "$logfile"
}

alert() {
    log_msg "[ALERT] $1"
}

declare -A known_hosts

parse_arp() {
    arp -n 2>/dev/null | tail -n +2 | while read -r ip type mac flags iface; do
        [ "$mac" = "(incomplete)" ] && continue
        echo "$ip $mac"
    done
}

load_baseline() {
    if [ -n "$baseline_file" ] && [ -f "$baseline_file" ]; then
        while read -r ip mac; do
            known_hosts["$ip"]="$mac"
        done < "$baseline_file"
        log_msg "loaded baseline: ${#known_hosts[@]} hosts from $baseline_file"
        return 0
    fi
    return 1
}

save_baseline() {
    if [ -n "$baseline_file" ]; then
        for ip in "${!known_hosts[@]}"; do
            echo "$ip ${known_hosts[$ip]}"
        done | sort > "$baseline_file"
        log_msg "saved baseline: ${#known_hosts[@]} hosts to $baseline_file"
    fi
}

log_msg "arp monitor started (gateway: $gateway)"

if ! load_baseline; then
    while read -r ip mac; do
        known_hosts["$ip"]="$mac"
    done < <(parse_arp)
    log_msg "scanned baseline: ${#known_hosts[@]} hosts"
    save_baseline
fi

log_msg "monitoring..."
echo ""

while true; do
    while read -r ip mac; do
        if [ -z "${known_hosts[$ip]}" ]; then
            log_msg "new host: $ip ($mac)"
            known_hosts["$ip"]="$mac"
            save_baseline
        elif [ "${known_hosts[$ip]}" != "$mac" ]; then
            old="${known_hosts[$ip]}"
            if [ "$ip" = "$gateway" ]; then
                alert "GATEWAY MAC CHANGED: $ip $old -> $mac (possible arp spoof)"
            else
                alert "mac changed: $ip $old -> $mac"
            fi
            known_hosts["$ip"]="$mac"
            save_baseline
        fi
    done < <(parse_arp)
    sleep "$interval"
done
