#!/bin/bash
# arp monitor - detect spoofing and anomalies

show_usage() {
    echo "usage: ./watch.sh [-i interval] [-l logfile] [-g gateway]"
    echo "  -i  check interval in seconds (default 3)"
    echo "  -l  log to file"
    echo "  -g  gateway ip to watch closely"
}

interval=3
logfile=""
gateway=""
while getopts "i:l:g:h" opt; do
    case $opt in
        i) interval="$OPTARG" ;;
        l) logfile="$OPTARG" ;;
        g) gateway="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

if [ -z "$gateway" ]; then
    gateway=$(ip route | grep default | head -1 | awk '{print $3}')
fi

log_msg() {
    local ts="$(date '+%Y-%m-%d %H:%M:%S')"
    local msg="$ts $1"
    echo "$msg"
    [ -n "$logfile" ] && echo "$msg" >> "$logfile"
}

alert() {
    local msg="$1"
    log_msg "[ALERT] $msg"
}

declare -A known_hosts
declare -A mac_ips

parse_arp() {
    arp -n 2>/dev/null | tail -n +2 | while read -r ip type mac flags iface; do
        [ "$mac" = "(incomplete)" ] && continue
        echo "$ip $mac"
    done
}

log_msg "arp monitor started"
log_msg "gateway: $gateway"
echo ""

while read -r ip mac; do
    known_hosts["$ip"]="$mac"
    mac_ips["$mac"]="${mac_ips[$mac]} $ip"
done < <(parse_arp)

log_msg "baseline: ${#known_hosts[@]} hosts"
log_msg "monitoring..."
echo ""

while true; do
    while read -r ip mac; do
        if [ -z "${known_hosts[$ip]}" ]; then
            log_msg "new host: $ip ($mac)"
            known_hosts["$ip"]="$mac"
            mac_ips["$mac"]="${mac_ips[$mac]} $ip"
        elif [ "${known_hosts[$ip]}" != "$mac" ]; then
            old_mac="${known_hosts[$ip]}"
            if [ "$ip" = "$gateway" ]; then
                alert "GATEWAY MAC CHANGED: $ip was $old_mac now $mac (possible arp spoof)"
            else
                alert "mac changed: $ip was $old_mac now $mac"
            fi
            known_hosts["$ip"]="$mac"
        fi
    done < <(parse_arp)

    for mac in "${!mac_ips[@]}"; do
        ip_count=$(echo "${mac_ips[$mac]}" | tr ' ' '\n' | sort -u | grep -c "\S")
        if [ "$ip_count" -gt 2 ]; then
            alert "mac $mac claims $ip_count ips: ${mac_ips[$mac]}"
        fi
    done

    sleep "$interval"
done
