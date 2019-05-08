#!/bin/bash
# dynamic firewall rule management

show_usage() {
    echo "usage: ./firewall.sh [-b blocklist] [-w whitelist] [-l logfile] [-m monitor_log] [-t threshold]"
    echo "  -b  load ip blocklist file"
    echo "  -w  whitelist file (never block these)"
    echo "  -l  log actions to file"
    echo "  -m  monitor log file for failed auth (fail2ban style)"
    echo "  -t  failed attempts threshold (default: 5)"
}

blocklist=""
whitelist=""
logfile=""
monitor_log=""
threshold=5
blocked=0

while getopts "b:w:l:m:t:h" opt; do
    case $opt in
        b) blocklist="$OPTARG" ;;
        w) whitelist="$OPTARG" ;;
        l) logfile="$OPTARG" ;;
        m) monitor_log="$OPTARG" ;;
        t) threshold="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "requires root"
    exit 1
fi

log_msg() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$msg"
    [ -n "$logfile" ] && echo "$msg" >> "$logfile"
}

is_whitelisted() {
    local ip="$1"
    [ -z "$whitelist" ] && return 1
    [ ! -f "$whitelist" ] && return 1
    grep -q "^$ip$" "$whitelist" 2>/dev/null
}

block_ip() {
    local ip="$1"
    local reason="$2"
    if is_whitelisted "$ip"; then
        log_msg "skipping whitelisted $ip"
        return
    fi
    if ! iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        iptables -A INPUT -s "$ip" -j DROP
        blocked=$((blocked + 1))
        log_msg "blocked $ip ($reason)"
    fi
}

unblock_ip() {
    local ip="$1"
    iptables -D INPUT -s "$ip" -j DROP 2>/dev/null && log_msg "unblocked $ip"
}

# load blocklist
if [ -n "$blocklist" ] && [ -f "$blocklist" ]; then
    log_msg "loading blocklist from $blocklist"
    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        [[ "$ip" =~ ^# ]] && continue
        block_ip "$ip" "blocklist"
    done < "$blocklist"
    log_msg "loaded $blocked ips from blocklist"
fi

# monitor log for failed auth
if [ -n "$monitor_log" ]; then
    if [ ! -f "$monitor_log" ]; then
        echo "log file not found: $monitor_log"
        exit 1
    fi

    log_msg "monitoring $monitor_log for failed auth (threshold: $threshold)"
    declare -A fail_count

    tail -F "$monitor_log" 2>/dev/null | while read -r line; do
        # match common auth failure patterns
        ip=""
        if echo "$line" | grep -qi "failed password"; then
            ip=$(echo "$line" | grep -oP 'from \K\d+\.\d+\.\d+\.\d+')
        elif echo "$line" | grep -qi "authentication failure"; then
            ip=$(echo "$line" | grep -oP 'rhost=\K\d+\.\d+\.\d+\.\d+')
        elif echo "$line" | grep -qi "invalid user"; then
            ip=$(echo "$line" | grep -oP 'from \K\d+\.\d+\.\d+\.\d+')
        fi

        [ -z "$ip" ] && continue

        fail_count["$ip"]=$(( ${fail_count[$ip]:-0} + 1 ))
        if [ "${fail_count[$ip]}" -ge "$threshold" ]; then
            block_ip "$ip" "failed auth x${fail_count[$ip]}"
            fail_count["$ip"]=0
        fi
    done
else
    log_msg "$blocked ips blocked total"
fi
