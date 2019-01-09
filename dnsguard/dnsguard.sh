#!/bin/bash
# dns monitoring and anomaly detection

show_usage() {
    echo "usage: ./dnsguard.sh [-i iface] [-t threshold] [-l logfile] [-e entropy_min]"
    echo "  -i  interface (default: eth0)"
    echo "  -t  query rate threshold per source (default: 50)"
    echo "  -l  log file"
    echo "  -e  entropy threshold for dga detection (default: 3.5)"
}

iface="eth0"
threshold=50
logfile=""
entropy_min="3.5"
total_queries=0
total_alerts=0

while getopts "i:t:l:e:h" opt; do
    case $opt in
        i) iface="$OPTARG" ;;
        t) threshold="$OPTARG" ;;
        l) logfile="$OPTARG" ;;
        e) entropy_min="$OPTARG" ;;
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

calc_entropy() {
    local str="$1"
    local len=${#str}
    [ "$len" -eq 0 ] && echo "0" && return
    echo "$str" | fold -w1 | sort | uniq -c | awk -v len="$len" '
    BEGIN { ent = 0 }
    {
        p = $1 / len
        if (p > 0) ent -= p * log(p) / log(2)
    }
    END { printf "%.2f", ent }'
}

declare -A query_count
declare -A first_seen

log_msg "dns monitor started on $iface"
log_msg "rate threshold: $threshold queries/min, entropy threshold: $entropy_min"

trap 'echo ""; echo "total queries: $total_queries"; echo "total alerts: $total_alerts"; exit 0' INT TERM

tcpdump -i "$iface" -n -l port 53 2>/dev/null | while read -r line; do
    # extract query domain from dns request lines
    domain=$(echo "$line" | grep -oP 'A\? \K[^ ]+' | sed 's/\.$//')
    [ -z "$domain" ] && continue

    src_ip=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
    [ -z "$src_ip" ] && continue

    total_queries=$((total_queries + 1))
    now=$(date +%s)

    # track query rate per source
    if [ -z "${first_seen[$src_ip]}" ] || [ $((now - ${first_seen[$src_ip]})) -gt 60 ]; then
        query_count["$src_ip"]=0
        first_seen["$src_ip"]=$now
    fi
    query_count["$src_ip"]=$((${query_count[$src_ip]} + 1))

    # check query rate
    if [ "${query_count[$src_ip]}" -ge "$threshold" ]; then
        log_msg "[WARNING] high query rate from $src_ip: ${query_count[$src_ip]} queries/min"
        total_alerts=$((total_alerts + 1))
        query_count["$src_ip"]=0
        first_seen["$src_ip"]=$now
    fi

    # check subdomain entropy for dga detection
    subdomain=$(echo "$domain" | awk -F. '{if(NF>2) print $1}')
    if [ -n "$subdomain" ] && [ ${#subdomain} -gt 8 ]; then
        ent=$(calc_entropy "$subdomain")
        high=$(awk "BEGIN {print ($ent >= $entropy_min) ? 1 : 0}")
        if [ "$high" -eq 1 ]; then
            log_msg "[ALERT] high entropy subdomain: $domain (entropy: $ent) from $src_ip"
            total_alerts=$((total_alerts + 1))
        fi
    fi

    # check for unusually long subdomains (dns tunneling indicator)
    if [ ${#domain} -gt 60 ]; then
        log_msg "[ALERT] possible dns tunnel: $domain (length: ${#domain}) from $src_ip"
        total_alerts=$((total_alerts + 1))
    fi
done
