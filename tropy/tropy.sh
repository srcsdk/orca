#!/bin/bash
# data loss prevention and exfiltration detection

show_usage() {
    echo "usage: ./tropy.sh [-i interface] [-m mode] [-t threshold] [-o output]"
    echo "  -i  network interface (default: eth0)"
    echo "  -m  mode: traffic|dns|patterns|all"
    echo "  -t  volume threshold in MB (default: 100)"
    echo "  -o  alert output file"
}

interface="eth0"
mode="all"
threshold_mb=100
output=""

while getopts "i:m:t:o:h" opt; do
    case $opt in
        i) interface="$OPTARG" ;;
        m) mode="$OPTARG" ;;
        t) threshold_mb="$OPTARG" ;;
        o) output="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

alert() {
    local severity="$1"
    local msg="$2"
    local now
    now=$(date "+%Y-%m-%dT%H:%M:%S")
    local line="[$now] [$severity] $msg"
    echo "$line"
    [[ -n "$output" ]] && echo "$line" >> "$output"
}

check_traffic_volume() {
    echo "[tropy] checking outbound traffic volume on $interface"

    if [[ ! -d "/sys/class/net/$interface" ]]; then
        echo "[warn] interface $interface not found, checking available"
        ls /sys/class/net/ 2>/dev/null
        return
    fi

    local tx_bytes
    tx_bytes=$(cat "/sys/class/net/$interface/statistics/tx_bytes" 2>/dev/null || echo "0")
    local tx_mb=$((tx_bytes / 1048576))

    echo "[info] total tx: ${tx_mb}MB on $interface"

    if [[ $tx_mb -gt $((threshold_mb * 10)) ]]; then
        alert "high" "unusually high outbound volume: ${tx_mb}MB on $interface"
    fi

    # check for large active connections
    if command -v ss &>/dev/null; then
        echo ""
        echo "[tropy] top outbound connections by state:"
        ss -tn state established 2>/dev/null | awk 'NR>1 {print $4}' | \
            cut -d: -f1 | sort | uniq -c | sort -rn | head -10

        local ext_conns
        ext_conns=$(ss -tn state established 2>/dev/null | awk 'NR>1' | wc -l)
        if [[ $ext_conns -gt 100 ]]; then
            alert "medium" "high number of established connections: $ext_conns"
        fi
    fi
}

check_dns_tunneling() {
    echo ""
    echo "[tropy] analyzing dns traffic for tunneling indicators"

    if ! command -v tcpdump &>/dev/null; then
        echo "[warn] tcpdump not available for dns capture"
        return
    fi

    local capture_file
    capture_file=$(mktemp /tmp/tropy_dns_XXXXXX.pcap)

    echo "[info] capturing dns traffic for 10 seconds..."
    timeout 10 tcpdump -i "$interface" -w "$capture_file" port 53 2>/dev/null &
    local cap_pid=$!
    sleep 10
    kill $cap_pid 2>/dev/null
    wait $cap_pid 2>/dev/null

    if [[ -s "$capture_file" ]]; then
        local query_count
        query_count=$(tcpdump -r "$capture_file" 2>/dev/null | wc -l)
        echo "[info] dns packets captured: $query_count"

        if [[ $query_count -gt 100 ]]; then
            alert "medium" "high dns query volume: $query_count queries in 10s"
        fi

        # check for long subdomain queries (tunneling indicator)
        tcpdump -r "$capture_file" -nn 2>/dev/null | grep -oP 'A\? \S+' | while read -r query; do
            local domain
            domain=$(echo "$query" | awk '{print $2}')
            local labels
            labels=$(echo "$domain" | tr '.' '\n' | head -1)
            if [[ ${#labels} -gt 30 ]]; then
                alert "high" "possible dns tunnel: long subdomain label in $domain"
            fi
        done
    fi

    rm -f "$capture_file"
}

check_encoded_patterns() {
    echo ""
    echo "[tropy] scanning for encoded data in recent connections"

    # check for base64 patterns in process command lines
    local b64_pattern='[A-Za-z0-9+/]{40,}={0,2}'

    if [[ -d /proc ]]; then
        local suspicious=0
        for pid_dir in /proc/[0-9]*; do
            local cmdline
            cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)
            if echo "$cmdline" | grep -qP "$b64_pattern"; then
                local pid
                pid=$(basename "$pid_dir")
                local name
                name=$(cat "$pid_dir/comm" 2>/dev/null)
                alert "medium" "base64 data in process args: pid=$pid name=$name"
                ((suspicious++))
            fi
        done
        echo "[info] processes with encoded args: $suspicious"
    fi

    # check for common sensitive data patterns in recent logs
    if [[ -f /var/log/syslog ]]; then
        local cc_pattern='[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}'
        local matches
        matches=$(tail -1000 /var/log/syslog 2>/dev/null | grep -cP "$cc_pattern" || echo "0")
        if [[ $matches -gt 0 ]]; then
            alert "high" "possible credit card pattern in syslog: $matches matches"
        fi
    fi
}

echo "[tropy] data loss prevention monitor"
echo "[tropy] interface: $interface, threshold: ${threshold_mb}MB"
echo ""

case "$mode" in
    traffic)  check_traffic_volume ;;
    dns)      check_dns_tunneling ;;
    patterns) check_encoded_patterns ;;
    all)
        check_traffic_volume
        check_dns_tunneling
        check_encoded_patterns
        ;;
    *)
        show_usage
        exit 1
        ;;
esac

echo ""
echo "[tropy] scan complete"
