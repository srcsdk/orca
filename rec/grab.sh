#!/bin/bash
# service banner grabber

show_usage() {
    echo "usage: ./grab.sh <host> <port> [port]..."
    echo "       ./grab.sh -f <netscan_output> <host>"
}

grab_banner() {
    local host="$1"
    local port="$2"
    local banner=""

    case "$port" in
        80|8080|8000|8888)
            banner=$(echo -e "HEAD / HTTP/1.0\r\nHost: $host\r\n\r\n" | nc -w 3 "$host" "$port" 2>/dev/null | head -10)
            ;;
        443|8443)
            banner=$(echo -e "HEAD / HTTP/1.0\r\nHost: $host\r\n\r\n" | timeout 5 openssl s_client -connect "$host:$port" -quiet 2>/dev/null | head -10)
            ;;
        25|587)
            banner=$(nc -w 3 "$host" "$port" 2>/dev/null | head -3)
            ;;
        *)
            banner=$(echo "" | nc -w 3 "$host" "$port" 2>/dev/null | head -5)
            ;;
    esac

    if [ -n "$banner" ]; then
        echo "[$host:$port]"
        echo "$banner"
    else
        echo "[$host:$port] no banner"
    fi
    echo ""
}

from_file=""
while getopts "f:h" opt; do
    case $opt in
        f) from_file="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

host="$1"
[ -z "$host" ] && { show_usage; exit 1; }
shift

if [ -n "$from_file" ]; then
    ports=$(grep "open" "$from_file" | awk -F/ '{print $1}' | tr -d ' ')
    for port in $ports; do
        grab_banner "$host" "$port"
    done
else
    for port in "$@"; do
        grab_banner "$host" "$port"
    done
fi
