#!/bin/bash
# grab banners from services

if [ -z "$1" ]; then
    echo "usage: ./grab.sh <host> <port> [port] [port]..."
    exit 1
fi

host="$1"
shift

grab_banner() {
    local host="$1"
    local port="$2"
    local banner=""

    if [ "$port" -eq 80 ] || [ "$port" -eq 8080 ]; then
        banner=$(echo -e "HEAD / HTTP/1.0\r\nHost: $host\r\n\r\n" | nc -w 3 "$host" "$port" 2>/dev/null | head -10)
    elif [ "$port" -eq 443 ]; then
        banner=$(echo -e "HEAD / HTTP/1.0\r\nHost: $host\r\n\r\n" | openssl s_client -connect "$host:$port" -quiet 2>/dev/null | head -10)
    else
        banner=$(echo "" | nc -w 3 "$host" "$port" 2>/dev/null | head -5)
    fi

    if [ -n "$banner" ]; then
        echo "[$host:$port]"
        echo "$banner"
        echo ""
    else
        echo "[$host:$port] no banner"
        echo ""
    fi
}

for port in "$@"; do
    grab_banner "$host" "$port"
done
