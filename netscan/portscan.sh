#!/bin/bash
# scan ports on a host with timeout

show_usage() {
    echo "usage: ./portscan.sh [-c] <host> [start_port] [end_port]"
    echo "  -c  scan common ports only"
}

common_ports="21 22 23 25 53 80 110 111 135 139 143 443 445 993 995 1723 3306 3389 5900 8080"

scan_common=0
while getopts "ch" opt; do
    case $opt in
        c) scan_common=1 ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

host="$1"
if [ -z "$host" ]; then
    show_usage
    exit 1
fi

check_port() {
    local h="$1"
    local p="$2"
    timeout 1 bash -c "echo > /dev/tcp/$h/$p" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "$p open"
    fi
}

if [ $scan_common -eq 1 ]; then
    echo "scanning $host (common ports)..."
    ports="$common_ports"
else
    start=${2:-1}
    end=${3:-1024}
    echo "scanning $host ports $start-$end..."
    ports=$(seq "$start" "$end")
fi

echo ""
for port in $ports; do
    check_port "$host" "$port"
done
