#!/bin/bash
# scan a range of ports on a host

if [ -z "$1" ]; then
    echo "usage: ./portscan.sh <host> [start_port] [end_port]"
    exit 1
fi

host="$1"
start=${2:-1}
end=${3:-1024}

echo "scanning $host ports $start-$end..."
echo ""

for port in $(seq "$start" "$end"); do
    (echo > /dev/tcp/"$host"/"$port") 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "$port open"
    fi
done
