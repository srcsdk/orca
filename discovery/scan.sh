#!/bin/bash
# ping every address in a subnet

if [ -z "$1" ]; then
    echo "usage: ./scan.sh <base_ip>"
    echo "example: ./scan.sh 192.168.1"
    exit 1
fi

count=0
for i in $(seq 1 254); do
    ping -c 1 -W 1 "$1.$i" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "$1.$i is up"
        count=$((count + 1))
    fi
done

echo ""
echo "$count hosts found"
