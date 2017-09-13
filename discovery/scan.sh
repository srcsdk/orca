#!/bin/bash
# ping sweep with mac address lookup

if [ -z "$1" ]; then
    echo "usage: ./scan.sh <base_ip>"
    echo "example: ./scan.sh 192.168.1"
    exit 1
fi

count=0
for i in $(seq 1 254); do
    ip="$1.$i"
    ping -c 1 -W 1 "$ip" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        mac=$(arp -n "$ip" 2>/dev/null | grep "$ip" | awk '{print $3}')
        if [ -n "$mac" ] && [ "$mac" != "(incomplete)" ]; then
            echo "$ip  $mac"
        else
            echo "$ip  (no mac)"
        fi
        count=$((count + 1))
    fi
done

echo ""
echo "$count hosts found"
