#!/bin/bash
# ping sweep with mac address lookup

show_usage() {
    echo "usage: ./scan.sh [subnet]"
    echo "if no subnet given, detects from default interface"
}

get_subnet() {
    ip route | grep default | head -1 | awk '{print $3}' | sed 's/\.[0-9]*$//';
}

subnet="$1"
if [ -z "$subnet" ]; then
    subnet=$(get_subnet)
    if [ -z "$subnet" ]; then
        echo "could not detect subnet"
        show_usage
        exit 1
    fi
    echo "detected subnet: $subnet.0/24"
fi

echo ""
count=0
for i in $(seq 1 254); do
    ip="$subnet.$i"
    ping -c 1 -W 1 "$ip" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        mac=$(arp -n "$ip" 2>/dev/null | grep "$ip" | awk '{print $3}')
        if [ -n "$mac" ] && [ "$mac" != "(incomplete)" ]; then
            printf "%-16s %s\n" "$ip" "$mac"
        else
            printf "%-16s %s\n" "$ip" "(unknown)"
        fi
        count=$((count + 1))
    fi
done

echo ""
echo "$count hosts found on $subnet.0/24"
