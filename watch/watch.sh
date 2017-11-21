#!/bin/bash
# watch arp table for changes

echo "monitoring arp table... (ctrl+c to stop)"
echo ""

prev=$(arp -n 2>/dev/null)

while true; do
    current=$(arp -n 2>/dev/null)
    diff <(echo "$prev") <(echo "$current") | grep "^[<>]" | while read -r line; do
        echo "$(date '+%H:%M:%S') change: $line"
    done
    prev="$current"
    sleep 5
done
