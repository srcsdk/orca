#!/bin/bash
# parse tcpdump output into flow summaries

show_usage() {
    echo "usage: ./flow.sh [-i iface] [-c count] [-r pcap]"
}

iface=""
count=500
readfile=""

while getopts "i:c:r:h" opt; do
    case $opt in
        i) iface="$OPTARG" ;;
        c) count="$OPTARG" ;;
        r) readfile="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

if [ -n "$readfile" ]; then
    data=$(tcpdump -n -q -r "$readfile" 2>/dev/null)
else
    cmd="tcpdump -n -q -c $count"
    [ -n "$iface" ] && cmd="$cmd -i $iface"
    echo "capturing $count packets..."
    data=$(eval "$cmd" 2>/dev/null)
fi

echo ""
echo "=== flow summary ==="
echo ""
printf "%-22s %-22s %-6s %s\n" "source" "destination" "proto" "count"
echo "--------------------------------------------------------------"

echo "$data" | grep -oP '\d+\.\d+\.\d+\.\d+\.\d+ > \d+\.\d+\.\d+\.\d+\.\d+: \S+' | \
    awk '{
        src=$1; dst=$3; sub(/:$/,"",dst); proto=$4
        key=src" "dst" "proto
        flows[key]++
    }
    END {
        for(k in flows) printf "%-22s %-22s %-6s %d\n", k, flows[k]
    }' | sort -t' ' -k4 -rn | head -20
