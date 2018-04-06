#!/bin/bash
# network flow analysis from packet captures

show_usage() {
    echo "usage: ./flow.sh [-i iface] [-c count] [-r pcap] [-t top_n]"
    echo "  -t  show top N flows (default 20)"
}

iface=""
count=1000
readfile=""
top_n=20

while getopts "i:c:r:t:h" opt; do
    case $opt in
        i) iface="$OPTARG" ;;
        c) count="$OPTARG" ;;
        r) readfile="$OPTARG" ;;
        t) top_n="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

capture() {
    if [ -n "$readfile" ]; then
        [ ! -f "$readfile" ] && { echo "file not found: $readfile"; exit 1; }
        tcpdump -n -q -r "$readfile" 2>/dev/null
    else
        local cmd="tcpdump -n -q -c $count"
        [ -n "$iface" ] && cmd="$cmd -i $iface"
        echo "capturing $count packets..." >&2
        eval "$cmd" 2>/dev/null
    fi
}

tmpfile=$(mktemp)
trap "rm -f $tmpfile" EXIT

capture > "$tmpfile"
total=$(wc -l < "$tmpfile")

echo ""
echo "=== flow analysis ($total packets) ==="

echo ""
echo "--- top $top_n flows by packet count ---"
printf "%-24s %-24s %-8s\n" "source" "destination" "packets"
echo "--------------------------------------------------------"

awk '
    /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {
        for(i=1;i<=NF;i++) {
            if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) {
                if(!src) src=$i
                else if($i != src) { dst=$i; break }
            }
        }
        if(src && dst) {
            sub(/:$/,"",dst)
            flows[src" "dst]++
        }
        src=""; dst=""
    }
    END {
        for(k in flows) print flows[k], k
    }
' "$tmpfile" | sort -rn | head -"$top_n" | while read -r cnt src dst; do
    printf "%-24s %-24s %-8d\n" "$src" "$dst" "$cnt"
done

echo ""
echo "--- protocol distribution ---"
tcp_c=$(grep -ci "tcp" "$tmpfile" || echo 0)
udp_c=$(grep -ci "udp" "$tmpfile" || echo 0)
icmp_c=$(grep -ci "icmp" "$tmpfile" || echo 0)
other=$((total - tcp_c - udp_c - icmp_c))

printf "  tcp:  %6d (%d%%)\n" "$tcp_c" $((tcp_c * 100 / (total + 1)))
printf "  udp:  %6d (%d%%)\n" "$udp_c" $((udp_c * 100 / (total + 1)))
printf "  icmp: %6d (%d%%)\n" "$icmp_c" $((icmp_c * 100 / (total + 1)))
printf "  other:%6d (%d%%)\n" "$other" $((other * 100 / (total + 1)))

echo ""
echo "--- top talkers ---"
printf "%-20s %s\n" "ip" "packets"
echo "-----------------------------"
grep -oP '\d+\.\d+\.\d+\.\d+' "$tmpfile" | sort | uniq -c | sort -rn | head -10 | while read -r cnt ip; do
    printf "%-20s %d\n" "$ip" "$cnt"
done
