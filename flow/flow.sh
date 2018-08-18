#!/bin/bash
# network flow analysis

show_usage() {
    echo "usage: ./flow.sh [-i iface] [-c count] [-r pcap] [-t top_n] [-o outfile]"
    echo "  -t  top N flows (default 20)"
    echo "  -o  save report to file"
}

iface=""
count=1000
readfile=""
top_n=20
outfile=""

while getopts "i:c:r:t:o:h" opt; do
    case $opt in
        i) iface="$OPTARG" ;;
        c) count="$OPTARG" ;;
        r) readfile="$OPTARG" ;;
        t) top_n="$OPTARG" ;;
        o) outfile="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

out() {
    echo "$1"
    [ -n "$outfile" ] && echo "$1" >> "$outfile"
}

[ -n "$outfile" ] && > "$outfile"

tmpfile=$(mktemp)
trap "rm -f $tmpfile" EXIT

if [ -n "$readfile" ]; then
    [ ! -f "$readfile" ] && { echo "file not found: $readfile"; exit 1; }
    tcpdump -nn -q -r "$readfile" 2>/dev/null > "$tmpfile"
else
    cmd="tcpdump -nn -q -c $count"
    [ -n "$iface" ] && cmd="$cmd -i $iface"
    echo "capturing $count packets..." >&2
    eval "$cmd" 2>/dev/null > "$tmpfile"
fi

total=$(wc -l < "$tmpfile")
[ "$total" -eq 0 ] && { echo "no packets captured"; exit 1; }

first_ts=$(head -1 "$tmpfile" | awk '{print $1}')
last_ts=$(tail -1 "$tmpfile" | awk '{print $1}')

out ""
out "=== flow analysis ==="
out "packets: $total"
out "time range: $first_ts - $last_ts"
out ""

out "--- conversations (top $top_n) ---"
out "$(printf '%-22s %-22s %-8s' 'source' 'destination' 'packets')"
out "$(printf '%56s' '' | tr ' ' '-')"

awk '
    {
        n=split($0, a, " ")
        src=""; dst=""
        for(i=1; i<=n; i++) {
            if(a[i] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) {
                if(!src) src=a[i]
                else { dst=a[i]; break }
            }
        }
        if(src && dst) {
            sub(/:$/, "", src)
            sub(/:$/, "", dst)
            if(src > dst) { t=src; src=dst; dst=t }
            convos[src" "dst]++
        }
    }
    END { for(k in convos) print convos[k], k }
' "$tmpfile" | sort -rn | head -"$top_n" | while read -r cnt src dst; do
    out "$(printf '%-22s %-22s %-8d' "$src" "$dst" "$cnt")"
done

out ""
out "--- protocols ---"
tcp_c=$(grep -ci "tcp" "$tmpfile" 2>/dev/null || echo 0)
udp_c=$(grep -ci "udp" "$tmpfile" 2>/dev/null || echo 0)
icmp_c=$(grep -ci "icmp" "$tmpfile" 2>/dev/null || echo 0)
arp_c=$(grep -ci "arp" "$tmpfile" 2>/dev/null || echo 0)

for proto in "tcp:$tcp_c" "udp:$udp_c" "icmp:$icmp_c" "arp:$arp_c"; do
    name="${proto%%:*}"
    val="${proto##*:}"
    [ "$val" -gt 0 ] && out "$(printf '  %-8s %6d (%d%%)' "$name" "$val" $((val * 100 / total)))"
done

out ""
out "--- top sources ---"
grep -oP '\d+\.\d+\.\d+\.\d+' "$tmpfile" | sort | uniq -c | sort -rn | head -10 | while read -r cnt ip; do
    out "$(printf '  %-20s %d' "$ip" "$cnt")"
done

out ""
out "--- unique ips ---"
unique=$(grep -oP '\d+\.\d+\.\d+\.\d+' "$tmpfile" | sort -u | wc -l)
out "  $unique unique addresses"
