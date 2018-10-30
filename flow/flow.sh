#!/bin/bash
# network flow analysis

show_usage() {
    echo "usage: ./flow.sh [-i iface] [-c count] [-r pcap] [-t top_n] [-o outfile] [-p]"
    echo "  -t  top N (default 20)"
    echo "  -o  save report"
    echo "  -p  include port analysis"
}

iface=""
count=1000
readfile=""
top_n=20
outfile=""
ports=0

while getopts "i:c:r:t:o:ph" opt; do
    case $opt in
        i) iface="$OPTARG" ;;
        c) count="$OPTARG" ;;
        r) readfile="$OPTARG" ;;
        t) top_n="$OPTARG" ;;
        o) outfile="$OPTARG" ;;
        p) ports=1 ;;
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

out "=== flow analysis ($total packets) ==="
out ""

out "--- conversations (top $top_n) ---"
out "$(printf '%-22s %-22s %s' 'source' 'destination' 'packets')"
out "$(printf '%54s' '' | tr ' ' '-')"

awk '
    {
        src=""; dst=""
        for(i=1; i<=NF; i++) {
            if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) {
                if(!src) src=$i; else { dst=$i; break }
            }
        }
        if(src && dst) {
            sub(/:$/, "", src); sub(/:$/, "", dst)
            if(src > dst) { t=src; src=dst; dst=t }
            c[src" "dst]++
        }
    }
    END { for(k in c) print c[k], k }
' "$tmpfile" | sort -rn | head -"$top_n" | while read -r cnt src dst; do
    out "$(printf '%-22s %-22s %d' "$src" "$dst" "$cnt")"
done

out ""
out "--- protocols ---"
for proto in TCP UDP ICMP ARP DNS; do
    c=$(grep -ci "$proto" "$tmpfile" 2>/dev/null || echo 0)
    [ "$c" -gt 0 ] && out "$(printf '  %-8s %6d (%d%%)' "$proto" "$c" $((c * 100 / total)))"
done

if [ $ports -eq 1 ]; then
    out ""
    out "--- top destination ports ---"
    grep -oP '\.\d+:' "$tmpfile" | tr -d '.:' | sort | uniq -c | sort -rn | head -10 | while read -r cnt port; do
        svc=$(grep -w "$port/tcp" /etc/services 2>/dev/null | head -1 | awk '{print $1}')
        [ -z "$svc" ] && svc="-"
        out "$(printf '  %-8s %-12s %d' "$port" "$svc" "$cnt")"
    done
fi

out ""
out "--- top sources ---"
grep -oP '\d+\.\d+\.\d+\.\d+' "$tmpfile" | sort | uniq -c | sort -rn | head -10 | while read -r cnt ip; do
    out "$(printf '  %-20s %d' "$ip" "$cnt")"
done

unique=$(grep -oP '\d+\.\d+\.\d+\.\d+' "$tmpfile" | sort -u | wc -l)
out ""
out "$unique unique addresses observed"
