#!/bin/bash
# packet capture and analysis

if ! command -v tcpdump &>/dev/null; then
    echo "tcpdump not found"
    exit 1
fi

show_usage() {
    echo "usage: ./capture.sh [-i iface] [-c count] [-f filter] [-w file] [-s] [-t]"
    echo "  -s  protocol summary"
    echo "  -t  top talkers (top 10 source ips)"
}

iface=""
count=0
filter=""
outfile=""
summary=0
talkers=0

while getopts "i:c:f:w:sth" opt; do
    case $opt in
        i) iface="$OPTARG" ;;
        c) count="$OPTARG" ;;
        f) filter="$OPTARG" ;;
        w) outfile="$OPTARG" ;;
        s) summary=1 ;;
        t) talkers=1 ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

build_cmd() {
    local cmd="tcpdump -n -q"
    [ -n "$iface" ] && cmd="$cmd -i $iface"
    [ "$count" -gt 0 ] && cmd="$cmd -c $count"
    [ -n "$filter" ] && cmd="$cmd $filter"
    echo "$cmd"
}

if [ $summary -eq 1 ] || [ $talkers -eq 1 ]; then
    tmpfile=$(mktemp)
    trap "rm -f $tmpfile" EXIT

    cmd=$(build_cmd)
    echo "capturing... (ctrl+c to stop)"
    eval "$cmd" 2>/dev/null > "$tmpfile"

    total=$(wc -l < "$tmpfile")
    echo ""
    echo "captured $total packets"
    echo ""

    if [ $summary -eq 1 ]; then
        echo "=== protocols ==="
        for proto in TCP UDP ICMP ARP DNS; do
            c=$(grep -ci "$proto" "$tmpfile" 2>/dev/null || echo 0)
            [ "$c" -gt 0 ] && printf "  %-8s %s\n" "$proto" "$c"
        done
        echo ""
    fi

    if [ $talkers -eq 1 ]; then
        echo "=== top talkers ==="
        grep -oP '\d+\.\d+\.\d+\.\d+' "$tmpfile" | sort | uniq -c | sort -rn | head -10 | while read -r cnt ip; do
            printf "  %-16s %s packets\n" "$ip" "$cnt"
        done
        echo ""
    fi

    [ -n "$outfile" ] && cp "$tmpfile" "$outfile" && echo "saved to $outfile"
else
    cmd="tcpdump -n"
    [ -n "$iface" ] && cmd="$cmd -i $iface"
    [ -n "$outfile" ] && cmd="$cmd -w $outfile"
    [ "$count" -gt 0 ] && cmd="$cmd -c $count"
    [ -n "$filter" ] && cmd="$cmd $filter"
    echo "running: $cmd"
    eval "$cmd"
fi
