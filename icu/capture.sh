#!/bin/bash
# packet capture with live summary

if ! command -v tcpdump &>/dev/null; then
    echo "tcpdump not found"
    exit 1
fi

show_usage() {
    echo "usage: ./capture.sh [-i iface] [-c count] [-f filter] [-w file] [-s]"
    echo "  -s  summary mode (show protocol counts)"
}

iface=""
count=0
filter=""
outfile=""
summary=0

while getopts "i:c:f:w:sh" opt; do
    case $opt in
        i) iface="$OPTARG" ;;
        c) count="$OPTARG" ;;
        f) filter="$OPTARG" ;;
        w) outfile="$OPTARG" ;;
        s) summary=1 ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

if [ $summary -eq 1 ]; then
    tmpfile=$(mktemp)
    trap "rm -f $tmpfile" EXIT

    cmd="tcpdump -n -q"
    [ -n "$iface" ] && cmd="$cmd -i $iface"
    [ "$count" -gt 0 ] && cmd="$cmd -c $count"
    [ -n "$filter" ] && cmd="$cmd $filter"

    echo "capturing... (ctrl+c for summary)"
    eval "$cmd" 2>/dev/null | tee "$tmpfile" | while read -r line; do
        echo "$line"
    done

    echo ""
    echo "=== summary ==="
    tcp=$(grep -c "TCP" "$tmpfile" 2>/dev/null || echo 0)
    udp=$(grep -c "UDP" "$tmpfile" 2>/dev/null || echo 0)
    icmp=$(grep -c "ICMP" "$tmpfile" 2>/dev/null || echo 0)
    arp_c=$(grep -c "ARP" "$tmpfile" 2>/dev/null || echo 0)
    total=$(wc -l < "$tmpfile")
    echo "total: $total"
    echo "tcp: $tcp"
    echo "udp: $udp"
    echo "icmp: $icmp"
    echo "arp: $arp_c"
else
    cmd="tcpdump -n"
    [ -n "$iface" ] && cmd="$cmd -i $iface"
    [ -n "$outfile" ] && cmd="$cmd -w $outfile"
    [ "$count" -gt 0 ] && cmd="$cmd -c $count"
    [ -n "$filter" ] && cmd="$cmd $filter"

    echo "running: $cmd"
    eval "$cmd"
fi
