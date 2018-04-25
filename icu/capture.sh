#!/bin/bash
# packet capture and analysis

if ! command -v tcpdump &>/dev/null; then
    echo "tcpdump not found"
    exit 1
fi

show_usage() {
    echo "usage: ./capture.sh [-i iface] [-c count] [-f filter] [-w file] [-r pcap] [-s] [-t]"
    echo "  -s  protocol summary"
    echo "  -t  top talkers"
    echo "  -r  read from pcap file instead of live capture"
}

iface=""
count=0
filter=""
outfile=""
readfile=""
summary=0
talkers=0

while getopts "i:c:f:w:r:sth" opt; do
    case $opt in
        i) iface="$OPTARG" ;;
        c) count="$OPTARG" ;;
        f) filter="$OPTARG" ;;
        w) outfile="$OPTARG" ;;
        r) readfile="$OPTARG" ;;
        s) summary=1 ;;
        t) talkers=1 ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

analyze() {
    local src="$1"
    local total=$(wc -l < "$src")
    echo "analyzed $total packets"
    echo ""

    if [ $summary -eq 1 ]; then
        echo "=== protocols ==="
        for proto in TCP UDP ICMP ARP DNS DHCP; do
            c=$(grep -ci "$proto" "$src" 2>/dev/null || echo 0)
            [ "$c" -gt 0 ] && printf "  %-8s %5d (%d%%)\n" "$proto" "$c" $((c * 100 / total))
        done
        echo ""
    fi

    if [ $talkers -eq 1 ]; then
        echo "=== top sources ==="
        grep -oP '(\d+\.\d+\.\d+\.\d+)(?=\.\d+\s)' "$src" | sort | uniq -c | sort -rn | head -10 | while read -r cnt ip; do
            printf "  %-16s %5d packets\n" "$ip" "$cnt"
        done
        echo ""

        echo "=== top destinations ==="
        grep -oP '(?<=\s>\s)(\d+\.\d+\.\d+\.\d+)' "$src" | sort | uniq -c | sort -rn | head -10 | while read -r cnt ip; do
            printf "  %-16s %5d packets\n" "$ip" "$cnt"
        done
        echo ""
    fi
}

if [ -n "$readfile" ]; then
    if [ ! -f "$readfile" ]; then
        echo "file not found: $readfile"
        exit 1
    fi
    tmpfile=$(mktemp)
    trap "rm -f $tmpfile" EXIT
    tcpdump -n -q -r "$readfile" $filter 2>/dev/null > "$tmpfile"
    analyze "$tmpfile"
elif [ $summary -eq 1 ] || [ $talkers -eq 1 ]; then
    tmpfile=$(mktemp)
    trap "rm -f $tmpfile" EXIT

    cmd="tcpdump -n -q"
    [ -n "$iface" ] && cmd="$cmd -i $iface"
    [ "$count" -gt 0 ] && cmd="$cmd -c $count"
    [ -n "$filter" ] && cmd="$cmd $filter"

    echo "capturing... (ctrl+c to stop)"
    eval "$cmd" 2>/dev/null > "$tmpfile"
    analyze "$tmpfile"
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
