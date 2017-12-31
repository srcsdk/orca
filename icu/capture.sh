#!/bin/bash
# simple packet capture wrapper around tcpdump

if ! command -v tcpdump &>/dev/null; then
    echo "tcpdump not found"
    exit 1
fi

show_usage() {
    echo "usage: ./capture.sh [-i interface] [-c count] [-f filter] [-w file]"
}

iface=""
count=100
filter=""
outfile=""

while getopts "i:c:f:w:h" opt; do
    case $opt in
        i) iface="$OPTARG" ;;
        c) count="$OPTARG" ;;
        f) filter="$OPTARG" ;;
        w) outfile="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

cmd="tcpdump"
[ -n "$iface" ] && cmd="$cmd -i $iface"
[ -n "$outfile" ] && cmd="$cmd -w $outfile"
cmd="$cmd -c $count"
[ -n "$filter" ] && cmd="$cmd $filter"

echo "running: $cmd"
eval "$cmd"
