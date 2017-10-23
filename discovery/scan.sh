#!/bin/bash
# network host discovery via ping sweep

show_usage() {
    echo "usage: ./scan.sh [-o outfile] [subnet]"
    echo "if no subnet given, detects from default interface"
}

get_subnet() {
    ip route | grep default | head -1 | awk '{print $3}' | sed 's/\.[0-9]*$//';
}

outfile=""
while getopts "o:h" opt; do
    case $opt in
        o) outfile="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

subnet="$1"
if [ -z "$subnet" ]; then
    subnet=$(get_subnet)
    if [ -z "$subnet" ]; then
        echo "could not detect subnet"
        show_usage
        exit 1
    fi
fi

echo "scanning $subnet.0/24..."
echo ""

output=""
count=0
for i in $(seq 1 254); do
    ip="$subnet.$i"
    ping -c 1 -W 1 "$ip" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        mac=$(arp -n "$ip" 2>/dev/null | grep "$ip" | awk '{print $3}')
        [ -z "$mac" ] || [ "$mac" = "(incomplete)" ] && mac="unknown"
        line=$(printf "%-16s %s" "$ip" "$mac")
        echo "$line"
        output="$output$line\n"
        count=$((count + 1))
    fi
done

echo ""
echo "$count hosts found"

if [ -n "$outfile" ]; then
    echo -e "$output" > "$outfile"
    echo "saved to $outfile"
fi
