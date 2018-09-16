#!/bin/bash
# tcp/udp port scanner

show_usage() {
    echo "usage: ./portscan.sh [-c] [-u] [-t threads] [-o outfile] [-T top_n] <host> [start] [end]"
    echo "  -c  common ports only (20)"
    echo "  -u  udp scan (slower)"
    echo "  -t  threads (default 50)"
    echo "  -o  output file"
    echo "  -T  top N ports (100, 1000)"
}

common_ports="21 22 23 25 53 80 110 111 135 139 143 443 445 993 995 1723 3306 3389 5900 8080"
top_100="7 9 13 21 22 23 25 26 37 53 79 80 81 88 106 110 111 113 119 135 139 143 144 179 199 389 427 443 444 445 465 513 514 515 543 544 548 554 587 631 646 873 990 993 995 1025 1026 1027 1028 1029 1110 1433 1720 1723 1755 1900 2000 2001 2049 2121 2717 3000 3128 3306 3389 3986 4899 5000 5009 5051 5060 5101 5190 5357 5432 5631 5666 5800 5900 6000 6001 6646 7070 8000 8008 8009 8080 8081 8443 8888 9100 9999 10000 32768 49152 49153 49154 49155 49156 49157"

get_service() {
    local port="$1"
    local proto="$2"
    grep -w "$port/$proto" /etc/services 2>/dev/null | head -1 | awk '{print $1}'
}

check_tcp() {
    local host="$1"
    local port="$2"
    timeout 1 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null && echo "$port"
}

check_udp() {
    local host="$1"
    local port="$2"
    timeout 2 bash -c "echo > /dev/udp/$host/$port" 2>/dev/null && echo "$port"
}

export -f check_tcp check_udp get_service

scan_common=0
udp=0
threads=50
outfile=""
top_mode=""
while getopts "cut:o:T:h" opt; do
    case $opt in
        c) scan_common=1 ;;
        u) udp=1 ;;
        t) threads="$OPTARG" ;;
        o) outfile="$OPTARG" ;;
        T) top_mode="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

host="$1"
[ -z "$host" ] && { show_usage; exit 1; }

proto="tcp"
[ $udp -eq 1 ] && proto="udp"

if [ -n "$top_mode" ]; then
    case "$top_mode" in
        100) ports="$top_100" ;;
        1000) ports=$(seq 1 1000) ;;
        *) ports=$(seq 1 "$top_mode") ;;
    esac
    total=$(echo "$ports" | wc -w)
elif [ $scan_common -eq 1 ]; then
    ports="$common_ports"
    total=20
else
    start=${2:-1}
    end=${3:-1024}
    ports=$(seq "$start" "$end")
    total=$((end - start + 1))
fi

echo "scanning $host ($proto, $total ports, $threads threads)..."

start_time=$(date +%s)

printf "\n%-10s %-8s %s\n" "port" "state" "service"
echo "--------------------------------"

checker="check_tcp"
[ $udp -eq 1 ] && checker="check_udp"

results=$(echo "$ports" | tr ' ' '\n' | xargs -I{} -P "$threads" bash -c "$checker $host {}")
open_ports=$(echo "$results" | sort -n | grep -v "^$")

output=""
if [ -n "$open_ports" ]; then
    while read -r p; do
        svc=$(get_service "$p" "$proto")
        [ -z "$svc" ] && svc="unknown"
        line=$(printf "%-10s %-8s %s" "$p/$proto" "open" "$svc")
        echo "$line"
        output="$output$line\n"
    done <<< "$open_ports"
fi

end_time=$(date +%s)
elapsed=$((end_time - start_time))
count=$(echo "$open_ports" | grep -c "\S" 2>/dev/null || echo 0)

echo ""
echo "$count open ports on $host (scanned $total in ${elapsed}s)"

if [ -n "$outfile" ]; then
    {
        printf "%-10s %-8s %s\n" "port" "state" "service"
        echo "--------------------------------"
        echo -e "$output"
        echo "$count open ports on $host"
    } > "$outfile"
    echo "saved to $outfile"
fi
