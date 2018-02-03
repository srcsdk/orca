#!/bin/bash
# tcp/udp port scanner

show_usage() {
    echo "usage: ./portscan.sh [-c] [-u] [-t threads] [-o outfile] <host> [start] [end]"
    echo "  -c  common ports only"
    echo "  -u  udp scan (requires root, slower)"
    echo "  -t  parallel threads (default 50)"
    echo "  -o  output file"
}

common_ports="21 22 23 25 53 80 110 111 135 139 143 443 445 993 995 1723 3306 3389 5900 8080"

get_service() {
    local port="$1"
    local proto="$2"
    local svc=$(grep -w "$port/$proto" /etc/services 2>/dev/null | head -1 | awk '{print $1}')
    [ -z "$svc" ] && svc="unknown"
    echo "$svc"
}

check_tcp() {
    local host="$1"
    local port="$2"
    timeout 1 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null
    [ $? -eq 0 ] && echo "$port"
}

check_udp() {
    local host="$1"
    local port="$2"
    timeout 2 bash -c "echo > /dev/udp/$host/$port" 2>/dev/null
    [ $? -eq 0 ] && echo "$port"
}

export -f check_tcp check_udp

scan_common=0
udp=0
threads=50
outfile=""
while getopts "cut:o:h" opt; do
    case $opt in
        c) scan_common=1 ;;
        u) udp=1 ;;
        t) threads="$OPTARG" ;;
        o) outfile="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

host="$1"
if [ -z "$host" ]; then
    show_usage
    exit 1
fi

proto="tcp"
[ $udp -eq 1 ] && proto="udp"

if [ $scan_common -eq 1 ]; then
    echo "scanning $host ($proto, common ports)..."
    ports="$common_ports"
else
    start=${2:-1}
    end=${3:-1024}
    echo "scanning $host ($proto, ports $start-$end)..."
    ports=$(seq "$start" "$end")
fi

printf "\n%-8s %-8s %s\n" "port" "state" "service"
echo "------------------------------"

if [ $udp -eq 1 ]; then
    results=$(echo "$ports" | tr ' ' '\n' | xargs -I{} -P "$threads" bash -c "check_udp $host {}")
else
    results=$(echo "$ports" | tr ' ' '\n' | xargs -I{} -P "$threads" bash -c "check_tcp $host {}")
fi

open_ports=$(echo "$results" | sort -n | grep -v "^$")

output=""
if [ -z "$open_ports" ]; then
    echo "no open ports found"
else
    while read -r p; do
        svc=$(get_service "$p" "$proto")
        line=$(printf "%-8s %-8s %s" "$p/$proto" "open" "$svc")
        echo "$line"
        output="$output$line\n"
    done <<< "$open_ports"
fi

count=$(echo "$open_ports" | grep -c "\S")
echo ""
echo "$count open ports on $host"

if [ -n "$outfile" ]; then
    echo -e "$output" > "$outfile"
    echo "saved to $outfile"
fi
