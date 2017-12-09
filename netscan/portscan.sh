#!/bin/bash
# tcp port scanner

show_usage() {
    echo "usage: ./portscan.sh [-c] [-t threads] [-o outfile] <host> [start] [end]"
    echo "  -c  common ports only"
    echo "  -t  parallel threads (default 50)"
    echo "  -o  output file"
}

common_ports="21 22 23 25 53 80 110 111 135 139 143 443 445 993 995 1723 3306 3389 5900 8080"

get_service() {
    local port="$1"
    local svc=$(grep -w "$port/tcp" /etc/services 2>/dev/null | head -1 | awk '{print $1}')
    [ -z "$svc" ] && svc="unknown"
    echo "$svc"
}

check_port() {
    local host="$1"
    local port="$2"
    timeout 1 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "$port"
    fi
}

export -f check_port

scan_common=0
threads=50
outfile=""
while getopts "ct:o:h" opt; do
    case $opt in
        c) scan_common=1 ;;
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

if [ $scan_common -eq 1 ]; then
    echo "scanning $host (common ports, $threads threads)..."
    ports="$common_ports"
else
    start=${2:-1}
    end=${3:-1024}
    echo "scanning $host ports $start-$end ($threads threads)..."
    ports=$(seq "$start" "$end")
fi

echo ""
printf "%-8s %-8s %s\n" "port" "state" "service"
echo "------------------------------"

results=$(echo "$ports" | tr ' ' '\n' | xargs -I{} -P "$threads" bash -c "check_port $host {}")
open_ports=$(echo "$results" | sort -n | grep -v "^$")

output=""
if [ -z "$open_ports" ]; then
    echo "no open ports found"
else
    while read -r p; do
        svc=$(get_service "$p")
        line=$(printf "%-8s %-8s %s" "$p/tcp" "open" "$svc")
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
