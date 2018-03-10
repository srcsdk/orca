#!/bin/bash
# service banner grabber and fingerprinter

show_usage() {
    echo "usage: ./grab.sh [-f netscan_output] [-o outfile] [-s] <host> [port]..."
    echo "  -s  show ssl certificate info for https ports"
}

grab_banner() {
    local host="$1"
    local port="$2"
    local banner=""

    case "$port" in
        80|8080|8000|8888)
            banner=$(echo -e "HEAD / HTTP/1.0\r\nHost: $host\r\n\r\n" | nc -w 3 "$host" "$port" 2>/dev/null)
            ;;
        443|8443)
            banner=$(echo -e "HEAD / HTTP/1.0\r\nHost: $host\r\n\r\n" | timeout 5 openssl s_client -connect "$host:$port" -quiet 2>/dev/null)
            ;;
        *)
            banner=$(echo "" | nc -w 3 "$host" "$port" 2>/dev/null)
            ;;
    esac

    [ -z "$banner" ] && return

    server=$(echo "$banner" | grep -i "^Server:" | head -1 | sed 's/Server: //i')
    ssh_ver=$(echo "$banner" | grep -i "^SSH-" | head -1)
    smtp_banner=$(echo "$banner" | grep -i "^220 " | head -1)

    version="${server:-${ssh_ver:-${smtp_banner:-$(echo "$banner" | head -1)}}}"
    printf "%-8s %s\n" "$port/tcp" "$version"
}

get_cert_info() {
    local host="$1"
    local port="$2"
    echo | timeout 5 openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null
}

from_file=""
outfile=""
show_ssl=0
while getopts "f:o:sh" opt; do
    case $opt in
        f) from_file="$OPTARG" ;;
        o) outfile="$OPTARG" ;;
        s) show_ssl=1 ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

host="$1"
[ -z "$host" ] && { show_usage; exit 1; }
shift

if [ -n "$from_file" ]; then
    ports=$(grep "open" "$from_file" | awk -F/ '{print $1}' | tr -d ' ')
else
    ports="$@"
fi

[ -z "$ports" ] && { echo "no ports specified"; exit 1; }

echo "grabbing banners from $host..."
printf "\n%-8s %s\n" "port" "version"
echo "----------------------------------------"

output=""
for port in $ports; do
    line=$(grab_banner "$host" "$port")
    if [ -n "$line" ]; then
        echo "$line"
        output="$output$line\n"
    fi

    if [ $show_ssl -eq 1 ]; then
        case "$port" in
            443|8443)
                cert=$(get_cert_info "$host" "$port")
                if [ -n "$cert" ]; then
                    echo "$cert" | sed 's/^/         /'
                fi
                ;;
        esac
    fi
done

if [ -n "$outfile" ]; then
    echo -e "$output" > "$outfile"
    echo ""
    echo "saved to $outfile"
fi
