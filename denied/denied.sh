#!/bin/bash
# simple http request firewall using iptables

show_usage() {
    echo "usage: ./denied.sh [-l logfile] [-p port] [-i iface] [-r] [-c]"
    echo "  -l  log blocked requests to file"
    echo "  -p  http port to protect (default: 80)"
    echo "  -i  interface"
    echo "  -r  remove all waf rules"
    echo "  -c  check current rules"
}

logfile=""
port=80
iface=""
remove=0
check=0
chain="WAF_FILTER"

while getopts "l:p:i:rch" opt; do
    case $opt in
        l) logfile="$OPTARG" ;;
        p) port="$OPTARG" ;;
        i) iface="$OPTARG" ;;
        r) remove=1 ;;
        c) check=1 ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "requires root"
    exit 1
fi

log_msg() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$msg"
    [ -n "$logfile" ] && echo "$msg" >> "$logfile"
}

if [ $check -eq 1 ]; then
    iptables -L "$chain" -n -v 2>/dev/null || echo "no waf rules found"
    exit 0
fi

if [ $remove -eq 1 ]; then
    iptables -D INPUT -p tcp --dport "$port" -j "$chain" 2>/dev/null
    iptables -F "$chain" 2>/dev/null
    iptables -X "$chain" 2>/dev/null
    echo "waf rules removed"
    exit 0
fi

# create chain
iptables -N "$chain" 2>/dev/null
iptables -F "$chain"

# sql injection patterns
iptables -A "$chain" -m string --string "UNION SELECT" --algo bm -j DROP
iptables -A "$chain" -m string --string "union select" --algo bm -j DROP
iptables -A "$chain" -m string --string "OR 1=1" --algo bm -j DROP
iptables -A "$chain" -m string --string "' OR '" --algo bm -j DROP
iptables -A "$chain" -m string --string "DROP TABLE" --algo bm -j DROP
iptables -A "$chain" -m string --string "drop table" --algo bm -j DROP

# xss patterns
iptables -A "$chain" -m string --string "<script>" --algo bm -j DROP
iptables -A "$chain" -m string --string "javascript:" --algo bm -j DROP
iptables -A "$chain" -m string --string "onerror=" --algo bm -j DROP
iptables -A "$chain" -m string --string "onload=" --algo bm -j DROP

# path traversal
iptables -A "$chain" -m string --string "../" --algo bm -j DROP
iptables -A "$chain" -m string --string "..%2f" --algo bm -j DROP
iptables -A "$chain" -m string --string "%2e%2e" --algo bm -j DROP

# command injection
iptables -A "$chain" -m string --string "; cat " --algo bm -j DROP
iptables -A "$chain" -m string --string "| cat " --algo bm -j DROP
iptables -A "$chain" -m string --string "/etc/passwd" --algo bm -j DROP
iptables -A "$chain" -m string --string "/etc/shadow" --algo bm -j DROP

# log dropped packets
iptables -A "$chain" -m string --string "SELECT" --algo bm -j LOG \
    --log-prefix "WAF_BLOCK: " --log-level 4 2>/dev/null

# hook into input chain
iptables -D INPUT -p tcp --dport "$port" -j "$chain" 2>/dev/null
iptables -A INPUT -p tcp --dport "$port" -j "$chain"

log_msg "waf rules installed on port $port"
log_msg "$(iptables -L "$chain" --line-numbers -n | wc -l) rules active"
