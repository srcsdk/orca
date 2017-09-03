#!/bin/bash
# check if a port is open on a host

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "usage: ./portscan.sh <host> <port>"
    exit 1
fi

host="$1"
port="$2"

(echo > /dev/tcp/"$host"/"$port") 2>/dev/null
if [ $? -eq 0 ]; then
    echo "$host:$port open"
else
    echo "$host:$port closed"
fi
