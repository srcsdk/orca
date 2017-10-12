#!/bin/bash
# grab banner from a service

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "usage: ./grab.sh <host> <port>"
    exit 1
fi

echo "" | nc -w 3 "$1" "$2" 2>/dev/null | head -5
