#!/bin/bash
# dns enumeration for a domain

if [ -z "$1" ]; then
    echo "usage: ./dns.sh <domain>"
    exit 1
fi

domain="$1"

echo "=== dns enumeration: $domain ==="

for rtype in A AAAA MX NS TXT SOA CNAME SRV; do
    result=$(dig +short "$domain" "$rtype" 2>/dev/null)
    if [ -n "$result" ]; then
        echo ""
        echo "$rtype:"
        echo "$result" | while read -r line; do
            echo "  $line"
        done
    fi
done
