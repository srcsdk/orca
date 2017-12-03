#!/bin/bash
# dns lookup for a domain

if [ -z "$1" ]; then
    echo "usage: ./dns.sh <domain>"
    exit 1
fi

domain="$1"

echo "=== $domain ==="
echo ""
echo "A records:"
dig +short "$domain" A 2>/dev/null | while read -r ip; do
    echo "  $ip"
done

echo ""
echo "MX records:"
dig +short "$domain" MX 2>/dev/null | while read -r line; do
    echo "  $line"
done

echo ""
echo "NS records:"
dig +short "$domain" NS 2>/dev/null | while read -r ns; do
    echo "  $ns"
done
