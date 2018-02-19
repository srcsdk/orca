#!/bin/bash
# dns reconnaissance

show_usage() {
    echo "usage: ./dns.sh [-z] [-r] [-o outfile] <domain>"
    echo "  -z  attempt zone transfer"
    echo "  -r  reverse lookup all A records"
    echo "  -o  output to file"
}

zone_transfer=0
reverse=0
outfile=""

while getopts "zro:h" opt; do
    case $opt in
        z) zone_transfer=1 ;;
        r) reverse=1 ;;
        o) outfile="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

domain="$1"
[ -z "$domain" ] && { show_usage; exit 1; }

output() {
    echo "$1"
    [ -n "$outfile" ] && echo "$1" >> "$outfile"
}

[ -n "$outfile" ] && > "$outfile"

output "=== dns recon: $domain ==="
output ""

for rtype in A AAAA MX NS TXT SOA CNAME SRV; do
    result=$(dig +short "$domain" "$rtype" 2>/dev/null)
    if [ -n "$result" ]; then
        output "$rtype:"
        echo "$result" | while read -r line; do
            output "  $line"
        done
        output ""
    fi
done

if [ $zone_transfer -eq 1 ]; then
    output "=== zone transfer attempts ==="
    nameservers=$(dig +short "$domain" NS 2>/dev/null)
    for ns in $nameservers; do
        ns_clean=$(echo "$ns" | sed 's/\.$//')
        output "trying $ns_clean..."
        result=$(dig @"$ns_clean" "$domain" AXFR +noall +answer 2>/dev/null)
        if [ -n "$result" ] && ! echo "$result" | grep -q "Transfer failed"; then
            output "  zone transfer successful:"
            echo "$result" | while read -r line; do
                output "    $line"
            done
        else
            output "  denied"
        fi
    done
    output ""
fi

if [ $reverse -eq 1 ]; then
    output "=== reverse lookups ==="
    ips=$(dig +short "$domain" A 2>/dev/null)
    for ip in $ips; do
        rev=$(dig +short -x "$ip" 2>/dev/null)
        [ -z "$rev" ] && rev="(no ptr)"
        output "  $ip -> $rev"
    done
    output ""
fi
