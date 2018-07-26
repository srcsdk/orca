#!/bin/bash
# dns reconnaissance

show_usage() {
    echo "usage: ./dns.sh [-z] [-r] [-b wordlist] [-w] [-o outfile] <domain>"
    echo "  -z  attempt zone transfer"
    echo "  -r  reverse lookup A records"
    echo "  -b  brute force subdomains"
    echo "  -w  include whois info"
    echo "  -o  output to file"
}

zone_transfer=0
reverse=0
wordlist=""
whois_lookup=0
outfile=""

while getopts "zrb:wo:h" opt; do
    case $opt in
        z) zone_transfer=1 ;;
        r) reverse=1 ;;
        b) wordlist="$OPTARG" ;;
        w) whois_lookup=1 ;;
        o) outfile="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

domain="$1"
[ -z "$domain" ] && { show_usage; exit 1; }

out() {
    echo "$1"
    [ -n "$outfile" ] && echo "$1" >> "$outfile"
}

[ -n "$outfile" ] && > "$outfile"

out "=== dns recon: $domain ==="
out ""

for rtype in A AAAA MX NS TXT SOA CNAME SRV; do
    result=$(dig +short "$domain" "$rtype" 2>/dev/null)
    if [ -n "$result" ]; then
        out "$rtype:"
        echo "$result" | while read -r line; do
            out "  $line"
        done
        out ""
    fi
done

if [ $whois_lookup -eq 1 ] && command -v whois &>/dev/null; then
    out "=== whois ==="
    whois "$domain" 2>/dev/null | grep -iE '(registrar|creation|expir|name server|registrant|org)' | head -15 | while read -r line; do
        out "  $line"
    done
    out ""
fi

if [ $zone_transfer -eq 1 ]; then
    out "=== zone transfer ==="
    for ns in $(dig +short "$domain" NS 2>/dev/null); do
        ns_clean=$(echo "$ns" | sed 's/\.$//')
        result=$(dig @"$ns_clean" "$domain" AXFR +noall +answer 2>/dev/null)
        if [ -n "$result" ] && ! echo "$result" | grep -q "Transfer failed"; then
            out "  $ns_clean: success"
            echo "$result" | while read -r line; do
                out "    $line"
            done
        else
            out "  $ns_clean: denied"
        fi
    done
    out ""
fi

if [ $reverse -eq 1 ]; then
    out "=== reverse lookups ==="
    for ip in $(dig +short "$domain" A 2>/dev/null); do
        rev=$(dig +short -x "$ip" 2>/dev/null)
        [ -z "$rev" ] && rev="(no ptr)"
        out "  $ip -> $rev"
    done
    out ""
fi

if [ -n "$wordlist" ]; then
    [ ! -f "$wordlist" ] && { echo "wordlist not found: $wordlist"; exit 1; }
    out "=== subdomain brute force ==="
    found=0
    while read -r sub; do
        [ -z "$sub" ] && continue
        result=$(dig +short "$sub.$domain" A 2>/dev/null)
        if [ -n "$result" ]; then
            out "  $sub.$domain -> $result"
            found=$((found + 1))
        fi
    done < "$wordlist"
    out "  $found subdomains found"
    out ""
fi
