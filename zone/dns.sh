#!/bin/bash
# dns reconnaissance

show_usage() {
    echo "usage: ./dns.sh [-z] [-r] [-b wordlist] [-o outfile] <domain>"
    echo "  -z  attempt zone transfer"
    echo "  -r  reverse lookup all A records"
    echo "  -b  brute force subdomains with wordlist"
    echo "  -o  output to file"
}

zone_transfer=0
reverse=0
wordlist=""
outfile=""

while getopts "zrb:o:h" opt; do
    case $opt in
        z) zone_transfer=1 ;;
        r) reverse=1 ;;
        b) wordlist="$OPTARG" ;;
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

if [ $zone_transfer -eq 1 ]; then
    out "=== zone transfer ==="
    for ns in $(dig +short "$domain" NS 2>/dev/null); do
        ns_clean=$(echo "$ns" | sed 's/\.$//')
        out "trying $ns_clean..."
        result=$(dig @"$ns_clean" "$domain" AXFR +noall +answer 2>/dev/null)
        if [ -n "$result" ] && ! echo "$result" | grep -q "Transfer failed"; then
            out "  success:"
            echo "$result" | while read -r line; do
                out "    $line"
            done
        else
            out "  denied"
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
    if [ ! -f "$wordlist" ]; then
        echo "wordlist not found: $wordlist"
        exit 1
    fi
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
