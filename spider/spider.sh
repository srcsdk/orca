#!/bin/bash
# web directory scanner and path brute force

show_usage() {
    echo "usage: ./spider.sh -u url [-w wordlist] [-s status_codes] [-o output] [-t timeout]"
    echo "  -u  target url (required)"
    echo "  -w  wordlist file (default: built-in common paths)"
    echo "  -s  status codes to show (default: 200,301,302,403)"
    echo "  -o  output file"
    echo "  -t  timeout seconds (default: 5)"
}

target=""
wordlist=""
status_filter="200,301,302,403"
output=""
timeout=5
found=0
checked=0

while getopts "u:w:s:o:t:h" opt; do
    case $opt in
        u) target="$OPTARG" ;;
        w) wordlist="$OPTARG" ;;
        s) status_filter="$OPTARG" ;;
        o) output="$OPTARG" ;;
        t) timeout="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

[ -z "$target" ] && echo "error: -u url required" && exit 1
target="${target%/}"

if ! command -v curl &>/dev/null; then
    echo "curl not found"
    exit 1
fi

common_paths=(
    "admin" "login" "wp-admin" "wp-login.php" "administrator"
    ".env" ".git/config" "robots.txt" "sitemap.xml" ".htaccess"
    "api" "api/v1" "swagger" "graphql" "debug"
    "phpmyadmin" "cpanel" "webmail" "server-status" "server-info"
    "backup" "backup.zip" "dump.sql" "config.php" "wp-config.php"
    "test" "staging" "dev" "old" "temp"
    ".DS_Store" "thumbs.db" "web.config" "crossdomain.xml"
    "console" "dashboard" "panel" "manager" "shell"
)

log_result() {
    local msg="$1"
    echo "$msg"
    [ -n "$output" ] && echo "$msg" >> "$output"
}

check_path() {
    local path="$1"
    local url="$target/$path"
    local response
    response=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" \
        --connect-timeout "$timeout" -L "$url" 2>/dev/null)
    local code=$(echo "$response" | awk '{print $1}')
    local size=$(echo "$response" | awk '{print $2}')
    checked=$((checked + 1))

    if echo "$status_filter" | grep -q "$code"; then
        found=$((found + 1))
        log_result "[$code] $url (${size}b)"
    fi
}

echo "scanning $target"
echo "filter: $status_filter"
echo ""

if [ -n "$wordlist" ] && [ -f "$wordlist" ]; then
    while IFS= read -r path; do
        [ -z "$path" ] && continue
        [[ "$path" =~ ^# ]] && continue
        check_path "$path"
    done < "$wordlist"
else
    for path in "${common_paths[@]}"; do
        check_path "$path"
    done
fi

echo ""
echo "scan complete: $checked paths checked, $found found"
