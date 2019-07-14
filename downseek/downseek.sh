#!/bin/bash
# tls configuration auditor for nginx and apache

show_usage() {
    echo "usage: ./downseek.sh [-t target] [-m mode] [-c config]"
    echo "  -t  target host for protocol testing"
    echo "  -m  mode: config|proto|ciphers|all"
    echo "  -c  path to config file (nginx.conf or ssl.conf)"
}

target=""
mode="all"
config_file=""

while getopts "t:m:c:h" opt; do
    case $opt in
        t) target="$OPTARG" ;;
        m) mode="$OPTARG" ;;
        c) config_file="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

weak_ciphers=(
    "RC4" "DES" "3DES" "MD5" "NULL" "EXPORT"
    "aNULL" "eNULL" "ADH" "AECDH"
)

weak_protos=("ssl2" "ssl3" "tls1" "tls1_1")

check_config() {
    local conf="$1"
    if [[ ! -f "$conf" ]]; then
        echo "[error] config file not found: $conf"
        return 1
    fi

    echo "=== config audit: $conf ==="
    local issues=0

    local cipher_line
    cipher_line=$(grep -i 'ssl_ciphers\|SSLCipherSuite' "$conf" | head -1)
    if [[ -n "$cipher_line" ]]; then
        echo "[info] cipher config: $cipher_line"
        for weak in "${weak_ciphers[@]}"; do
            if echo "$cipher_line" | grep -qi "$weak"; then
                echo "[warn] weak cipher found: $weak"
                ((issues++))
            fi
        done
    else
        echo "[warn] no cipher configuration found"
        ((issues++))
    fi

    if grep -qi 'ssl_prefer_server_ciphers\s*on\|SSLHonorCipherOrder\s*on' "$conf"; then
        echo "[pass] server cipher preference enabled"
    else
        echo "[warn] server cipher preference not enabled"
        ((issues++))
    fi

    if grep -qi 'SSLv2\|SSLv3\|TLSv1[^.]' "$conf"; then
        echo "[warn] legacy protocol references found in config"
        ((issues++))
    fi

    if grep -qi 'ssl_stapling\s*on\|SSLUseStapling\s*on' "$conf"; then
        echo "[pass] ocsp stapling enabled"
    else
        echo "[info] ocsp stapling not configured"
    fi

    if grep -qi 'Strict-Transport-Security\|add_header.*HSTS' "$conf"; then
        echo "[pass] hsts header configured"
    else
        echo "[warn] hsts not configured"
        ((issues++))
    fi

    echo ""
    echo "total issues: $issues"
    return $issues
}

test_protocol() {
    local host="$1"
    local proto="$2"
    local flag=""

    case "$proto" in
        ssl2)   flag="-ssl2" ;;
        ssl3)   flag="-ssl3" ;;
        tls1)   flag="-tls1" ;;
        tls1_1) flag="-tls1_1" ;;
        tls1_2) flag="-tls1_2" ;;
        tls1_3) flag="-tls1_3" ;;
    esac

    if echo "" | timeout 5 openssl s_client -connect "$host:443" $flag 2>/dev/null | grep -q "Protocol"; then
        return 0
    fi
    return 1
}

check_protocols() {
    local host="$1"
    if [[ -z "$host" ]]; then
        echo "[error] target required for protocol testing"
        return 1
    fi

    if ! command -v openssl &>/dev/null; then
        echo "[error] openssl not found"
        return 1
    fi

    echo "=== protocol test: $host ==="

    for proto in "${weak_protos[@]}"; do
        if test_protocol "$host" "$proto"; then
            echo "[fail] $proto is enabled (insecure)"
        else
            echo "[pass] $proto is disabled"
        fi
    done

    for proto in tls1_2 tls1_3; do
        if test_protocol "$host" "$proto"; then
            echo "[pass] $proto is enabled"
        else
            echo "[warn] $proto is not enabled"
        fi
    done
}

check_ciphers() {
    local host="$1"
    if [[ -z "$host" ]]; then
        echo "[error] target required for cipher testing"
        return 1
    fi

    echo "=== cipher check: $host ==="

    local result
    result=$(echo "" | timeout 5 openssl s_client -connect "$host:443" 2>/dev/null)

    local cipher
    cipher=$(echo "$result" | grep "Cipher    :" | awk '{print $NF}')
    echo "[info] negotiated cipher: $cipher"

    local cert_expiry
    cert_expiry=$(echo "" | timeout 5 openssl s_client -connect "$host:443" 2>/dev/null | \
        openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    if [[ -n "$cert_expiry" ]]; then
        echo "[info] cert expires: $cert_expiry"
        local exp_epoch
        exp_epoch=$(date -d "$cert_expiry" +%s 2>/dev/null)
        local now_epoch
        now_epoch=$(date +%s)
        if [[ -n "$exp_epoch" ]]; then
            local days_left=$(( (exp_epoch - now_epoch) / 86400 ))
            if [[ $days_left -lt 30 ]]; then
                echo "[warn] certificate expires in $days_left days"
            else
                echo "[pass] certificate valid for $days_left days"
            fi
        fi
    fi
}

case "$mode" in
    config)
        [[ -z "$config_file" ]] && { echo "[error] -c config required"; exit 1; }
        check_config "$config_file"
        ;;
    proto)
        check_protocols "$target"
        ;;
    ciphers)
        check_ciphers "$target"
        ;;
    all)
        [[ -n "$config_file" ]] && check_config "$config_file"
        if [[ -n "$target" ]]; then
            echo ""
            check_protocols "$target"
            echo ""
            check_ciphers "$target"
        fi
        [[ -z "$config_file" && -z "$target" ]] && { show_usage; exit 1; }
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
