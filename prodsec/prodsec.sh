#!/bin/bash
# cis benchmark hardening checks for linux servers

show_usage() {
    echo "usage: ./prodsec.sh [-m mode] [-o output]"
    echo "  -m  mode: ssh|perms|services|password|all"
    echo "  -o  output report file"
}

mode="all"
output=""
issues=0
passes=0

while getopts "m:o:h" opt; do
    case $opt in
        m) mode="$OPTARG" ;;
        o) output="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

report() {
    local status="$1"
    local msg="$2"
    local line="[$status] $msg"
    echo "$line"
    [[ -n "$output" ]] && echo "$line" >> "$output"
    if [[ "$status" == "pass" ]]; then
        ((passes++))
    elif [[ "$status" == "fail" || "$status" == "warn" ]]; then
        ((issues++))
    fi
}

check_ssh() {
    echo "=== ssh configuration ==="

    local sshd_conf="/etc/ssh/sshd_config"
    if [[ ! -f "$sshd_conf" ]]; then
        report "info" "sshd_config not found"
        return
    fi

    # root login
    if grep -qiE '^\s*PermitRootLogin\s+(no|prohibit-password)' "$sshd_conf"; then
        report "pass" "root login restricted"
    else
        report "fail" "root login may be permitted"
    fi

    # protocol version
    if grep -qi '^\s*Protocol\s*1' "$sshd_conf"; then
        report "fail" "ssh protocol 1 enabled"
    else
        report "pass" "ssh protocol 1 not enabled"
    fi

    # password authentication
    if grep -qi '^\s*PasswordAuthentication\s*no' "$sshd_conf"; then
        report "pass" "password authentication disabled"
    else
        report "warn" "password authentication may be enabled"
    fi

    # max auth tries
    local max_auth
    max_auth=$(grep -i '^\s*MaxAuthTries' "$sshd_conf" | awk '{print $2}')
    if [[ -n "$max_auth" && "$max_auth" -le 4 ]]; then
        report "pass" "maxauthtries set to $max_auth"
    else
        report "warn" "maxauthtries not restricted (${max_auth:-default})"
    fi

    # empty passwords
    if grep -qi '^\s*PermitEmptyPasswords\s*no' "$sshd_conf"; then
        report "pass" "empty passwords disabled"
    else
        report "warn" "empty passwords not explicitly disabled"
    fi

    # x11 forwarding
    if grep -qi '^\s*X11Forwarding\s*no' "$sshd_conf"; then
        report "pass" "x11 forwarding disabled"
    else
        report "info" "x11 forwarding may be enabled"
    fi

    # idle timeout
    if grep -qi '^\s*ClientAliveInterval' "$sshd_conf"; then
        report "pass" "client alive interval set"
    else
        report "warn" "no client alive interval configured"
    fi
}

check_permissions() {
    echo ""
    echo "=== file permissions ==="

    # passwd and shadow
    local passwd_perms
    passwd_perms=$(stat -c %a /etc/passwd 2>/dev/null)
    if [[ "$passwd_perms" == "644" ]]; then
        report "pass" "/etc/passwd permissions: $passwd_perms"
    else
        report "warn" "/etc/passwd permissions: $passwd_perms (expected 644)"
    fi

    local shadow_perms
    shadow_perms=$(stat -c %a /etc/shadow 2>/dev/null)
    if [[ "$shadow_perms" == "640" || "$shadow_perms" == "600" || "$shadow_perms" == "000" ]]; then
        report "pass" "/etc/shadow permissions: $shadow_perms"
    else
        report "fail" "/etc/shadow permissions: $shadow_perms (expected 640 or stricter)"
    fi

    # world-writable files in key dirs
    local ww_count
    ww_count=$(find /etc -maxdepth 2 -type f -perm -002 2>/dev/null | wc -l)
    if [[ $ww_count -eq 0 ]]; then
        report "pass" "no world-writable files in /etc"
    else
        report "fail" "$ww_count world-writable files in /etc"
    fi

    # suid binaries
    local suid_count
    suid_count=$(find /usr -type f -perm -4000 2>/dev/null | wc -l)
    report "info" "$suid_count suid binaries in /usr"

    # home directory permissions
    if [[ -d /home ]]; then
        for home_dir in /home/*/; do
            local dir_perms
            dir_perms=$(stat -c %a "$home_dir" 2>/dev/null)
            local dir_name
            dir_name=$(basename "$home_dir")
            if [[ "$dir_perms" -le 750 ]]; then
                report "pass" "$dir_name home dir permissions: $dir_perms"
            else
                report "warn" "$dir_name home dir permissions: $dir_perms (should be 750 or stricter)"
            fi
        done
    fi
}

check_services() {
    echo ""
    echo "=== service audit ==="

    local risky_services=("telnet" "rsh" "rlogin" "tftp" "xinetd" "avahi-daemon" "cups")

    for svc in "${risky_services[@]}"; do
        if systemctl is-active "$svc" &>/dev/null; then
            report "warn" "$svc is running (consider disabling)"
        elif systemctl is-enabled "$svc" &>/dev/null; then
            report "info" "$svc is enabled but not running"
        fi
    done

    # check listening ports
    if command -v ss &>/dev/null; then
        local listen_count
        listen_count=$(ss -tlnp 2>/dev/null | tail -n +2 | wc -l)
        report "info" "$listen_count services listening"

        # check for services on all interfaces
        local wildcard
        wildcard=$(ss -tlnp 2>/dev/null | grep -c '0.0.0.0:\|::' || true)
        if [[ $wildcard -gt 5 ]]; then
            report "warn" "$wildcard services listening on all interfaces"
        fi
    fi

    # firewall status
    if command -v ufw &>/dev/null; then
        if ufw status 2>/dev/null | grep -q "active"; then
            report "pass" "ufw firewall is active"
        else
            report "fail" "ufw firewall is not active"
        fi
    elif command -v iptables &>/dev/null; then
        local rules
        rules=$(iptables -L 2>/dev/null | grep -cv '^Chain\|^target\|^$' || echo "0")
        if [[ $rules -gt 0 ]]; then
            report "pass" "iptables has $rules rules configured"
        else
            report "warn" "no iptables rules configured"
        fi
    fi
}

check_password_policy() {
    echo ""
    echo "=== password policy ==="

    local login_defs="/etc/login.defs"
    if [[ -f "$login_defs" ]]; then
        local max_days
        max_days=$(grep '^\s*PASS_MAX_DAYS' "$login_defs" | awk '{print $2}')
        if [[ -n "$max_days" && "$max_days" -le 90 ]]; then
            report "pass" "password max age: $max_days days"
        else
            report "warn" "password max age: ${max_days:-not set} (should be <= 90)"
        fi

        local min_len
        min_len=$(grep '^\s*PASS_MIN_LEN' "$login_defs" | awk '{print $2}')
        if [[ -n "$min_len" && "$min_len" -ge 8 ]]; then
            report "pass" "password min length: $min_len"
        else
            report "warn" "password min length: ${min_len:-not set} (should be >= 8)"
        fi
    fi

    # accounts with empty passwords
    local empty_pw
    empty_pw=$(awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null | wc -l)
    if [[ $empty_pw -eq 0 ]]; then
        report "pass" "no accounts with empty passwords"
    else
        report "fail" "$empty_pw accounts with empty/locked passwords"
    fi

    # uid 0 accounts
    local root_accounts
    root_accounts=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null)
    local root_count
    root_count=$(echo "$root_accounts" | wc -w)
    if [[ $root_count -eq 1 ]]; then
        report "pass" "only root has uid 0"
    else
        report "fail" "multiple uid 0 accounts: $root_accounts"
    fi
}

echo "[prodsec] server hardening audit"
echo ""

case "$mode" in
    ssh)      check_ssh ;;
    perms)    check_permissions ;;
    services) check_services ;;
    password) check_password_policy ;;
    all)
        check_ssh
        check_permissions
        check_services
        check_password_policy
        ;;
    *)
        show_usage
        exit 1
        ;;
esac

echo ""
echo "[prodsec] audit complete: $passes passed, $issues issues"
