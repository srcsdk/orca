#!/bin/bash
# patch and configuration auditor

show_usage() {
    echo "usage: ./audit.sh [-c config_check] [-p package_check] [-o output] [-v]"
    echo "  -c  check config files (sshd,apache,nginx)"
    echo "  -p  check package versions"
    echo "  -o  output report file"
    echo "  -v  verbose output"
}

check_config=0
check_packages=0
output=""
verbose=0
issues=0
checks=0

while getopts "cpvo:h" opt; do
    case $opt in
        c) check_config=1 ;;
        p) check_packages=1 ;;
        o) output="$OPTARG" ;;
        v) verbose=1 ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

[ $check_config -eq 0 ] && [ $check_packages -eq 0 ] && check_config=1 && check_packages=1

report() {
    local msg="$1"
    echo "$msg"
    [ -n "$output" ] && echo "$msg" >> "$output"
}

check_pass() {
    checks=$((checks + 1))
    [ $verbose -eq 1 ] && report "[PASS] $1"
}

check_fail() {
    checks=$((checks + 1))
    issues=$((issues + 1))
    report "[FAIL] $1"
}

check_warn() {
    checks=$((checks + 1))
    report "[WARN] $1"
}

report "audit started: $(date)"
report ""

if [ $check_config -eq 1 ]; then
    report "--- sshd configuration ---"
    sshd_conf="/etc/ssh/sshd_config"
    if [ -f "$sshd_conf" ]; then
        if grep -qi "^PermitRootLogin\s*yes" "$sshd_conf" 2>/dev/null; then
            check_fail "sshd: root login enabled"
        else
            check_pass "sshd: root login disabled or restricted"
        fi
        if grep -qi "^PasswordAuthentication\s*yes" "$sshd_conf" 2>/dev/null; then
            check_warn "sshd: password auth enabled (prefer key-based)"
        else
            check_pass "sshd: password auth disabled"
        fi
        if grep -qi "^PermitEmptyPasswords\s*yes" "$sshd_conf" 2>/dev/null; then
            check_fail "sshd: empty passwords permitted"
        else
            check_pass "sshd: empty passwords not permitted"
        fi
        if grep -qi "^Protocol\s*1" "$sshd_conf" 2>/dev/null; then
            check_fail "sshd: protocol 1 enabled"
        else
            check_pass "sshd: protocol 2 only"
        fi
        if grep -qi "^X11Forwarding\s*yes" "$sshd_conf" 2>/dev/null; then
            check_warn "sshd: x11 forwarding enabled"
        fi
    else
        report "sshd_config not found, skipping"
    fi

    report ""
    report "--- file permissions ---"
    for f in /etc/passwd /etc/shadow /etc/group; do
        if [ -f "$f" ]; then
            perms=$(stat -c "%a" "$f" 2>/dev/null)
            owner=$(stat -c "%U" "$f" 2>/dev/null)
            if [ "$f" = "/etc/shadow" ] && [ "$perms" != "640" ] && [ "$perms" != "600" ]; then
                check_fail "$f has permissions $perms (expected 600 or 640)"
            elif [ "$owner" != "root" ]; then
                check_fail "$f not owned by root (owner: $owner)"
            else
                check_pass "$f permissions ok ($perms, $owner)"
            fi
        fi
    done

    report ""
    report "--- world writable files in /etc ---"
    ww_count=$(find /etc -maxdepth 2 -perm -o+w -type f 2>/dev/null | wc -l)
    if [ "$ww_count" -gt 0 ]; then
        check_fail "found $ww_count world-writable files in /etc"
        [ $verbose -eq 1 ] && find /etc -maxdepth 2 -perm -o+w -type f 2>/dev/null | while read -r f; do
            report "  $f"
        done
    else
        check_pass "no world-writable files in /etc"
    fi
fi

if [ $check_packages -eq 1 ]; then
    report ""
    report "--- package updates ---"
    if command -v apt &>/dev/null; then
        updates=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
        if [ "$updates" -gt 0 ]; then
            check_warn "$updates packages have available updates"
        else
            check_pass "all packages up to date"
        fi
    elif command -v yum &>/dev/null; then
        updates=$(yum check-update 2>/dev/null | grep -cE "^\S+\s+\S+\s+\S+")
        if [ "$updates" -gt 0 ]; then
            check_warn "$updates packages have available updates"
        else
            check_pass "all packages up to date"
        fi
    else
        report "no supported package manager found"
    fi
fi

report ""
report "audit complete: $checks checks, $issues issues found"
