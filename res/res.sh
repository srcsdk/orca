#!/bin/bash
# incident response evidence collection toolkit

show_usage() {
    echo "usage: ./res.sh [-m mode] [-o output_dir] [-p pid]"
    echo "  -m  mode: collect|network|processes|users|integrity|all"
    echo "  -o  output directory (default: ./ir_evidence)"
    echo "  -p  suspicious pid for targeted collection"
}

mode="all"
output_dir="./ir_evidence"
target_pid=""

while getopts "m:o:p:h" opt; do
    case $opt in
        m) mode="$OPTARG" ;;
        o) output_dir="$OPTARG" ;;
        p) target_pid="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

timestamp=$(date "+%Y%m%d_%H%M%S")
evidence_dir="$output_dir/evidence_$timestamp"
mkdir -p "$evidence_dir"

log() {
    local msg="[$(date "+%H:%M:%S")] $1"
    echo "$msg"
    echo "$msg" >> "$evidence_dir/collection.log"
}

collect_system_info() {
    log "collecting system information"

    {
        echo "=== hostname ==="
        hostname
        echo ""
        echo "=== date/time ==="
        date
        date -u
        echo ""
        echo "=== uptime ==="
        uptime
        echo ""
        echo "=== kernel ==="
        uname -a
        echo ""
        echo "=== os release ==="
        cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null
        echo ""
        echo "=== disk usage ==="
        df -h
        echo ""
        echo "=== memory ==="
        free -h
        echo ""
        echo "=== mounted filesystems ==="
        mount
    } > "$evidence_dir/system_info.txt" 2>&1

    log "system info saved"
}

collect_processes() {
    log "collecting process information"

    ps auxf > "$evidence_dir/process_tree.txt" 2>&1
    ps aux --sort=-%mem > "$evidence_dir/process_by_memory.txt" 2>&1
    ps aux --sort=-%cpu > "$evidence_dir/process_by_cpu.txt" 2>&1

    if [[ -n "$target_pid" ]]; then
        log "collecting details for pid $target_pid"
        local pid_dir="$evidence_dir/pid_$target_pid"
        mkdir -p "$pid_dir"

        if [[ -d "/proc/$target_pid" ]]; then
            cat "/proc/$target_pid/cmdline" 2>/dev/null | tr '\0' ' ' > "$pid_dir/cmdline.txt"
            cat "/proc/$target_pid/environ" 2>/dev/null | tr '\0' '\n' > "$pid_dir/environ.txt"
            ls -la "/proc/$target_pid/fd/" > "$pid_dir/file_descriptors.txt" 2>&1
            cat "/proc/$target_pid/maps" > "$pid_dir/memory_maps.txt" 2>/dev/null
            cat "/proc/$target_pid/status" > "$pid_dir/status.txt" 2>/dev/null
            ls -la "/proc/$target_pid/exe" > "$pid_dir/executable.txt" 2>&1
        else
            log "pid $target_pid not found in /proc"
        fi
    fi

    # check for deleted binaries still running
    ls -la /proc/*/exe 2>/dev/null | grep "(deleted)" > "$evidence_dir/deleted_executables.txt" 2>&1

    log "process info saved"
}

collect_network() {
    log "collecting network information"

    {
        echo "=== interfaces ==="
        ip addr 2>/dev/null || ifconfig
        echo ""
        echo "=== routes ==="
        ip route 2>/dev/null || route -n
        echo ""
        echo "=== arp table ==="
        ip neigh 2>/dev/null || arp -a
        echo ""
        echo "=== dns config ==="
        cat /etc/resolv.conf
    } > "$evidence_dir/network_config.txt" 2>&1

    # active connections
    if command -v ss &>/dev/null; then
        ss -tulnp > "$evidence_dir/listening_ports.txt" 2>&1
        ss -tnp > "$evidence_dir/established_connections.txt" 2>&1
    elif command -v netstat &>/dev/null; then
        netstat -tulnp > "$evidence_dir/listening_ports.txt" 2>&1
        netstat -tnp > "$evidence_dir/established_connections.txt" 2>&1
    fi

    # iptables rules
    iptables -L -n -v > "$evidence_dir/iptables_rules.txt" 2>&1

    log "network info saved"
}

collect_users() {
    log "collecting user and login information"

    {
        echo "=== current users ==="
        w
        echo ""
        echo "=== last logins ==="
        last -20
        echo ""
        echo "=== failed logins ==="
        lastb -20 2>/dev/null || echo "lastb not available"
        echo ""
        echo "=== recent auth log ==="
        tail -100 /var/log/auth.log 2>/dev/null || tail -100 /var/log/secure 2>/dev/null
    } > "$evidence_dir/user_activity.txt" 2>&1

    # cron jobs
    {
        echo "=== system crontab ==="
        cat /etc/crontab 2>/dev/null
        echo ""
        echo "=== cron.d ==="
        ls -la /etc/cron.d/ 2>/dev/null
        echo ""
        echo "=== user crontabs ==="
        for user in $(cut -d: -f1 /etc/passwd); do
            local crontab
            crontab=$(crontab -l -u "$user" 2>/dev/null)
            if [[ -n "$crontab" ]]; then
                echo "--- $user ---"
                echo "$crontab"
            fi
        done
    } > "$evidence_dir/scheduled_tasks.txt" 2>&1

    # authorized keys
    find /home -name "authorized_keys" -type f 2>/dev/null | while read -r keyfile; do
        local owner
        owner=$(stat -c %U "$keyfile" 2>/dev/null)
        echo "=== $keyfile (owner: $owner) ===" >> "$evidence_dir/ssh_keys.txt"
        cat "$keyfile" >> "$evidence_dir/ssh_keys.txt" 2>/dev/null
        echo "" >> "$evidence_dir/ssh_keys.txt"
    done

    log "user info saved"
}

check_integrity() {
    log "checking system integrity"

    # recently modified system files
    find /etc -type f -mtime -7 -ls 2>/dev/null > "$evidence_dir/recent_etc_changes.txt"
    find /usr/bin -type f -mtime -7 -ls 2>/dev/null > "$evidence_dir/recent_bin_changes.txt"
    find /tmp -type f -ls 2>/dev/null > "$evidence_dir/tmp_contents.txt"

    # check package integrity if available
    if command -v dpkg &>/dev/null; then
        dpkg --verify > "$evidence_dir/package_verify.txt" 2>&1
    elif command -v rpm &>/dev/null; then
        rpm -Va > "$evidence_dir/package_verify.txt" 2>&1
    fi

    # check for rootkit indicators
    {
        echo "=== hidden files in / ==="
        ls -la /.[!.]* 2>/dev/null
        echo ""
        echo "=== suspicious /dev files ==="
        find /dev -type f 2>/dev/null
        echo ""
        echo "=== kernel modules ==="
        lsmod 2>/dev/null
    } > "$evidence_dir/rootkit_checks.txt" 2>&1

    log "integrity checks saved"
}

log "incident response collection started"
log "evidence directory: $evidence_dir"
echo ""

case "$mode" in
    collect)   collect_system_info ;;
    network)   collect_network ;;
    processes) collect_processes ;;
    users)     collect_users ;;
    integrity) check_integrity ;;
    all)
        collect_system_info
        collect_processes
        collect_network
        collect_users
        check_integrity
        ;;
    *)
        show_usage
        exit 1
        ;;
esac

echo ""
log "collection complete"
log "evidence files:"
ls -la "$evidence_dir/" | tail -n +2
echo ""
echo "archive with: tar czf evidence_$timestamp.tar.gz -C $output_dir evidence_$timestamp"
