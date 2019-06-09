#!/bin/bash
# process and system monitoring

show_usage() {
    echo "usage: ./tapped.sh [-i interval] [-l logfile] [-s suspicious_list] [-p pid]"
    echo "  -i  check interval seconds (default: 5)"
    echo "  -l  log file"
    echo "  -s  file with suspicious process names"
    echo "  -p  monitor specific pid"
}

interval=5
logfile=""
suspicious_file=""
watch_pid=""
total_alerts=0

while getopts "i:l:s:p:h" opt; do
    case $opt in
        i) interval="$OPTARG" ;;
        l) logfile="$OPTARG" ;;
        s) suspicious_file="$OPTARG" ;;
        p) watch_pid="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

log_msg() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$msg"
    [ -n "$logfile" ] && echo "$msg" >> "$logfile"
}

alert() {
    total_alerts=$((total_alerts + 1))
    log_msg "[ALERT] $1"
}

# default suspicious names
suspicious_names="nc ncat netcat socat cryptominer xmrig"
if [ -n "$suspicious_file" ] && [ -f "$suspicious_file" ]; then
    suspicious_names=$(cat "$suspicious_file" | tr '\n' ' ')
fi

declare -A known_pids

snapshot_procs() {
    local current_pids=()
    for pid_dir in /proc/[0-9]*; do
        local pid=$(basename "$pid_dir")
        [ ! -f "$pid_dir/comm" ] && continue
        local name=$(cat "$pid_dir/comm" 2>/dev/null)
        [ -z "$name" ] && continue
        current_pids+=("$pid")

        # new process detection
        if [ -z "${known_pids[$pid]}" ]; then
            local cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)
            local ppid=$(awk '/^PPid:/{print $2}' "$pid_dir/status" 2>/dev/null)
            local uid=$(awk '/^Uid:/{print $2}' "$pid_dir/status" 2>/dev/null)
            log_msg "new process: pid=$pid name=$name ppid=$ppid uid=$uid"

            # check against suspicious list
            for sus in $suspicious_names; do
                if [ "$name" = "$sus" ]; then
                    alert "suspicious process: $name (pid=$pid) cmd=$cmdline"
                fi
            done

            # check for processes with deleted exe
            local exe=$(readlink "$pid_dir/exe" 2>/dev/null)
            if echo "$exe" | grep -q "(deleted)"; then
                alert "process running deleted binary: $name (pid=$pid) $exe"
            fi
        fi
        known_pids["$pid"]="$name"
    done

    # detect terminated processes
    for pid in "${!known_pids[@]}"; do
        if [ ! -d "/proc/$pid" ]; then
            log_msg "process exited: pid=$pid name=${known_pids[$pid]}"
            unset known_pids["$pid"]
        fi
    done
}

# single pid monitoring mode
if [ -n "$watch_pid" ]; then
    if [ ! -d "/proc/$watch_pid" ]; then
        echo "pid $watch_pid not found"
        exit 1
    fi
    log_msg "watching pid $watch_pid"
    while [ -d "/proc/$watch_pid" ]; do
        fd_count=$(ls /proc/$watch_pid/fd 2>/dev/null | wc -l)
        threads=$(ls /proc/$watch_pid/task 2>/dev/null | wc -l)
        mem=$(awk '/VmRSS/{print $2}' /proc/$watch_pid/status 2>/dev/null)
        log_msg "pid=$watch_pid fds=$fd_count threads=$threads mem=${mem}kB"
        sleep "$interval"
    done
    log_msg "pid $watch_pid exited"
    exit 0
fi

# continuous monitoring mode
log_msg "process monitor started (interval: ${interval}s)"
log_msg "suspicious names: $suspicious_names"

trap 'echo ""; echo "alerts: $total_alerts"; exit 0' INT TERM

# initial snapshot
snapshot_procs

while true; do
    sleep "$interval"
    snapshot_procs
done
