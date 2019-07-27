#!/bin/bash
# centralized log collection and normalization

show_usage() {
    echo "usage: ./logma.sh [-f file...] [-d dir] [-o output] [-n]"
    echo "  -f  log file(s) to monitor (can repeat)"
    echo "  -d  directory of log files"
    echo "  -o  output file (default: stdout)"
    echo "  -n  normalize timestamps to iso format"
}

declare -a log_files
output=""
normalize=0
log_dir=""

while getopts "f:d:o:nh" opt; do
    case $opt in
        f) log_files+=("$OPTARG") ;;
        d) log_dir="$OPTARG" ;;
        o) output="$OPTARG" ;;
        n) normalize=1 ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

if [[ -n "$log_dir" ]]; then
    while IFS= read -r -d '' f; do
        log_files+=("$f")
    done < <(find "$log_dir" -name "*.log" -type f -print0 2>/dev/null)
fi

if [[ ${#log_files[@]} -eq 0 ]]; then
    echo "[error] no log files specified"
    show_usage
    exit 1
fi

for f in "${log_files[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "[warn] file not found: $f" >&2
    fi
done

normalize_timestamp() {
    local line="$1"
    local source="$2"

    # syslog format: Mon DD HH:MM:SS
    if echo "$line" | grep -qP '^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}'; then
        local ts
        ts=$(echo "$line" | grep -oP '^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}')
        local msg
        msg=$(echo "$line" | sed "s/^$ts //")
        local iso
        iso=$(date -d "$ts" "+%Y-%m-%dT%H:%M:%S" 2>/dev/null || echo "$ts")
        echo "$iso|$source|$msg"
        return
    fi

    # apache/nginx format: DD/Mon/YYYY:HH:MM:SS
    if echo "$line" | grep -qP '\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}'; then
        local ts
        ts=$(echo "$line" | grep -oP '\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}')
        local clean_ts
        clean_ts=$(echo "$ts" | sed 's|/| |g; s/:/ /' | head -1)
        local iso
        iso=$(date -d "$clean_ts" "+%Y-%m-%dT%H:%M:%S" 2>/dev/null || echo "$ts")
        echo "$iso|$source|$line"
        return
    fi

    # iso format already
    if echo "$line" | grep -qP '^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'; then
        local ts
        ts=$(echo "$line" | grep -oP '^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}')
        echo "$ts|$source|$line"
        return
    fi

    echo "unknown|$source|$line"
}

extract_severity() {
    local line="$1"
    local lower
    lower=$(echo "$line" | tr '[:upper:]' '[:lower:]')

    if echo "$lower" | grep -qE '(emerg|panic|fatal)'; then
        echo "critical"
    elif echo "$lower" | grep -qE '(error|err|fail)'; then
        echo "error"
    elif echo "$lower" | grep -qE '(warn|warning)'; then
        echo "warning"
    elif echo "$lower" | grep -qE '(notice|info)'; then
        echo "info"
    else
        echo "unknown"
    fi
}

process_line() {
    local line="$1"
    local source="$2"
    [[ -z "$line" ]] && return

    if [[ $normalize -eq 1 ]]; then
        normalize_timestamp "$line" "$source"
    else
        local severity
        severity=$(extract_severity "$line")
        echo "[$severity] [$source] $line"
    fi
}

write_output() {
    if [[ -n "$output" ]]; then
        cat >> "$output"
    else
        cat
    fi
}

echo "[logma] monitoring ${#log_files[@]} files" >&2

for f in "${log_files[@]}"; do
    [[ ! -f "$f" ]] && continue
    local_name=$(basename "$f")

    while IFS= read -r line; do
        process_line "$line" "$local_name" | write_output
    done < "$f"
done

if command -v tail &>/dev/null; then
    valid_files=()
    for f in "${log_files[@]}"; do
        [[ -f "$f" ]] && valid_files+=("$f")
    done

    if [[ ${#valid_files[@]} -gt 0 ]]; then
        echo "[logma] tailing ${#valid_files[@]} files (ctrl+c to stop)" >&2
        tail -f -n 0 "${valid_files[@]}" 2>/dev/null | while IFS= read -r line; do
            if [[ "$line" == "==> "* ]]; then
                current_source=$(echo "$line" | sed 's/==> //; s/ <==//')
                current_source=$(basename "$current_source")
                continue
            fi
            [[ -n "$line" ]] && process_line "$line" "${current_source:-unknown}" | write_output
        done
    fi
fi
