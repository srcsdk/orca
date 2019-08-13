#!/bin/bash
# event correlation and alert engine

show_usage() {
    echo "usage: ./supertect.sh [-f file...] [-w window] [-r rules] [-o output]"
    echo "  -f  log file(s) to analyze (can repeat)"
    echo "  -w  time window in seconds (default: 300)"
    echo "  -r  rules file (grep patterns, one per line)"
    echo "  -o  output file for alerts"
}

declare -a log_files
time_window=300
rules_file=""
output=""

while getopts "f:w:r:o:h" opt; do
    case $opt in
        f) log_files+=("$OPTARG") ;;
        w) time_window="$OPTARG" ;;
        r) rules_file="$OPTARG" ;;
        o) output="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

if [[ ${#log_files[@]} -eq 0 ]]; then
    echo "[error] at least one log file required"
    show_usage
    exit 1
fi

declare -A pattern_counts
declare -A pattern_first_seen
declare -A alerted_patterns

default_patterns=(
    "Failed password"
    "authentication failure"
    "Invalid user"
    "POSSIBLE BREAK-IN"
    "refused connect"
    "segfault"
    "SYN_RECV"
    "port scan"
    "unauthorized"
    "permission denied"
)

load_rules() {
    if [[ -n "$rules_file" && -f "$rules_file" ]]; then
        mapfile -t default_patterns < "$rules_file"
        echo "[info] loaded ${#default_patterns[@]} rules from $rules_file"
    fi
}

get_log_timestamp() {
    local line="$1"
    local ts

    # syslog format
    ts=$(echo "$line" | grep -oP '^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}')
    if [[ -n "$ts" ]]; then
        date -d "$ts" +%s 2>/dev/null
        return
    fi

    # iso format
    ts=$(echo "$line" | grep -oP '^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}')
    if [[ -n "$ts" ]]; then
        date -d "$ts" +%s 2>/dev/null
        return
    fi

    echo "0"
}

emit_alert() {
    local severity="$1"
    local pattern="$2"
    local count="$3"
    local source="$4"
    local sample="$5"
    local now
    now=$(date "+%Y-%m-%dT%H:%M:%S")

    local alert="[$now] [$severity] pattern=\"$pattern\" count=$count source=$source sample=\"$sample\""

    if [[ -n "$output" ]]; then
        echo "$alert" >> "$output"
    fi
    echo "$alert"
}

classify_severity() {
    local pattern="$1"
    local count="$2"

    if echo "$pattern" | grep -qi "BREAK-IN\|segfault\|unauthorized"; then
        echo "critical"
    elif [[ $count -gt 50 ]]; then
        echo "high"
    elif [[ $count -gt 10 ]]; then
        echo "medium"
    else
        echo "low"
    fi
}

correlate_events() {
    local now
    now=$(date +%s)

    for key in "${!pattern_counts[@]}"; do
        local first="${pattern_first_seen[$key]}"
        local count="${pattern_counts[$key]}"

        if [[ -n "$first" && $first -ne 0 ]]; then
            local elapsed=$((now - first))
            if [[ $elapsed -le $time_window && $count -gt 3 ]]; then
                if [[ -z "${alerted_patterns[$key]}" ]]; then
                    local severity
                    severity=$(classify_severity "$key" "$count")
                    emit_alert "$severity" "$key" "$count" "multi-source" "correlated in ${elapsed}s"
                    alerted_patterns[$key]=1
                fi
            fi
        fi

        if [[ -n "$first" && $first -ne 0 ]]; then
            local elapsed=$((now - first))
            if [[ $elapsed -gt $time_window ]]; then
                pattern_counts[$key]=0
                pattern_first_seen[$key]=0
                unset alerted_patterns[$key]
            fi
        fi
    done
}

scan_file() {
    local file="$1"
    local source
    source=$(basename "$file")

    [[ ! -f "$file" ]] && return

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        for pattern in "${default_patterns[@]}"; do
            if echo "$line" | grep -qi "$pattern"; then
                local key="$pattern"
                local ts
                ts=$(get_log_timestamp "$line")

                if [[ -z "${pattern_first_seen[$key]}" || "${pattern_first_seen[$key]}" == "0" ]]; then
                    pattern_first_seen[$key]=$ts
                fi
                pattern_counts[$key]=$(( ${pattern_counts[$key]:-0} + 1 ))

                if [[ ${pattern_counts[$key]} -eq 1 ]]; then
                    emit_alert "info" "$pattern" "1" "$source" "$line"
                fi
            fi
        done
    done < "$file"
}

load_rules

echo "[supertect] scanning ${#log_files[@]} files with ${#default_patterns[@]} patterns"
echo "[supertect] time window: ${time_window}s"

for f in "${log_files[@]}"; do
    scan_file "$f"
done

correlate_events

total_alerts=0
for key in "${!pattern_counts[@]}"; do
    total_alerts=$((total_alerts + pattern_counts[$key]))
done

echo ""
echo "[supertect] scan complete: $total_alerts pattern matches found"
