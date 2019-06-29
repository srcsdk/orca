#!/bin/bash
# process evasion techniques for testing detection tools

show_usage() {
    echo "usage: ./vaded.sh [-m mode] [-p pid] [-n name]"
    echo "  -m  mode: rename|preload|hide|test"
    echo "  -p  target pid (for rename mode, must be own process)"
    echo "  -n  new process name (for rename mode)"
    echo ""
    echo "modes:"
    echo "  rename   - rename a process via /proc/pid/comm (own process only)"
    echo "  preload  - demonstrate ld_preload injection concept"
    echo "  hide     - show how processes can disguise themselves"
    echo "  test     - run all techniques and check if tapped detects them"
}

mode=""
target_pid=""
new_name=""

while getopts "m:p:n:h" opt; do
    case $opt in
        m) mode="$OPTARG" ;;
        p) target_pid="$OPTARG" ;;
        n) new_name="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

[ -z "$mode" ] && echo "error: -m mode required" && show_usage && exit 1

demo_rename() {
    local pid="${target_pid:-$$}"
    local name="${new_name:-sshd}"

    # safety: only allow renaming own process
    if [ "$pid" != "$$" ]; then
        proc_uid=$(awk '/^Uid:/{print $2}' /proc/$pid/status 2>/dev/null)
        my_uid=$(id -u)
        if [ "$proc_uid" != "$my_uid" ]; then
            echo "safety: can only rename own processes"
            exit 1
        fi
    fi

    echo "original name: $(cat /proc/$pid/comm 2>/dev/null)"
    echo "$name" > /proc/$pid/comm 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "renamed to: $(cat /proc/$pid/comm 2>/dev/null)"
        echo "check: ps aux | grep $pid"
    else
        echo "rename failed (permission denied)"
    fi
}

demo_preload() {
    echo "ld_preload demonstration"
    echo ""
    echo "this technique uses LD_PRELOAD to intercept library calls."
    echo "a shared library loaded before others can override functions."
    echo ""
    echo "example concept (not executing):"
    echo "  1. compile a .so that overrides readdir() to hide files"
    echo "  2. set LD_PRELOAD=/path/to/lib.so"
    echo "  3. ls will not show hidden files"
    echo ""
    echo "detection methods:"
    echo "  - check /proc/pid/maps for unexpected libraries"
    echo "  - check LD_PRELOAD environment variable"
    echo "  - compare /proc/pid/maps across processes"

    # show current preloads
    echo ""
    echo "current ld preloads on this system:"
    if [ -f /etc/ld.so.preload ]; then
        cat /etc/ld.so.preload
    else
        echo "  none (/etc/ld.so.preload not found)"
    fi
}

demo_hide() {
    echo "process hiding techniques overview"
    echo ""
    echo "1. name masquerading:"
    echo "   renaming process to look like a system service"
    local fake_names="[kworker/0:1] [migration/0] sshd crond"
    for n in $fake_names; do
        echo "   example: disguise as '$n'"
    done
    echo ""
    echo "2. argv manipulation:"
    echo "   overwrite argv[0] to change what shows in ps"
    echo ""
    echo "3. mount namespace hiding:"
    echo "   use unshare to create isolated mount namespace"
    echo ""
    echo "4. timing-based evasion:"
    echo "   run only briefly between monitoring intervals"
    echo ""
    echo "running quick detection test..."
    # spawn a short-lived process with suspicious name to test detection
    bash -c 'echo "test" > /dev/null' &
    echo "spawned test process pid=$! (already exited)"
}

run_test() {
    echo "evasion detection test suite"
    echo ""

    echo "[test 1] process rename"
    original=$(cat /proc/$$/comm)
    echo "  original: $original"
    echo "kworker" > /proc/$$/comm 2>/dev/null
    renamed=$(cat /proc/$$/comm)
    echo "  renamed:  $renamed"
    echo "$original" > /proc/$$/comm 2>/dev/null
    echo "  restored: $(cat /proc/$$/comm)"
    echo ""

    echo "[test 2] deleted binary detection"
    echo "  checking for processes with deleted executables..."
    found=0
    for pid_dir in /proc/[0-9]*; do
        exe=$(readlink "$pid_dir/exe" 2>/dev/null)
        if echo "$exe" | grep -q "(deleted)"; then
            pid=$(basename "$pid_dir")
            name=$(cat "$pid_dir/comm" 2>/dev/null)
            echo "  found: pid=$pid name=$name exe=$exe"
            found=$((found + 1))
        fi
    done
    [ $found -eq 0 ] && echo "  none found"
    echo ""

    echo "[test 3] ld_preload check"
    for pid_dir in /proc/[0-9]*; do
        env_file="$pid_dir/environ"
        [ ! -r "$env_file" ] && continue
        if tr '\0' '\n' < "$env_file" 2>/dev/null | grep -q "LD_PRELOAD"; then
            pid=$(basename "$pid_dir")
            name=$(cat "$pid_dir/comm" 2>/dev/null)
            preload=$(tr '\0' '\n' < "$env_file" 2>/dev/null | grep "LD_PRELOAD")
            echo "  found: pid=$pid name=$name $preload"
        fi
    done 2>/dev/null
    echo "  check complete"
}

case "$mode" in
    rename)  demo_rename ;;
    preload) demo_preload ;;
    hide)    demo_hide ;;
    test)    run_test ;;
    *)       echo "unknown mode: $mode"; show_usage; exit 1 ;;
esac
