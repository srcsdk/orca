#!/bin/bash
# container security scanner for docker

show_usage() {
    echo "usage: ./containok.sh [-m mode] [-i image] [-f dockerfile]"
    echo "  -m  mode: daemon|containers|image|all"
    echo "  -i  image name to inspect"
    echo "  -f  dockerfile to lint"
}

mode="all"
image=""
dockerfile=""

while getopts "m:i:f:h" opt; do
    case $opt in
        m) mode="$OPTARG" ;;
        i) image="$OPTARG" ;;
        f) dockerfile="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

issues=0

check_docker_available() {
    if ! command -v docker &>/dev/null; then
        echo "[error] docker not found"
        exit 1
    fi

    if ! docker info &>/dev/null; then
        echo "[error] cannot connect to docker daemon"
        exit 1
    fi
}

check_daemon() {
    echo "=== docker daemon configuration ==="

    local daemon_json="/etc/docker/daemon.json"
    if [[ -f "$daemon_json" ]]; then
        echo "[info] daemon.json found"

        if grep -q '"userns-remap"' "$daemon_json"; then
            echo "[pass] user namespace remapping configured"
        else
            echo "[warn] no user namespace remapping"
            ((issues++))
        fi

        if grep -q '"no-new-privileges"' "$daemon_json"; then
            echo "[pass] no-new-privileges set"
        else
            echo "[warn] no-new-privileges not configured"
            ((issues++))
        fi

        if grep -q '"icc":\s*false' "$daemon_json"; then
            echo "[pass] inter-container communication disabled"
        else
            echo "[warn] inter-container communication enabled by default"
            ((issues++))
        fi
    else
        echo "[warn] no daemon.json found (using defaults)"
        ((issues++))
    fi

    local socket="/var/run/docker.sock"
    if [[ -S "$socket" ]]; then
        local perms
        perms=$(stat -c %a "$socket" 2>/dev/null)
        if [[ "$perms" == "660" ]]; then
            echo "[pass] docker socket permissions: $perms"
        else
            echo "[warn] docker socket permissions: $perms (expected 660)"
            ((issues++))
        fi
    fi

    if docker network ls 2>/dev/null | grep -q "bridge"; then
        echo "[info] default bridge network exists"
    fi
}

check_containers() {
    echo ""
    echo "=== running container audit ==="

    local containers
    containers=$(docker ps --format '{{.ID}} {{.Names}} {{.Image}}' 2>/dev/null)

    if [[ -z "$containers" ]]; then
        echo "[info] no running containers"
        return
    fi

    while read -r cid cname cimage; do
        echo ""
        echo "--- container: $cname ($cid) ---"

        local inspect
        inspect=$(docker inspect "$cid" 2>/dev/null)

        # check privileged mode
        if echo "$inspect" | grep -q '"Privileged": true'; then
            echo "[crit] running in privileged mode"
            ((issues++))
        else
            echo "[pass] not privileged"
        fi

        # check pid namespace
        if echo "$inspect" | grep -q '"PidMode": "host"'; then
            echo "[warn] using host pid namespace"
            ((issues++))
        fi

        # check network mode
        if echo "$inspect" | grep -q '"NetworkMode": "host"'; then
            echo "[warn] using host network"
            ((issues++))
        fi

        # check root user
        local user
        user=$(echo "$inspect" | grep -oP '"User":\s*"\K[^"]*' | head -1)
        if [[ -z "$user" || "$user" == "root" || "$user" == "0" ]]; then
            echo "[warn] running as root"
            ((issues++))
        else
            echo "[pass] running as user: $user"
        fi

        # check mounted volumes
        local mounts
        mounts=$(echo "$inspect" | grep -oP '"Source":\s*"\K[^"]*')
        if echo "$mounts" | grep -q '/var/run/docker.sock'; then
            echo "[crit] docker socket mounted inside container"
            ((issues++))
        fi
        if echo "$mounts" | grep -qE '^/(etc|root|home)$'; then
            echo "[warn] sensitive host path mounted"
            ((issues++))
        fi

        # check capabilities
        local caps
        caps=$(echo "$inspect" | grep -A20 '"CapAdd"' | grep -oP '"[A-Z_]+"' | tr -d '"')
        if [[ -n "$caps" ]]; then
            echo "[info] added capabilities: $caps"
            if echo "$caps" | grep -q "SYS_ADMIN"; then
                echo "[crit] SYS_ADMIN capability added"
                ((issues++))
            fi
        fi

    done <<< "$containers"
}

lint_dockerfile() {
    local df="$1"
    if [[ ! -f "$df" ]]; then
        echo "[error] dockerfile not found: $df"
        return
    fi

    echo ""
    echo "=== dockerfile lint: $df ==="

    if ! grep -qi '^USER' "$df"; then
        echo "[warn] no USER instruction (runs as root)"
        ((issues++))
    fi

    if grep -qi 'FROM.*:latest' "$df" || grep -qi 'FROM [a-z]*$' "$df"; then
        echo "[warn] using latest or untagged base image"
        ((issues++))
    fi

    if grep -qi 'ADD ' "$df"; then
        echo "[info] ADD used (prefer COPY for local files)"
    fi

    if grep -qi 'ENV.*PASSWORD\|ENV.*SECRET\|ENV.*KEY' "$df"; then
        echo "[crit] secrets in ENV instruction"
        ((issues++))
    fi

    if grep -qi 'EXPOSE' "$df"; then
        local ports
        ports=$(grep -i 'EXPOSE' "$df" | grep -oP '\d+')
        echo "[info] exposed ports: $ports"
    fi

    if ! grep -qi 'HEALTHCHECK' "$df"; then
        echo "[info] no HEALTHCHECK defined"
    fi
}

check_docker_available

case "$mode" in
    daemon)     check_daemon ;;
    containers) check_containers ;;
    image)
        [[ -n "$dockerfile" ]] && lint_dockerfile "$dockerfile"
        ;;
    all)
        check_daemon
        check_containers
        [[ -n "$dockerfile" ]] && lint_dockerfile "$dockerfile"
        ;;
    *)
        show_usage
        exit 1
        ;;
esac

echo ""
echo "[containok] audit complete: $issues issues found"
