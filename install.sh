#!/bin/sh
# one-click installer for orca security platform
# usage: curl -fsSL https://raw.githubusercontent.com/srcsdk/cybersec/master/install.sh | sh
set -e

ORCA_DIR="$HOME/.orca"
VENV_DIR="$ORCA_DIR/venv"

detect_pkg_manager() {
    if command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    elif command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v zypper >/dev/null 2>&1; then
        echo "zypper"
    elif command -v apk >/dev/null 2>&1; then
        echo "apk"
    elif command -v brew >/dev/null 2>&1; then
        echo "brew"
    else
        echo "unknown"
    fi
}

install_deps() {
    mgr=$1
    case "$mgr" in
        pacman) sudo pacman -S --noconfirm --needed python python-pip nmap tcpdump ;;
        apt)    sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-venv nmap tcpdump ;;
        dnf)    sudo dnf install -y python3 python3-pip nmap tcpdump ;;
        zypper) sudo zypper install -y python3 python3-pip nmap tcpdump ;;
        apk)    sudo apk add python3 py3-pip nmap tcpdump ;;
        brew)   brew install python nmap ;;
        *)      echo "unsupported package manager, install python3 and pip manually" ;;
    esac
}

setup_venv() {
    mkdir -p "$ORCA_DIR"
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip
    "$VENV_DIR/bin/pip" install orcasec
}

create_launcher() {
    mkdir -p "$HOME/.local/bin"
    cat > "$HOME/.local/bin/orca" << 'LAUNCHER'
#!/bin/sh
exec "$HOME/.orca/venv/bin/python" -m orca "$@"
LAUNCHER
    chmod +x "$HOME/.local/bin/orca"
}

main() {
    echo "orca security platform installer"
    echo "================================"

    os=$(uname -s)
    arch=$(uname -m)
    echo "detected: $os $arch"

    mgr=$(detect_pkg_manager)
    echo "package manager: $mgr"

    echo ""
    echo "installing system dependencies..."
    install_deps "$mgr"

    echo ""
    echo "setting up orca in $ORCA_DIR..."
    setup_venv

    echo ""
    echo "creating launcher..."
    create_launcher

    echo ""
    echo "orca installed successfully"
    echo "make sure ~/.local/bin is in your PATH"
    echo "run: orca --help"
}

main
