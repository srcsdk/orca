#!/usr/bin/env python3
"""cross-platform installer for orca security platform"""

import os
import platform
import subprocess
import sys


def detect_platform():
    """detect os, distro, and package manager."""
    system = platform.system().lower()
    info = {"system": system, "arch": platform.machine()}
    if system == "linux":
        info.update(_detect_linux())
    elif system == "darwin":
        info["distro"] = "macos"
        info["pkg_manager"] = "brew"
    elif system == "windows":
        info["distro"] = "windows"
        info["pkg_manager"] = "winget"
    return info


def _detect_linux():
    """detect linux distribution and package manager."""
    info = {}
    if os.path.isfile("/etc/os-release"):
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("ID="):
                    info["distro"] = line.split("=")[1].strip().strip('"')
                elif line.startswith("ID_LIKE="):
                    info["family"] = line.split("=")[1].strip().strip('"')
    distro = info.get("distro", "")
    family = info.get("family", "")
    if distro == "arch" or "arch" in family:
        info["pkg_manager"] = "pacman"
    elif distro in ("ubuntu", "debian") or "debian" in family:
        info["pkg_manager"] = "apt"
    elif distro in ("fedora", "rhel", "centos") or "fedora" in family:
        info["pkg_manager"] = "dnf"
    elif distro == "opensuse" or "suse" in family:
        info["pkg_manager"] = "zypper"
    elif distro == "alpine":
        info["pkg_manager"] = "apk"
    elif distro == "void":
        info["pkg_manager"] = "xbps"
    elif distro == "gentoo":
        info["pkg_manager"] = "emerge"
    else:
        info["pkg_manager"] = "unknown"
    return info


def install_dependencies(platform_info):
    """install system dependencies for orca."""
    pkg_mgr = platform_info.get("pkg_manager", "unknown")
    deps = {
        "pacman": {
            "cmd": "sudo pacman -S --noconfirm --needed",
            "packages": "python python-pip nmap tcpdump net-tools iproute2",
        },
        "apt": {
            "cmd": "sudo apt-get install -y",
            "packages": "python3 python3-pip nmap tcpdump net-tools iproute2",
        },
        "dnf": {
            "cmd": "sudo dnf install -y",
            "packages": "python3 python3-pip nmap tcpdump net-tools iproute",
        },
        "brew": {
            "cmd": "brew install",
            "packages": "python nmap",
        },
    }
    if pkg_mgr not in deps:
        print(f"unsupported package manager: {pkg_mgr}")
        return False
    dep = deps[pkg_mgr]
    cmd = f"{dep['cmd']} {dep['packages']}"
    print(f"installing dependencies: {cmd}")
    try:
        result = subprocess.run(
            cmd.split(), capture_output=True, text=True, timeout=300,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def install_orca(method="pip"):
    """install orca python package."""
    if method == "pip":
        cmd = [sys.executable, "-m", "pip", "install", "orcasec"]
    elif method == "pipx":
        cmd = ["pipx", "install", "orcasec"]
    elif method == "venv":
        venv_dir = os.path.expanduser("~/.orca/venv")
        os.makedirs(os.path.dirname(venv_dir), exist_ok=True)
        subprocess.run([sys.executable, "-m", "venv", venv_dir], check=True)
        pip = os.path.join(venv_dir, "bin", "pip")
        cmd = [pip, "install", "orcasec"]
    else:
        print(f"unknown install method: {method}")
        return False
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def one_click_install():
    """detect os and install everything automatically."""
    info = detect_platform()
    print(f"detected: {info.get('distro', info['system'])} "
          f"({info['arch']})")
    print(f"package manager: {info.get('pkg_manager', 'unknown')}")
    print("\ninstalling system dependencies...")
    deps_ok = install_dependencies(info)
    if not deps_ok:
        print("warning: some dependencies may not have installed")
    print("\ninstalling orca...")
    if info.get("distro") == "arch":
        ok = install_orca(method="venv")
    else:
        ok = install_orca(method="pip")
    if ok:
        print("\norca installed successfully")
        print("run: orca --help")
    else:
        print("\ninstall failed, try: pip install orcasec")
    return ok


if __name__ == "__main__":
    info = detect_platform()
    print("platform info:")
    for key, val in info.items():
        print(f"  {key}: {val}")
