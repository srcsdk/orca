#!/usr/bin/env python3
"""operating system and environment detection"""

import os
import platform
import subprocess


def detect_os():
    """detect the operating system."""
    system = platform.system().lower()
    if system == "linux":
        return _detect_linux_distro()
    elif system == "darwin":
        version = platform.mac_ver()[0]
        return {"os": "macos", "version": version, "family": "unix"}
    elif system == "windows":
        version = platform.version()
        return {"os": "windows", "version": version, "family": "windows"}
    return {"os": system, "version": "", "family": "unknown"}


def _detect_linux_distro():
    """detect linux distribution."""
    info = {"os": "linux", "family": "unix"}
    if os.path.isfile("/etc/os-release"):
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("ID="):
                    info["distro"] = line.split("=")[1].strip().strip('"')
                elif line.startswith("VERSION_ID="):
                    info["version"] = line.split("=")[1].strip().strip('"')
                elif line.startswith("PRETTY_NAME="):
                    info["pretty_name"] = (
                        line.split("=", 1)[1].strip().strip('"')
                    )
    info["kernel"] = platform.release()
    return info


def detect_package_manager():
    """detect available package manager."""
    managers = [
        ("apt", "apt"),
        ("pacman", "pacman"),
        ("dnf", "dnf"),
        ("yum", "yum"),
        ("zypper", "zypper"),
        ("brew", "brew"),
        ("apk", "apk"),
    ]
    for name, cmd in managers:
        try:
            subprocess.run(
                ["which", cmd], capture_output=True, check=True,
            )
            return name
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    return None


def detect_init_system():
    """detect the init system."""
    if os.path.isdir("/run/systemd/system"):
        return "systemd"
    if os.path.isfile("/sbin/openrc"):
        return "openrc"
    if os.path.isfile("/sbin/init"):
        return "sysvinit"
    return "unknown"


def detect_shell():
    """detect the current shell."""
    shell = os.environ.get("SHELL", "")
    if shell:
        return os.path.basename(shell)
    return "unknown"


def system_summary():
    """comprehensive system summary."""
    os_info = detect_os()
    return {
        **os_info,
        "architecture": platform.machine(),
        "hostname": platform.node(),
        "package_manager": detect_package_manager(),
        "init_system": detect_init_system(),
        "shell": detect_shell(),
        "python": platform.python_version(),
    }


if __name__ == "__main__":
    summary = system_summary()
    print("system info:")
    for key, value in summary.items():
        print(f"  {key}: {value}")
