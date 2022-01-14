#!/usr/bin/env python3
"""ssh connection manager with key-based auth"""

import os
import subprocess


DEFAULT_KEY_PATH = os.path.expanduser("~/.ssh/id_rsa")


def test_connection(host, user, port=22, key_path=None):
    """test ssh connection to remote host."""
    cmd = _build_ssh_cmd(host, user, port, key_path)
    cmd.extend(["echo", "connected"])
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def run_remote(host, user, command, port=22, key_path=None):
    """execute command on remote host via ssh."""
    cmd = _build_ssh_cmd(host, user, port, key_path)
    cmd.append(command)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "timeout", "returncode": -1}


def copy_to_remote(local_path, host, user, remote_path, port=22, key_path=None):
    """copy file to remote host via scp."""
    if key_path is None:
        key_path = DEFAULT_KEY_PATH
    cmd = [
        "scp", "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-P", str(port),
    ]
    if key_path and os.path.exists(key_path):
        cmd.extend(["-i", key_path])
    cmd.extend([local_path, f"{user}@{host}:{remote_path}"])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.returncode == 0


def list_keys():
    """list available ssh keys."""
    ssh_dir = os.path.expanduser("~/.ssh")
    if not os.path.isdir(ssh_dir):
        return []
    keys = []
    for f in os.listdir(ssh_dir):
        if f.endswith(".pub"):
            key_name = f[:-4]
            private = os.path.join(ssh_dir, key_name)
            keys.append({
                "name": key_name,
                "public": os.path.join(ssh_dir, f),
                "private": private if os.path.exists(private) else None,
            })
    return keys


def parse_ssh_config():
    """parse ~/.ssh/config for host definitions."""
    config_path = os.path.expanduser("~/.ssh/config")
    if not os.path.exists(config_path):
        return {}
    hosts = {}
    current = None
    with open(config_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.lower().startswith("host ") and "*" not in line:
                current = line.split(None, 1)[1]
                hosts[current] = {}
            elif current and " " in line:
                key, val = line.split(None, 1)
                hosts[current][key.lower()] = val
    return hosts


def _build_ssh_cmd(host, user, port=22, key_path=None):
    """build ssh command with options."""
    if key_path is None:
        key_path = DEFAULT_KEY_PATH
    cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-p", str(port),
    ]
    if key_path and os.path.exists(key_path):
        cmd.extend(["-i", key_path])
    cmd.append(f"{user}@{host}")
    return cmd


if __name__ == "__main__":
    keys = list_keys()
    print(f"found {len(keys)} ssh keys")
    for k in keys:
        print(f"  {k['name']}: {k['public']}")
    hosts = parse_ssh_config()
    print(f"ssh config hosts: {list(hosts.keys())}")
