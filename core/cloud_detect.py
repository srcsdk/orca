#!/usr/bin/env python3
"""detect cloud environment and provider"""

import os
import subprocess


def detect_provider():
    """detect if running in aws, gcp, azure, or local."""
    checks = [
        ("aws", _check_aws),
        ("gcp", _check_gcp),
        ("azure", _check_azure),
        ("docker", _check_docker),
    ]
    for name, check_fn in checks:
        if check_fn():
            return name
    return "local"


def _check_aws():
    """check for aws metadata service or env vars."""
    if os.environ.get("AWS_EXECUTION_ENV"):
        return True
    if os.path.exists("/sys/hypervisor/uuid"):
        try:
            with open("/sys/hypervisor/uuid", "r") as f:
                return f.read(3).lower() == "ec2"
        except (IOError, PermissionError):
            pass
    return False


def _check_gcp():
    """check for gcp metadata markers."""
    if os.environ.get("GOOGLE_CLOUD_PROJECT"):
        return True
    return os.path.exists("/etc/google_cloud")


def _check_azure():
    """check for azure vm markers."""
    if os.environ.get("WEBSITE_SITE_NAME"):
        return True
    try:
        result = subprocess.run(
            ["dmidecode", "-s", "system-manufacturer"],
            capture_output=True, text=True, timeout=5
        )
        return "microsoft" in result.stdout.lower()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _check_docker():
    """check if running inside a container."""
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup", "r") as f:
            return "docker" in f.read() or "containerd" in f.read()
    except (IOError, PermissionError):
        return False


def get_instance_info():
    """gather instance metadata if available."""
    provider = detect_provider()
    info = {"provider": provider, "instance_id": None, "region": None}
    if provider == "aws":
        info["instance_id"] = os.environ.get("AWS_INSTANCE_ID")
        info["region"] = os.environ.get("AWS_DEFAULT_REGION")
    elif provider == "gcp":
        info["region"] = os.environ.get("GOOGLE_CLOUD_REGION")
    return info


if __name__ == "__main__":
    provider = detect_provider()
    print(f"environment: {provider}")
    info = get_instance_info()
    for k, v in info.items():
        print(f"  {k}: {v}")
