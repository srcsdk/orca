#!/usr/bin/env python3
"""centralized configuration management for orca"""

import os
import json


DEFAULT_CONFIG = {
    "scan_interval": 3600,
    "dashboard_port": 8080,
    "log_level": "info",
    "alert_email": "",
    "modules_dir": "core/modules",
    "data_dir": "data",
    "auto_scan": True,
    "max_log_size_mb": 50,
}


def config_path():
    """get path to orca config file."""
    xdg = os.environ.get("XDG_CONFIG_HOME", "")
    base = xdg if xdg else os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "orca", "config.json")


def load_config():
    """load configuration with defaults."""
    config = dict(DEFAULT_CONFIG)
    path = config_path()
    if os.path.isfile(path):
        with open(path) as f:
            user_config = json.load(f)
        config.update(user_config)
    env_overrides = {
        "ORCA_SCAN_INTERVAL": ("scan_interval", int),
        "ORCA_DASHBOARD_PORT": ("dashboard_port", int),
        "ORCA_LOG_LEVEL": ("log_level", str),
        "ORCA_ALERT_EMAIL": ("alert_email", str),
    }
    for env_key, (config_key, converter) in env_overrides.items():
        val = os.environ.get(env_key)
        if val is not None:
            config[config_key] = converter(val)
    return config


def save_config(config):
    """save configuration to file."""
    path = config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(config, f, indent=2)


def get(key, default=None):
    """get a single config value."""
    config = load_config()
    return config.get(key, default)


def set_value(key, value):
    """set a single config value."""
    config = load_config()
    config[key] = value
    save_config(config)


def validate_config(config):
    """validate configuration values."""
    issues = []
    if config.get("scan_interval", 0) < 60:
        issues.append("scan_interval too low (min 60)")
    port = config.get("dashboard_port", 0)
    if port < 1024 or port > 65535:
        issues.append(f"invalid dashboard_port: {port}")
    valid_levels = {"debug", "info", "warning", "error"}
    if config.get("log_level", "") not in valid_levels:
        issues.append(f"invalid log_level: {config.get('log_level')}")
    return issues


if __name__ == "__main__":
    config = load_config()
    print("orca configuration:")
    for k, v in config.items():
        print(f"  {k}: {v}")
    issues = validate_config(config)
    if issues:
        print(f"\nvalidation issues: {issues}")
    else:
        print("\nconfiguration valid")
