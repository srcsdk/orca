#!/usr/bin/env python3
"""configuration parser for orca scan profiles"""

import json
import os


DEFAULT_CONFIG = {
    "scan_interval": 3600,
    "modules_enabled": ["port_scan", "wifi_scan", "arp_watch"],
    "log_level": "info",
    "report_format": "text",
    "alert_threshold": "medium",
    "output_dir": "/tmp/orca_reports",
}


def load_config(path=None):
    """load config from json file, falling back to defaults."""
    if path and os.path.exists(path):
        with open(path, "r") as f:
            user_config = json.load(f)
        config = DEFAULT_CONFIG.copy()
        config.update(user_config)
        return config
    return DEFAULT_CONFIG.copy()


def save_config(config, path):
    """save configuration to file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(config, f, indent=2)


def validate_config(config):
    """check config values are within expected ranges."""
    errors = []
    if config.get("scan_interval", 0) < 60:
        errors.append("scan_interval must be at least 60 seconds")
    valid_levels = {"debug", "info", "warning", "error"}
    if config.get("log_level", "").lower() not in valid_levels:
        errors.append(f"log_level must be one of {valid_levels}")
    valid_formats = {"text", "json", "html"}
    if config.get("report_format", "").lower() not in valid_formats:
        errors.append(f"report_format must be one of {valid_formats}")
    return errors


def merge_profiles(base, override):
    """merge two config profiles with override taking precedence."""
    merged = base.copy()
    for key, value in override.items():
        if isinstance(value, list) and isinstance(merged.get(key), list):
            merged[key] = list(set(merged[key] + value))
        else:
            merged[key] = value
    return merged


if __name__ == "__main__":
    config = load_config()
    errors = validate_config(config)
    print(f"config valid: {len(errors) == 0}")
    for e in errors:
        print(f"  error: {e}")
