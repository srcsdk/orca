#!/usr/bin/env python3
"""unified configuration management for orcasec platform"""

import json
import os
import platform
import sys


PLATFORM = platform.system().lower()

DEFAULT_CONFIG = {
    "platform": PLATFORM,
    "output_format": "table",
    "output_dir": "",
    "log_level": "info",
    "log_file": "",
    "max_threads": 50,
    "timeout": 5,
    "interface": "",
    "modules": {
        "discovery": {"enabled": True, "timeout": 2, "threads": 100},
        "netscan": {"enabled": True, "timeout": 1, "threads": 200},
        "target": {"enabled": True, "timeout": 5},
        "spider": {"enabled": True, "depth": 3, "timeout": 10},
        "detect": {"enabled": True, "interval": 5},
        "watch": {"enabled": True, "interval": 10},
        "flow": {"enabled": True, "duration": 60},
        "rec": {"enabled": True, "timeout": 3},
        "nvd": {"enabled": True, "api_key": ""},
        "zone": {"enabled": True},
        "poison": {"enabled": False},
        "logma": {"enabled": True, "watch_paths": []},
        "patch": {"enabled": True},
        "gnore": {"enabled": True, "timeout": 5},
        "icu": {"enabled": True, "count": 100},
        "denied": {"enabled": True, "port": 8080},
        "dnsguard": {"enabled": True, "interval": 30},
        "containok": {"enabled": True},
        "conductor": {"enabled": True},
        "supertect": {"enabled": True},
        "tapped": {"enabled": True},
        "probaduce": {"enabled": True},
        "prodsec": {"enabled": True},
        "downseek": {"enabled": True},
        "over": {"enabled": False},
        "vaded": {"enabled": False},
        "sike": {"enabled": False},
        "tropy": {"enabled": True},
        "weewoo": {"enabled": True},
        "res": {"enabled": True},
        "10fthigher": {"enabled": True},
    },
    "pipelines": {},
}


def _get_config_dir():
    """get platform-appropriate config directory"""
    if PLATFORM == "windows":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
        return os.path.join(base, "orcasec")
    elif PLATFORM == "darwin":
        return os.path.expanduser("~/Library/Application Support/orcasec")
    return os.path.expanduser("~/.config/orcasec")


def _get_data_dir():
    """get platform-appropriate data directory"""
    if PLATFORM == "windows":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
        return os.path.join(base, "orcasec", "data")
    elif PLATFORM == "darwin":
        return os.path.expanduser("~/Library/Application Support/orcasec/data")
    return os.path.expanduser("~/.local/share/orcasec")


def _get_log_dir():
    """get platform-appropriate log directory"""
    if PLATFORM == "windows":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
        return os.path.join(base, "orcasec", "logs")
    return os.path.expanduser("~/.local/share/orcasec/logs")


CONFIG_DIR = _get_config_dir()
CONFIG_FILE = os.path.join(CONFIG_DIR, "orcasec.json")
DATA_DIR = _get_data_dir()
LOG_DIR = _get_log_dir()


def load_config(path=None):
    """load config from json file, merging with defaults"""
    path = path or CONFIG_FILE
    config = dict(DEFAULT_CONFIG)
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                user_config = json.load(f)
            _merge(config, user_config)
        except (json.JSONDecodeError, IOError) as e:
            print(f"warning: failed to load config from {path}: {e}", file=sys.stderr)
    if not config["output_dir"]:
        config["output_dir"] = DATA_DIR
    if not config["log_file"]:
        config["log_file"] = os.path.join(LOG_DIR, "orcasec.log")
    return config


def save_config(config, path=None):
    """save config to json file"""
    path = path or CONFIG_FILE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(config, f, indent=2, sort_keys=True)
    return path


def _merge(base, override):
    """recursively merge override dict into base dict"""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _merge(base[key], value)
        else:
            base[key] = value


def get_module_config(module_name, config=None):
    """get config for a specific module"""
    config = config or load_config()
    return config.get("modules", {}).get(module_name, {})


def set_module_config(module_name, settings, config=None):
    """update config for a specific module"""
    config = config or load_config()
    if "modules" not in config:
        config["modules"] = {}
    if module_name not in config["modules"]:
        config["modules"][module_name] = {}
    config["modules"][module_name].update(settings)
    save_config(config)
    return config


def ensure_dirs():
    """create all required directories"""
    for d in (CONFIG_DIR, DATA_DIR, LOG_DIR):
        os.makedirs(d, exist_ok=True)


def main():
    """show current configuration"""
    config = load_config()
    print(json.dumps(config, indent=2))
    print(f"\nconfig file: {CONFIG_FILE}")
    print(f"data dir:    {DATA_DIR}")
    print(f"log dir:     {LOG_DIR}")


if __name__ == "__main__":
    main()


def load_profile(profile_name):
    """load a named scan profile from config"""
    config = load_config()
    profiles = config.get("profiles", {})
    if profile_name in profiles:
        return profiles[profile_name]
    builtin = {
        "quick": {"timeout": 1, "threads": 50, "top_ports": 100},
        "thorough": {"timeout": 3, "threads": 20, "top_ports": 1000},
        "stealth": {"timeout": 5, "threads": 5, "top_ports": 100},
    }
    return builtin.get(profile_name, builtin["quick"])
