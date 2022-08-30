#!/usr/bin/env python3
"""deployment profile management for orca"""

import os
import json


DEFAULT_PROFILES = {
    "personal": {
        "description": "basic personal device security",
        "modules": [
            "port_scanner", "firewall", "proc_monitor",
            "passwd_audit", "ssl_check", "os_detect",
        ],
    },
    "home_network": {
        "description": "full home network monitoring and defense",
        "modules": [
            "port_scanner", "firewall", "proc_monitor", "net_map",
            "arp_watch", "dns_sinkhole", "wifi_scan", "ssl_check",
            "vuln_scan", "log_monitor", "passwd_audit",
        ],
    },
    "cloud_server": {
        "description": "cloud server hardening and monitoring",
        "modules": [
            "port_scanner", "firewall", "proc_monitor", "log_monitor",
            "ssl_check", "vuln_scan", "server_harden", "compliance",
            "aws_scanner", "aws_iam", "backup",
        ],
    },
    "enterprise": {
        "description": "full enterprise security suite",
        "modules": [
            "port_scanner", "firewall", "proc_monitor", "net_map",
            "arp_watch", "dns_sinkhole", "ssl_check", "vuln_scan",
            "log_monitor", "passwd_audit", "server_harden",
            "compliance", "aws_scanner", "aws_iam", "backup",
            "wifi_scan",
        ],
    },
}


class ProfileManager:
    """manage deployment profiles for different environments."""

    def __init__(self, config_dir=None):
        self.config_dir = config_dir or os.path.expanduser("~/.orca/profiles")
        self.profiles = dict(DEFAULT_PROFILES)
        self._load_custom_profiles()

    def _load_custom_profiles(self):
        """load custom profiles from config directory."""
        if not os.path.isdir(self.config_dir):
            return
        for fname in os.listdir(self.config_dir):
            if not fname.endswith(".json"):
                continue
            path = os.path.join(self.config_dir, fname)
            try:
                with open(path) as f:
                    profile = json.load(f)
                name = fname.rsplit(".", 1)[0]
                self.profiles[name] = profile
            except (json.JSONDecodeError, OSError):
                continue

    def get_profile(self, name):
        """get a profile by name."""
        return self.profiles.get(name)

    def list_profiles(self):
        """list all available profiles."""
        return {
            name: profile.get("description", "")
            for name, profile in self.profiles.items()
        }

    def get_modules(self, profile_name):
        """get list of modules for a profile."""
        profile = self.profiles.get(profile_name)
        if not profile:
            return []
        return profile.get("modules", [])

    def create_profile(self, name, description, modules):
        """create a custom profile."""
        profile = {
            "description": description,
            "modules": modules,
        }
        self.profiles[name] = profile
        self._save_profile(name, profile)
        return profile

    def _save_profile(self, name, profile):
        """save profile to config directory."""
        os.makedirs(self.config_dir, exist_ok=True)
        path = os.path.join(self.config_dir, f"{name}.json")
        with open(path, "w") as f:
            json.dump(profile, f, indent=2)


if __name__ == "__main__":
    pm = ProfileManager()
    profiles = pm.list_profiles()
    for name, desc in profiles.items():
        modules = pm.get_modules(name)
        print(f"  {name}: {desc} ({len(modules)} modules)")
