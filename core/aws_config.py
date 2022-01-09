#!/usr/bin/env python3
"""aws credential and region configuration"""

import os
import configparser


DEFAULT_REGION = "us-east-1"
AWS_CONFIG_PATH = os.path.expanduser("~/.aws/config")
AWS_CREDS_PATH = os.path.expanduser("~/.aws/credentials")


def load_profile(profile="default"):
    """load aws profile configuration."""
    config = {"region": DEFAULT_REGION, "profile": profile}
    if os.path.exists(AWS_CONFIG_PATH):
        parser = configparser.ConfigParser()
        parser.read(AWS_CONFIG_PATH)
        section = f"profile {profile}" if profile != "default" else "default"
        if parser.has_section(section):
            config["region"] = parser.get(section, "region", fallback=DEFAULT_REGION)
            config["output"] = parser.get(section, "output", fallback="json")
    return config


def get_credentials(profile="default"):
    """load aws credentials from file or env."""
    env_key = os.environ.get("AWS_ACCESS_KEY_ID")
    env_secret = os.environ.get("AWS_SECRET_ACCESS_KEY")
    if env_key and env_secret:
        return {
            "access_key": env_key,
            "secret_key": env_secret,
            "source": "environment",
        }
    if os.path.exists(AWS_CREDS_PATH):
        parser = configparser.ConfigParser()
        parser.read(AWS_CREDS_PATH)
        if parser.has_section(profile):
            return {
                "access_key": parser.get(profile, "aws_access_key_id", fallback=None),
                "secret_key": parser.get(profile, "aws_secret_access_key", fallback=None),
                "source": "credentials_file",
            }
    return {"access_key": None, "secret_key": None, "source": "none"}


def list_profiles():
    """list all configured aws profiles."""
    profiles = []
    for path in [AWS_CONFIG_PATH, AWS_CREDS_PATH]:
        if os.path.exists(path):
            parser = configparser.ConfigParser()
            parser.read(path)
            for section in parser.sections():
                name = section.replace("profile ", "")
                if name not in profiles:
                    profiles.append(name)
    return profiles


def validate_config():
    """check if aws is configured properly."""
    issues = []
    creds = get_credentials()
    if creds["source"] == "none":
        issues.append("no aws credentials found")
    elif not creds["access_key"]:
        issues.append("access key is empty")
    config = load_profile()
    if not config.get("region"):
        issues.append("no region configured")
    return {"valid": len(issues) == 0, "issues": issues}


if __name__ == "__main__":
    config = load_profile()
    print(f"region: {config['region']}")
    profiles = list_profiles()
    print(f"profiles: {profiles}")
    check = validate_config()
    print(f"valid: {check['valid']}")
    for issue in check["issues"]:
        print(f"  - {issue}")
