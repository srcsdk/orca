#!/usr/bin/env python3
"""password audit module with entropy scoring"""

import math
import hashlib
import os

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "shadow", "123123", "654321", "superman",
    "michael", "password1", "password123", "welcome",
}


def password_entropy(password):
    """calculate password entropy in bits."""
    if not password:
        return 0.0
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(not c.isalnum() for c in password):
        charset += 32
    if charset == 0:
        return 0.0
    return round(len(password) * math.log2(charset), 1)


def strength_rating(entropy):
    """rate password strength based on entropy."""
    if entropy < 28:
        return "very_weak"
    elif entropy < 36:
        return "weak"
    elif entropy < 60:
        return "moderate"
    elif entropy < 80:
        return "strong"
    return "very_strong"


def is_common(password):
    """check against common password list."""
    return password.lower() in COMMON_PASSWORDS


def check_breach(password):
    """check password against haveibeenpwned api (k-anonymity).

    only sends first 5 chars of sha1 hash.
    """
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    try:
        from urllib.request import urlopen
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        resp = urlopen(url, timeout=5)
        for line in resp.read().decode().split("\n"):
            if line.strip().startswith(suffix):
                count = int(line.strip().split(":")[1])
                return count
    except (OSError, ValueError):
        pass
    return 0


def audit_password(password):
    """full password audit."""
    entropy = password_entropy(password)
    return {
        "entropy": entropy,
        "strength": strength_rating(entropy),
        "is_common": is_common(password),
        "length": len(password),
        "has_upper": any(c.isupper() for c in password),
        "has_lower": any(c.islower() for c in password),
        "has_digit": any(c.isdigit() for c in password),
        "has_special": any(not c.isalnum() for c in password),
    }


if __name__ == "__main__":
    test_passwords = ["password", "Tr0ub4dor&3", "correct horse battery"]
    for pwd in test_passwords:
        result = audit_password(pwd)
        print(f"  {pwd}: {result['strength']} "
              f"(entropy={result['entropy']} bits)")
