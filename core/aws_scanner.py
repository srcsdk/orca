#!/usr/bin/env python3
"""aws s3 bucket permission scanner"""

import json


def check_bucket_acl(acl_response):
    """check s3 bucket acl for public access.

    acl_response: dict from s3 get_bucket_acl.
    """
    issues = []
    public_uris = [
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    ]
    for grant in acl_response.get("Grants", []):
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI", "")
        if uri in public_uris:
            issues.append({
                "type": "public_acl",
                "permission": grant.get("Permission"),
                "grantee": uri.split("/")[-1],
            })
    return issues


def check_bucket_policy(policy_str):
    """check s3 bucket policy for overly permissive statements."""
    issues = []
    try:
        policy = json.loads(policy_str)
    except (json.JSONDecodeError, TypeError):
        return issues
    for statement in policy.get("Statement", []):
        principal = statement.get("Principal", "")
        effect = statement.get("Effect", "")
        if principal == "*" and effect == "Allow":
            issues.append({
                "type": "public_policy",
                "action": statement.get("Action"),
                "resource": statement.get("Resource"),
            })
    return issues


def check_encryption(encryption_response):
    """verify bucket has encryption enabled."""
    rules = encryption_response.get("ServerSideEncryptionConfiguration", {})
    if not rules.get("Rules"):
        return {"encrypted": False, "algorithm": None}
    rule = rules["Rules"][0]
    algo = rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
    return {"encrypted": True, "algorithm": algo}


def scan_summary(bucket_name, acl_issues, policy_issues, encryption):
    """compile scan results into summary."""
    severity = "low"
    if acl_issues or policy_issues:
        severity = "high"
    elif not encryption.get("encrypted"):
        severity = "medium"
    return {
        "bucket": bucket_name,
        "severity": severity,
        "acl_issues": len(acl_issues),
        "policy_issues": len(policy_issues),
        "encrypted": encryption.get("encrypted", False),
        "details": {
            "acl": acl_issues,
            "policy": policy_issues,
            "encryption": encryption,
        },
    }


if __name__ == "__main__":
    acl = {"Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]}
    issues = check_bucket_acl(acl)
    print(f"acl issues: {issues}")
