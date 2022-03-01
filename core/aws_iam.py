#!/usr/bin/env python3
"""iam policy analyzer for overprivileged roles"""

import json


DANGEROUS_ACTIONS = [
    "iam:*",
    "s3:*",
    "ec2:*",
    "lambda:*",
    "sts:AssumeRole",
    "iam:CreateUser",
    "iam:AttachUserPolicy",
    "s3:DeleteBucket",
    "ec2:TerminateInstances",
]


def analyze_policy(policy_document):
    """analyze iam policy for overprivileged permissions."""
    issues = []
    try:
        if isinstance(policy_document, str):
            policy = json.loads(policy_document)
        else:
            policy = policy_document
    except json.JSONDecodeError:
        return [{"type": "parse_error", "message": "invalid policy json"}]
    for statement in policy.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resource = statement.get("Resource", "")
        for action in actions:
            if action == "*":
                issues.append({
                    "type": "wildcard_action",
                    "severity": "critical",
                    "action": action,
                    "resource": resource,
                })
            elif action in DANGEROUS_ACTIONS:
                issues.append({
                    "type": "dangerous_action",
                    "severity": "high",
                    "action": action,
                    "resource": resource,
                })
            elif action.endswith(":*"):
                issues.append({
                    "type": "service_wildcard",
                    "severity": "medium",
                    "action": action,
                    "resource": resource,
                })
        if resource == "*":
            issues.append({
                "type": "wildcard_resource",
                "severity": "medium",
                "action": str(actions),
                "resource": resource,
            })
    return issues


def least_privilege_suggestions(issues):
    """suggest least-privilege alternatives for found issues."""
    suggestions = []
    for issue in issues:
        if issue["type"] == "wildcard_action":
            suggestions.append(
                "replace * with specific actions needed"
            )
        elif issue["type"] == "service_wildcard":
            service = issue["action"].split(":")[0]
            suggestions.append(
                f"replace {issue['action']} with specific "
                f"{service} actions (e.g. {service}:GetObject)"
            )
        elif issue["type"] == "wildcard_resource":
            suggestions.append(
                "scope resource to specific arns instead of *"
            )
    return suggestions


def policy_risk_score(issues):
    """calculate risk score from policy analysis."""
    weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
    score = sum(weights.get(i["severity"], 0) for i in issues)
    return min(score, 100)


if __name__ == "__main__":
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Allow", "Action": "s3:GetObject",
             "Resource": "arn:aws:s3:::my-bucket/*"},
        ]
    }
    issues = analyze_policy(policy)
    print(f"issues found: {len(issues)}")
    print(f"risk score: {policy_risk_score(issues)}")
    for i in issues:
        print(f"  [{i['severity']}] {i['type']}: {i['action']}")
