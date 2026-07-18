"""Deterministic, read-only AWS IAM least-privilege policy auditor."""

from __future__ import annotations

from typing import Any

SEVERITY_POINTS = {"critical": 40, "high": 25, "medium": 10, "low": 3}
PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:attachrolepolicy",
    "iam:createaccesskey",
    "iam:createpolicyversion",
    "iam:passrole",
    "iam:putrolepolicy",
    "lambda:createfunction",
    "sts:assumerole",
}


def _items(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _finding(
    statement: int,
    rule: str,
    severity: str,
    evidence: str,
    remediation: str,
) -> dict[str, Any]:
    return {
        "statement": statement,
        "rule": rule,
        "severity": severity,
        "evidence": evidence,
        "remediation": remediation,
    }


def analyze(policy: dict[str, Any]) -> dict[str, Any]:
    """Analyze an IAM identity/resource policy without changing cloud state."""
    raw_statements = policy.get("Statement", [])
    statements = raw_statements if isinstance(raw_statements, list) else [raw_statements]
    findings: list[dict[str, Any]] = []

    for index, statement in enumerate(statements):
        if not isinstance(statement, dict) or statement.get("Effect", "Allow") != "Allow":
            continue

        actions = [action.lower() for action in _items(statement.get("Action"))]
        resources = _items(statement.get("Resource"))
        conditions = statement.get("Condition")

        if "NotAction" in statement:
            findings.append(
                _finding(
                    index,
                    "ALLOW_WITH_NOTACTION",
                    "high",
                    f"NotAction={statement['NotAction']!r}",
                    "Replace the inverse allow-list with explicit required actions.",
                )
            )

        if "*" in actions:
            findings.append(
                _finding(
                    index,
                    "GLOBAL_ACTION_WILDCARD",
                    "critical",
                    'Action="*"',
                    "Allow only the API operations required by the workload.",
                )
            )
        else:
            service_wildcards = sorted(action for action in actions if action.endswith(":*"))
            if service_wildcards:
                findings.append(
                    _finding(
                        index,
                        "SERVICE_ACTION_WILDCARD",
                        "high",
                        f"Action={service_wildcards!r}",
                        "Replace service wildcards with the exact operations observed and required.",
                    )
                )

        wildcard_resource = "*" in resources
        if wildcard_resource:
            findings.append(
                _finding(
                    index,
                    "GLOBAL_RESOURCE_WILDCARD",
                    "high",
                    'Resource="*"',
                    "Scope resources to specific ARNs; document actions that cannot be resource-scoped.",
                )
            )

        escalation = sorted(set(actions).intersection(PRIVILEGE_ESCALATION_ACTIONS))
        if escalation and wildcard_resource:
            findings.append(
                _finding(
                    index,
                    "PRIVILEGE_ESCALATION_ON_ALL_RESOURCES",
                    "critical",
                    f"Actions={escalation!r}, Resource='*'",
                    "Scope target roles/resources and add trust, tag, path, or permission-boundary conditions.",
                )
            )

        broad_access = wildcard_resource or "*" in actions or any(
            action.endswith(":*") for action in actions
        )
        if broad_access and not conditions:
            findings.append(
                _finding(
                    index,
                    "BROAD_ALLOW_WITHOUT_CONDITION",
                    "medium",
                    "Condition is absent",
                    "Add applicable organization, account, tag, region, source, or MFA conditions.",
                )
            )

    severity_counts = {
        severity: sum(item["severity"] == severity for item in findings)
        for severity in SEVERITY_POINTS
    }
    score = min(100, sum(SEVERITY_POINTS[item["severity"]] for item in findings))
    risk = "critical" if severity_counts["critical"] else "high" if severity_counts["high"] else "medium" if severity_counts["medium"] else "low"
    return {
        "project": "IAM Least-Privilege Auditor",
        "mode": "read-only",
        "statements_evaluated": len(statements),
        "risk": risk,
        "risk_score": score,
        "finding_count": len(findings),
        "severity_counts": severity_counts,
        "findings": findings,
        "recommendation": "APPROVAL REQUIRED" if findings else "STANDARD REVIEW",
    }
