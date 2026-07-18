# IAM Least-Privilege Auditor

Day 2 of my 30-day Cloud + AI portfolio series.

IAM policies often grow faster than teams can review them. A wildcard added during an incident can survive into production, turning one compromised identity into an account-wide security event. This project provides an evidence-first review step before an engineer approves a policy change.

![IAM Least-Privilege Auditor architecture](docs/architecture.png)

## What it does

The auditor parses AWS identity or resource policy JSON and produces deterministic, explainable findings. It currently identifies:

- global and service-level action wildcards;
- global resource wildcards;
- privilege-escalation actions such as `iam:PassRole` against every resource;
- `Allow` statements using `NotAction`;
- broad access without a limiting condition.

Every finding includes the statement index, severity, evidence, and a remediation recommendation. The engine is read-only: it never calls AWS or mutates a policy.

## Quick start

Python 3.11+ is the only runtime requirement.

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m iam_least_privilege_auditor examples/sample.json
```

Example output includes a `risk_score`, severity counts, structured findings, and an explicit `APPROVAL REQUIRED` recommendation.

## Architecture and decision boundary

1. A policy document enters as JSON.
2. The parser normalizes statements, actions, resources, effects, and conditions.
3. Transparent policy rules produce structured evidence.
4. A human reviews the findings before any infrastructure change.

This separation is intentional: an AI assistant may summarize the evidence later, but it cannot silently override the deterministic control or authorize production access.

## Safe CI deployment

The included GitHub Actions workflow runs unit tests and audits the synthetic sample on every push and pull request. To use the tool in a real delivery pipeline, export the proposed IAM policy from the plan/build stage and pass that file to the CLI. Keep cloud credentials and `terraform apply` outside this project, and require a protected-environment approval when findings exist.

## Test coverage

The suite covers global wildcards, service wildcards, privilege escalation, `NotAction`, scoped policies, and deny statements. The sample contains synthetic ARNs and no credentials.

## Known limitations

- This is a portfolio-grade guardrail, not a replacement for AWS IAM Access Analyzer.
- It does not resolve variables, permission boundaries, SCPs, trust policies, or effective permissions across accounts.
- Findings are intentionally conservative and must be reviewed in deployment context.

## Interview positioning

“I built a deterministic IAM guardrail that converts policy JSON into explainable least-privilege findings. I separated evidence generation from infrastructure mutation, added CI coverage, and retained human approval for security-impacting changes.”
