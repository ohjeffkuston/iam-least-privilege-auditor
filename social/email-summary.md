# Day 2 — IAM Least-Privilege Auditor

Jeffrey,

Today’s project is a read-only AWS IAM policy guardrail. It accepts policy JSON, normalizes each statement, applies deterministic security rules, and returns structured least-privilege findings. It never logs into AWS or changes infrastructure.

## Architecture

`IAM policy JSON → deterministic rule engine → structured findings → human approval`

The decision boundary is the key design choice: analysis is automated, but production authorization remains human-controlled.

## Implementation walkthrough

- `_items` normalizes IAM fields that may be strings or arrays.
- `analyze` processes only `Allow` statements when identifying excess permission.
- Transparent rules flag wildcards, unrestricted resources, privilege escalation, `NotAction`, and missing conditions.
- `_finding` produces a consistent evidence contract containing statement, rule, severity, evidence, and remediation.
- Severity points create a bounded risk score while retaining the underlying findings for auditability.
- The CLI reads a local JSON file and prints a machine-readable report.

## Run it yourself

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m iam_least_privilege_auditor examples/sample.json
```

## Deployment direction

In a real CI/CD workflow, export the proposed IAM policy during the plan/build stage, audit the file, save the JSON report as an artifact, and require a protected-environment approval when findings exist. Keep AWS credentials and any `terraform apply` command outside the auditor.

## What to study

1. Why IAM `Action` and `Resource` accept both strings and arrays.
2. Why `iam:PassRole` plus `Resource: "*"` creates an escalation path.
3. Why deny statements should not be reported as excess allowed permission.
4. Why deterministic controls are easier to audit than a model-only security decision.
5. How human approval separates evidence generation from production mutation.

## Interview positioning

“I built a deterministic IAM least-privilege auditor that turns policy JSON into statement-level security evidence. I added CI and tests for wildcard, escalation, and scoping scenarios, then designed the workflow so AI can explain findings without controlling production authorization.”

## Next improvements

- Add AWS IAM Access Analyzer validation.
- Evaluate permission boundaries and SCP context.
- Emit SARIF for code-scanning annotations.
- Add optional AI explanations grounded only in deterministic findings.

This project demonstrates Python automation, AWS IAM knowledge, CI/CD guardrails, security engineering, and approval-first AI orchestration.
