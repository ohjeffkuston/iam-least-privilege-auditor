Imagine a production incident at 2:00 AM. An engineer grants `Action: "*"` to restore service quickly—and the temporary permission quietly becomes permanent.

For an organization, that single policy can expand the blast radius of a compromised workload, enable privilege escalation, and turn a routine exception into an audit finding or security incident.

The safest response is not another opaque automation layer. It is an evidence-first control that explains exactly why a policy is risky before anyone approves it.

I built the IAM Least-Privilege Auditor: a read-only Python guardrail that parses AWS IAM policy JSON and produces deterministic, testable findings.

- Detects global and service-level action wildcards
- Flags unrestricted resources and missing limiting conditions
- Identifies privilege-escalation paths such as `iam:PassRole` on every resource
- Produces statement-level evidence, severity, and remediation guidance
- Retains a human approval boundary and never changes cloud infrastructure

This is game-changing because it makes least-privilege review faster and more consistent without hiding security responsibility inside an AI response.

Which IAM permission would you never allow through a production pipeline without explicit approval? Share your view in the comments.
