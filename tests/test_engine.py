import unittest

from iam_least_privilege_auditor.engine import analyze


class EngineTests(unittest.TestCase):
    def test_global_wildcards_are_critical(self):
        result = analyze({"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
        rules = {finding["rule"] for finding in result["findings"]}
        self.assertEqual("critical", result["risk"])
        self.assertIn("GLOBAL_ACTION_WILDCARD", rules)
        self.assertIn("GLOBAL_RESOURCE_WILDCARD", rules)

    def test_pass_role_on_all_resources_flags_escalation(self):
        result = analyze(
            {"Statement": [{"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}]}
        )
        rules = {finding["rule"] for finding in result["findings"]}
        self.assertIn("PRIVILEGE_ESCALATION_ON_ALL_RESOURCES", rules)

    def test_service_wildcard_is_high_risk(self):
        result = analyze(
            {"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::reports/*"}}
        )
        self.assertEqual("high", result["risk"])

    def test_notaction_allow_is_flagged(self):
        result = analyze(
            {"Statement": {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}}
        )
        self.assertIn("ALLOW_WITH_NOTACTION", {f["rule"] for f in result["findings"]})

    def test_scoped_policy_has_no_findings(self):
        result = analyze(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::reports/prod/*",
                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}},
                }
            }
        )
        self.assertEqual("low", result["risk"])
        self.assertEqual(0, result["finding_count"])
        self.assertEqual("STANDARD REVIEW", result["recommendation"])

    def test_deny_statements_are_not_reported_as_excess_permissions(self):
        result = analyze({"Statement": {"Effect": "Deny", "Action": "*", "Resource": "*"}})
        self.assertEqual([], result["findings"])


if __name__ == "__main__":
    unittest.main()
