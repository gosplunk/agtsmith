import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from environment_profile import _auth_sourcetype_clause, apply_environment_query_constraints
from minimal_question_to_answer import map_question_to_template


class EnvironmentProfileQueryConstraintTests(unittest.TestCase):
    def _write_profile(self, payload: dict) -> Path:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        with tmp:
            json.dump(payload, tmp)
        return Path(tmp.name)

    def test_failed_login_query_does_not_inherit_web_domain_rewrites(self) -> None:
        template = map_question_to_template("Show failed login activity in the last 24 hours")
        profile_payload = {
            "indexes": [
                {"index": "soc_web", "sourcetypes": ["access_combined"]},
                {"index": "soc_windows", "sourcetypes": ["XmlWinEventLog"]},
            ],
            "sourcetype_semantics": {
                "access_combined": {"use_cases": ["failed_login_activity", "linux_auth_failures", "linux_session_activity", "web_scanning"]},
                "XmlWinEventLog": {"use_cases": ["windows_auth_failures"]},
            },
            "sourcetype_field_inventory": {
                "access_combined": {"fields": [{"name": "clientip", "populated_pct": 1.0}]},
                "XmlWinEventLog": {
                    "fields": [
                        {"name": "TargetUserName", "populated_pct": 1.0},
                        {"name": "IpAddress", "populated_pct": 1.0},
                        {"name": "EventCode", "populated_pct": 1.0},
                    ]
                },
            },
        }
        profile_path = self._write_profile(profile_payload)
        try:
            rewritten = apply_environment_query_constraints(
                "Show failed login activity in the last 24 hours",
                template.intent,
                template.query,
                profile_path=profile_path,
            )
        finally:
            profile_path.unlink(missing_ok=True)

        self.assertNotIn("index=soc_web", rewritten)
        self.assertNotIn("sourcetype=access_combined", rewritten)
        self.assertIn('source="/var/log/auth.log"', rewritten)
        self.assertIn("(index=windows OR index=windows_sysmon)", rewritten)

        linux_template = map_question_to_template("Show failed SSH login activity in the last 24 hours on my linux systems.")
        profile_path = self._write_profile(profile_payload)
        try:
            linux_rewritten = apply_environment_query_constraints(
                "Show failed SSH login activity in the last 24 hours on my linux systems.",
                linux_template.intent,
                linux_template.query,
                profile_path=profile_path,
            )
        finally:
            profile_path.unlink(missing_ok=True)

        self.assertNotIn("index=soc_web", linux_rewritten)
        self.assertNotIn("sourcetype=access_combined", linux_rewritten)
        self.assertIn('source="/var/log/auth.log"', linux_rewritten)

    def test_auth_sourcetype_clause_prefers_auth_like_sourcetypes(self) -> None:
        clause = _auth_sourcetype_clause(
            {
                "sourcetypes": [
                    "access_combined",
                    "alternatives.log-too_small",
                    "auth.log",
                    "linux_secure",
                ]
            },
            {
                "access_combined": {"use_cases": ["web_scanning"]},
                "alternatives.log-too_small": {"use_cases": []},
                "auth.log": {"use_cases": ["linux_auth_failures"]},
                "linux_secure": {"use_cases": ["linux_auth_failures"]},
            },
        )

        self.assertIn("sourcetype=auth.log", clause)
        self.assertIn("sourcetype=linux_secure", clause)
        self.assertNotIn("sourcetype=access_combined", clause)


if __name__ == "__main__":
    unittest.main()
