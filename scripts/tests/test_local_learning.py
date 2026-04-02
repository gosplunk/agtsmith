#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from local_learning import (
    _approved_learning_state_summary,
    _candidate,
    _candidate_writer_target_intents,
    _learning_record_fingerprint,
    _proposal_values,
)


class TestLocalLearning(unittest.TestCase):
    def test_proposal_values_filters_legacy_sourcetypes(self) -> None:
        proposal = {
            "preferred_sourcetypes": [
                "auth-too_small",
                "auth.log",
                "linux_secure",
                "secure-too_small",
            ]
        }
        self.assertEqual(
            _proposal_values(proposal, "preferred_sourcetypes"),
            ["auth.log", "linux_secure"],
        )

    def test_candidate_sanitizes_legacy_sourcetypes(self) -> None:
        row = _candidate(
            intent="linux_auth_failures",
            kind="preferred_sources",
            proposal={
                "preferred_index": "linux",
                "preferred_sources": ["/var/log/auth.log"],
                "preferred_sourcetypes": ["auth-too_small", "auth.log", "linux_secure"],
            },
            reason="Linux auth logs include auth-too_small and auth.log.",
        )
        self.assertEqual(
            row["proposal"]["preferred_sourcetypes"],
            ["auth.log", "linux_secure"],
        )
        self.assertNotIn("auth-too_small", row["reason"])

    def test_candidate_writer_target_intents_limit_scope(self) -> None:
        self.assertEqual(
            _candidate_writer_target_intents(
                {"intent": "linux_auth_failures", "kind": "preferred_sources"},
                ["linux_auth_failures", "failed_login_activity", "apache_access_top_ips"],
            ),
            ["failed_login_activity", "linux_auth_failures"],
        )
        self.assertEqual(
            _candidate_writer_target_intents(
                {"intent": "failed_login_activity", "kind": "post_result_pivot_hint"},
                ["failed_login_activity"],
            ),
            [],
        )

    def test_learning_record_fingerprint_ignores_legacy_sourcetype_noise(self) -> None:
        first = _candidate(
            intent="linux_auth_failures",
            kind="preferred_sources",
            proposal={
                "preferred_index": "linux",
                "preferred_sources": ["/var/log/auth.log"],
                "preferred_sourcetypes": ["auth-too_small", "auth.log"],
            },
            reason="first",
        )
        second = _candidate(
            intent="linux_auth_failures",
            kind="preferred_sources",
            proposal={
                "preferred_index": "linux",
                "preferred_sources": ["/var/log/auth.log"],
                "preferred_sourcetypes": ["auth.log"],
            },
            reason="second",
        )
        self.assertEqual(_learning_record_fingerprint(first), _learning_record_fingerprint(second))

    def test_approved_learning_state_summary_reports_active_hints(self) -> None:
        summary = _approved_learning_state_summary(
            [
                {
                    "intent": "linux_auth_failures",
                    "kind": "preferred_sources",
                    "proposal": {"preferred_sources": ["/var/log/auth.log"]},
                    "status": "approved",
                },
                {
                    "intent": "apache_access_top_ips",
                    "kind": "preferred_fields",
                    "proposal": {"preferred_fields": ["clientip"]},
                    "status": "approved",
                },
            ]
        )
        self.assertTrue(summary["active"])
        self.assertEqual(summary["approved_count"], 2)
        self.assertEqual(summary["intents"], ["apache_access_top_ips", "linux_auth_failures"])
        self.assertEqual(summary["kinds"], ["preferred_fields", "preferred_sources"])


if __name__ == "__main__":
    unittest.main()
