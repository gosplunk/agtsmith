#!/usr/bin/env python3
"""Regression tests for profile-driven live benchmark oracles."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from run_live_domain_benchmark import BenchmarkCase, _resolve_case_domain


class LiveDomainBenchmarkTests(unittest.TestCase):
    def test_platform_affinity_avoids_generic_mixed_index(self) -> None:
        profile = {
            "indexes": [
                {
                    "index": "agtsmith_test",
                    "sourcetypes": ["auth.log", "XmlWinEventLog"],
                },
                {
                    "index": "linux",
                    "sourcetypes": ["auth.log"],
                },
            ],
            "sourcetype_to_indexes": {
                "auth.log": ["agtsmith_test", "linux"],
            },
        }
        case = BenchmarkCase(
            id="linux-auth",
            theme="auth",
            question="Show failed SSH logins on Linux hosts",
            intent="linux_auth_failures",
            profile_domain_hints={
                "platform": "linux",
                "preferred_sourcetypes": ["auth.log"],
            },
            expected_shape="stats",
            required_terms=(),
            forbidden_patterns=(),
            allow_zero_rows=False,
            min_rows=1,
        )
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            with mock.patch(
                "run_live_domain_benchmark."
                "resolve_authoritative_domains_for_question",
                return_value=[],
            ):
                _, primary = _resolve_case_domain(case, profile_path)
        self.assertIsNotNone(primary)
        self.assertEqual(primary["index"], "linux")

    def test_explicit_sourcetype_hint_beats_fuzzy_domain_ranking(self) -> None:
        profile = {
            "indexes": [
                {
                    "index": "linux",
                    "sourcetypes": ["duo-desktop-too_small"],
                },
                {
                    "index": "botsv3",
                    "sourcetypes": ["access_combined"],
                },
            ],
            "sourcetype_to_indexes": {
                "duo-desktop-too_small": ["linux"],
                "access_combined": ["botsv3"],
            },
        }
        case = BenchmarkCase(
            id="apache",
            theme="web",
            question="Show top web source IPs",
            intent="apache_access_top_ips",
            profile_domain_hints={
                "platform": "web",
                "preferred_sourcetypes": ["access_combined"],
            },
            expected_shape="stats",
            required_terms=(),
            forbidden_patterns=(),
            allow_zero_rows=False,
            min_rows=1,
        )
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            with mock.patch(
                "run_live_domain_benchmark."
                "resolve_authoritative_domains_for_question",
                return_value=[
                    {
                        "index": "linux",
                        "sourcetypes": ["duo-desktop-too_small"],
                    }
                ],
            ):
                _, primary = _resolve_case_domain(case, profile_path)
        self.assertIsNotNone(primary)
        self.assertEqual(primary["index"], "botsv3")
        self.assertIn("access_combined", primary["sourcetypes"])


if __name__ == "__main__":
    unittest.main()
