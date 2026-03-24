#!/usr/bin/env python3
"""Unit tests for environment profile helpers."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from environment_profile import (
    build_environment_context,
    build_tag_context,
    extract_indexes_from_query,
    extract_sourcetypes_from_query,
    suggest_domains_for_question,
    validate_query_against_environment,
)


class EnvironmentProfileTests(unittest.TestCase):
    def test_extract_index_and_sourcetype_tokens(self) -> None:
        q = 'search index=linux sourcetype="access_combined" OR sourcetype=auth.log | stats count'
        self.assertEqual(extract_indexes_from_query(q), ["linux"])
        self.assertEqual(extract_sourcetypes_from_query(q), ["access_combined", "auth.log"])

    def test_validate_query_with_known_index_and_sourcetype(self) -> None:
        profile = {
            "indexes": [
                {"index": "linux", "sourcetypes": ["access_combined", "auth.log"]},
                {"index": "_audit", "sourcetypes": ["audittrail"]},
            ],
            "sourcetype_to_indexes": {
                "access_combined": ["linux"],
                "auth.log": ["linux"],
                "audittrail": ["_audit"],
            },
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            ok, reason = validate_query_against_environment(
                {"query": 'search index=linux sourcetype="access_combined" | stats count'},
                profile_path=path,
            )
            self.assertTrue(ok, reason)
            self.assertEqual(reason, "environment_query_ok")

    def test_validate_query_blocks_mismatched_sourcetype(self) -> None:
        profile = {
            "indexes": [
                {"index": "linux", "sourcetypes": ["auth.log"]},
                {"index": "_audit", "sourcetypes": ["audittrail"]},
            ],
            "sourcetype_to_indexes": {"auth.log": ["linux"], "audittrail": ["_audit"]},
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            ok, reason = validate_query_against_environment(
                {"query": 'search index=linux sourcetype="audittrail" | stats count'},
                profile_path=path,
            )
            self.assertFalse(ok)
            self.assertIn("environment_sourcetype_not_in_index", reason)

    def test_context_builder_includes_indexes(self) -> None:
        profile = {
            "indexes": [{"index": "linux", "sourcetypes": ["access_combined", "auth.log"]}],
            "sourcetype_to_indexes": {"access_combined": ["linux"], "auth.log": ["linux"]},
            "sourcetype_semantics": {
                "access_combined": {"description": "Apache/Nginx style web access logs."},
                "auth.log": {"description": "Auth log events."},
            },
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            ctx = build_environment_context("show apache top ips", profile_path=path)
            self.assertIn("index=linux", ctx)
            self.assertIn("access_combined", ctx)

    def test_context_builder_includes_known_fields_when_available(self) -> None:
        profile = {
            "indexes": [{"index": "linux", "sourcetypes": ["access_combined"]}],
            "sourcetype_to_indexes": {"access_combined": ["linux"]},
            "sourcetype_semantics": {
                "access_combined": {"description": "Apache/Nginx style web access logs."},
            },
            "sourcetype_field_inventory": {
                "access_combined": {
                    "interesting_field_examples": [
                        {"field": "clientip", "sample_values": ["203.0.113.10", "198.51.100.7"], "count": 200},
                        {"field": "status", "sample_values": ["200", "404"], "count": 200},
                    ]
                }
            },
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            ctx = build_environment_context("show apache top ips", profile_path=path)
            self.assertIn("access_combined fields:", ctx)
            self.assertIn("clientip", ctx)
            self.assertIn("203.0.113.10", ctx)

    def test_suggest_domains_for_question_prefers_non_internal_for_failed_logins(self) -> None:
        profile = {
            "indexes": [
                {"index": "_audit", "sourcetypes": ["audittrail"]},
                {"index": "linux", "sourcetypes": ["access_combined", "auth.log"]},
                {"index": "windows", "sourcetypes": ["XmlWinEventLog"]},
            ],
            "sourcetype_to_indexes": {
                "audittrail": ["_audit"],
                "access_combined": ["linux"],
                "auth.log": ["linux"],
                "XmlWinEventLog": ["windows"],
            },
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            hints = suggest_domains_for_question(
                "Show failed login activity in the last 24 hours",
                profile_path=path,
                max_indexes=3,
            )
            self.assertTrue(hints)
            self.assertEqual(hints[0]["index"], "linux")

    def test_suggest_domains_allows_internal_when_explicit(self) -> None:
        profile = {
            "indexes": [
                {"index": "_audit", "sourcetypes": ["audittrail"]},
                {"index": "linux", "sourcetypes": ["auth.log"]},
            ],
            "sourcetype_to_indexes": {
                "audittrail": ["_audit"],
                "auth.log": ["linux"],
            },
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            hints = suggest_domains_for_question(
                "Show Splunk internal failed login activity from _audit in the last 24 hours",
                profile_path=path,
                max_indexes=3,
            )
            self.assertTrue(hints)
            self.assertEqual(hints[0]["index"], "_audit")

    def test_build_tag_context_includes_relevant_tags(self) -> None:
        profile = {
            "tag_to_index_sourcetype": {
                "authentication": [{"index": "linux", "sourcetype": "auth.log"}],
                "web": [{"index": "linux", "sourcetype": "access_combined"}],
            }
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            ctx = build_tag_context(
                "Show failed login activity in the last 24 hours",
                profile_path=path,
            ).lower()
            self.assertIn("[cim_tag_profile]", ctx)
            self.assertIn("tag=authentication", ctx)


if __name__ == "__main__":
    unittest.main()
