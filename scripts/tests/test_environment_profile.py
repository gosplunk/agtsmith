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
    apply_environment_query_constraints,
    build_environment_context,
    build_tag_context,
    extract_indexes_from_query,
    extract_sourcetypes_from_query,
    resolve_authoritative_domains_for_question,
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

    def test_resolve_authoritative_domains_prefers_semantic_auth_index_not_name(self) -> None:
        profile = {
            "indexes": [
                {"index": "_audit", "sourcetypes": ["audittrail"]},
                {"index": "soc_linux", "sourcetypes": ["auditd", "linux_secure"]},
                {"index": "misc_web", "sourcetypes": ["access_combined"]},
            ],
            "sourcetype_to_indexes": {
                "audittrail": ["_audit"],
                "auditd": ["soc_linux"],
                "linux_secure": ["soc_linux"],
                "access_combined": ["misc_web"],
            },
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            hints = resolve_authoritative_domains_for_question(
                "Show failed login activity in the last 24 hours",
                "failed_login_activity",
                profile_path=path,
            )
            self.assertTrue(hints)
            self.assertEqual(hints[0]["index"], "soc_linux")
            self.assertIn("linux", hints[0]["styles"])

    def test_apply_environment_query_constraints_rewrites_generic_linux_auth_query(self) -> None:
        profile = {
            "indexes": [
                {"index": "soc_linux", "sourcetypes": ["auditd", "linux_secure"]},
            ],
            "sourcetype_to_indexes": {
                "auditd": ["soc_linux"],
                "linux_secure": ["soc_linux"],
            },
        }
        query = (
            'search index=linux (source="/var/log/auth.log" OR source="/var/log/secure") '
            '("Failed password" OR "authentication failure") '
            '| append [ search (index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog (EventCode=4625 OR EventID=4625) ] '
            '| stats count by index host user_name src_ip'
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            rendered = apply_environment_query_constraints(
                "Show failed login activity in the last 24 hours",
                "failed_login_activity",
                query,
                profile_path=path,
            )
            self.assertIn("index=soc_linux", rendered)
            self.assertNotIn("index=linux", rendered)
            self.assertNotIn("index=windows", rendered)
            self.assertNotIn("index=windows_sysmon", rendered)
            self.assertNotIn("/var/log/auth.log", rendered)
            self.assertNotIn("/var/log/secure", rendered)
            self.assertTrue("sourcetype=auditd" in rendered or "sourcetype=linux_secure" in rendered)
            self.assertNotIn("| append [", rendered)

    def test_apply_environment_query_constraints_preserves_distinct_windows_domain_when_present(self) -> None:
        profile = {
            "indexes": [
                {"index": "soc_linux", "sourcetypes": ["linux_secure"]},
                {"index": "soc_windows", "sourcetypes": ["XmlWinEventLog:Security"]},
            ],
            "sourcetype_to_indexes": {
                "linux_secure": ["soc_linux"],
                "XmlWinEventLog:Security": ["soc_windows"],
            },
        }
        query = (
            'search index=linux (source="/var/log/auth.log" OR source="/var/log/secure") ("Failed password") '
            '| append [ search (index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog (EventCode=4625 OR EventID=4625) ] '
            '| stats count by index host user_name src_ip'
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            rendered = apply_environment_query_constraints(
                "Show failed login activity across Linux and Windows in the last 24 hours",
                "failed_login_activity",
                query,
                profile_path=path,
            )
            self.assertIn("index=soc_linux", rendered)
            self.assertIn("index=soc_windows", rendered)
            self.assertNotIn("index=linux", rendered)
            self.assertNotIn("index=windows_sysmon", rendered)

    def test_apply_environment_query_constraints_drops_sysmon_only_windows_branch_for_failed_logins(self) -> None:
        profile = {
            "indexes": [
                {"index": "soc_linux", "sourcetypes": ["auditd", "linux_secure"]},
                {"index": "soc_sysmon", "sourcetypes": ["XmlWinEventLog"]},
            ],
            "sourcetype_to_indexes": {
                "auditd": ["soc_linux"],
                "linux_secure": ["soc_linux"],
                "XmlWinEventLog": ["soc_sysmon"],
            },
            "sourcetype_field_inventory": {
                "auditd": {"interesting_fields": ["acct", "addr", "host"]},
                "linux_secure": {"interesting_fields": ["user", "src_ip", "host"]},
                "XmlWinEventLog": {"interesting_fields": ["Image", "DestinationIp", "QueryName", "Computer"]},
            },
        }
        query = (
            'search index=linux (source="/var/log/auth.log" OR source="/var/log/secure") '
            '("Failed password" OR "authentication failure") '
            '| append [ search (index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog (EventCode=4625 OR EventID=4625 OR "An account failed to log on") ] '
            '| stats count by index host user_name src_ip'
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            rendered = apply_environment_query_constraints(
                "Show failed login activity in the last 24 hours",
                "failed_login_activity",
                query,
                profile_path=path,
            )
            self.assertIn("index=soc_linux", rendered)
            self.assertNotIn("soc_sysmon", rendered)
            self.assertNotIn("| append [", rendered)

    def test_apply_environment_query_constraints_rewrites_web_access_sourcetype(self) -> None:
        profile = {
            "indexes": [
                {"index": "soc_web", "sourcetypes": ["apache:access", "apache:error"]},
            ],
            "sourcetype_to_indexes": {
                "apache:access": ["soc_web"],
                "apache:error": ["soc_web"],
            },
            "sourcetype_field_inventory": {
                "apache:access": {"interesting_fields": ["host", "src", "status", "request"]},
                "apache:error": {"interesting_fields": ["host", "src", "error_code", "error_message"]},
            },
        }
        query = "search index=linux sourcetype=access_combined | stats count by clientip status method | sort - count"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            rendered = apply_environment_query_constraints(
                "Show top Apache client IPs in the last 24 hours",
                "apache_access_top_ips",
                query,
                profile_path=path,
            )
            self.assertIn("index=soc_web", rendered)
            self.assertIn("sourcetype=apache:access", rendered)
            self.assertNotIn("index=linux", rendered)
            self.assertNotIn("sourcetype=access_combined", rendered)

    def test_apply_environment_query_constraints_rewrites_generic_main_cloudtrail_query(self) -> None:
        profile = {
            "indexes": [{"index": "soc_cloud", "sourcetypes": ["aws:cloudtrail"]}],
            "sourcetype_to_indexes": {"aws:cloudtrail": ["soc_cloud"]},
            "sourcetype_field_inventory": {
                "aws:cloudtrail": {"interesting_fields": ["eventSource", "eventName", "sourceIPAddress"]}
            },
        }
        query = "search index=main sourcetype=aws:cloudtrail | stats count by eventSource eventName sourceIPAddress"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            rendered = apply_environment_query_constraints(
                "Investigate CloudTrail activity by event name and service in the last 24 hours",
                "aws_cloudtrail_activity",
                query,
                profile_path=path,
            )
            self.assertIn("index=soc_cloud", rendered)
            self.assertNotIn("index=main", rendered)

    def test_apply_environment_query_constraints_drops_sysmon_only_windows_branch_for_success_logins(self) -> None:
        profile = {
            "indexes": [
                {"index": "soc_linux", "sourcetypes": ["auditd", "linux_secure"]},
                {"index": "soc_sysmon", "sourcetypes": ["XmlWinEventLog"]},
            ],
            "sourcetype_to_indexes": {
                "auditd": ["soc_linux"],
                "linux_secure": ["soc_linux"],
                "XmlWinEventLog": ["soc_sysmon"],
            },
            "sourcetype_field_inventory": {
                "auditd": {"interesting_fields": ["acct", "addr", "host"]},
                "linux_secure": {"interesting_fields": ["user", "src_ip", "host"]},
                "XmlWinEventLog": {"interesting_fields": ["Image", "DestinationIp", "QueryName", "Computer"]},
            },
        }
        query = (
            'search ((index=linux (source="/var/log/auth.log" OR source="/var/log/secure") '
            '("Accepted password" OR "Accepted publickey" OR "Accepted keyboard-interactive/pam" OR "session opened for user")) '
            'OR ((index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog '
            '(EventCode=4624 OR EventID=4624 OR "An account was successfully logged on"))) '
            '| stats count by index host user_name src_ip auth_port'
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            rendered = apply_environment_query_constraints(
                "Show successful login activity in the last 24 hours",
                "successful_login_activity",
                query,
                profile_path=path,
            )
            self.assertIn("index=soc_linux", rendered)
            self.assertNotIn("soc_sysmon", rendered)
            self.assertNotIn("EventCode=4624", rendered)


if __name__ == "__main__":
    unittest.main()
