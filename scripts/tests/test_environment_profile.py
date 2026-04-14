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

    def test_validate_query_allows_known_botsv3_sourcetypes_when_recent_profile_is_empty(self) -> None:
        profile = {
            "indexes": [{"index": "botsv3", "sourcetypes": []}],
            "sourcetype_to_indexes": {},
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            ok, reason = validate_query_against_environment(
                {"query": 'search index=botsv3 sourcetype="aws:cloudtrail" | stats count by eventSource'},
                profile_path=path,
            )
            self.assertTrue(ok, reason)
            self.assertEqual(reason, "environment_query_ok")

    def test_validate_query_still_blocks_unknown_botsv3_sourcetypes(self) -> None:
        profile = {
            "indexes": [{"index": "botsv3", "sourcetypes": []}],
            "sourcetype_to_indexes": {},
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            ok, reason = validate_query_against_environment(
                {"query": 'search index=botsv3 sourcetype="not:a:real:demo:sourcetype" | stats count'},
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
            self.assertEqual(hints[0]["sourcetypes"][0], "auth.log")

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
                intent="internal_auth_failures",
                profile_path=path,
                max_indexes=3,
            )
            self.assertTrue(hints)
            self.assertEqual(hints[0]["index"], "_audit")

    def test_suggest_domains_keeps_cross_platform_auth_balanced(self) -> None:
        profile = {
            "indexes": [
                {"index": "linux", "sourcetypes": ["auth.log", "linux_secure", "auditd"]},
                {"index": "windows", "sourcetypes": ["XmlWinEventLog"]},
                {"index": "noise_linux", "sourcetypes": ["auth.log", "syslog", "secure"]},
            ],
            "sourcetype_to_indexes": {
                "auth.log": ["linux", "noise_linux"],
                "linux_secure": ["linux"],
                "auditd": ["linux"],
                "XmlWinEventLog": ["windows"],
            },
            "sourcetype_field_inventory": {
                "auth.log": {"interesting_fields": ["user", "rhost", "host"]},
                "linux_secure": {"interesting_fields": ["user", "src_ip", "host"]},
                "auditd": {"interesting_fields": ["acct", "addr", "host"]},
                "XmlWinEventLog": {"interesting_fields": ["TargetUserName", "IpAddress", "EventCode"]},
            },
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            hints = suggest_domains_for_question(
                "Show failed login activity across Windows and Linux in the last 24 hours.",
                intent="failed_login_activity",
                profile_path=path,
                max_indexes=3,
            )
            self.assertGreaterEqual(len(hints), 2)
            self.assertEqual(hints[0]["index"], "linux")
            self.assertEqual(hints[1]["index"], "windows")

    def test_suggest_domains_prefers_windows_sysmon_for_sysmon_questions(self) -> None:
        profile = {
            "indexes": [
                {"index": "windows", "sourcetypes": ["Script:ListeningPorts", "XmlWinEventLog"]},
                {"index": "windows_sysmon", "sourcetypes": ["XmlWinEventLog"]},
            ],
            "sourcetype_to_indexes": {
                "Script:ListeningPorts": ["windows"],
                "XmlWinEventLog": ["windows", "windows_sysmon"],
            },
            "sourcetype_field_inventory": {
                "Script:ListeningPorts": {"interesting_fields": ["port", "process_name", "host"]},
                "XmlWinEventLog": {"interesting_fields": ["Image", "DestinationIp", "DestinationPort", "Protocol", "QueryName"]},
            },
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            hints = suggest_domains_for_question(
                "Show Windows Sysmon network connections in the last 30 days with process image and destination IP.",
                intent="windows_sysmon_network_activity",
                profile_path=path,
                max_indexes=3,
            )
            self.assertTrue(hints)
            self.assertEqual(hints[0]["index"], "windows_sysmon")

    def test_apply_constraints_rewrites_windows_auth_to_environment_index(self) -> None:
        profile = {
            "indexes": [
                {"index": "soc_windows", "sourcetypes": ["XmlWinEventLog:Security", "XmlWinEventLog"]},
            ],
            "sourcetype_to_indexes": {
                "XmlWinEventLog:Security": ["soc_windows"],
                "XmlWinEventLog": ["soc_windows"],
            },
            "index_sourcetype_field_inventory": {
                "soc_windows": {
                    "XmlWinEventLog:Security": {
                        "interesting_field_examples": [
                            {"field": "TargetUserName", "sample_values": ["alice"], "count": 10},
                            {"field": "IpAddress", "sample_values": ["10.0.0.5"], "count": 10},
                            {"field": "EventCode", "sample_values": ["4625"], "count": 10},
                        ]
                    }
                }
            },
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            query = (
                "search (index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog "
                "(Channel=Security OR source=\"XmlWinEventLog:Security\") "
                "(EventCode=4625 OR EventID=4625 OR \"An account failed to log on\") "
                "| table _time Computer TargetUserName IpAddress"
            )
            rendered = apply_environment_query_constraints(
                "Show Windows failed login activity in the last 24 hours.",
                "windows_auth_failures",
                query,
                profile_path=path,
            )
            self.assertIn("index=soc_windows", rendered)
            self.assertNotIn("index=windows_sysmon", rendered)
            self.assertNotIn("index=windows ", rendered)

    def test_apply_constraints_rewrites_sysmon_to_discovered_index(self) -> None:
        profile = {
            "indexes": [
                {"index": "soc_windows", "sourcetypes": ["XmlWinEventLog:Security"]},
                {"index": "soc_sysmon", "sourcetypes": ["XmlWinEventLog"]},
            ],
            "sourcetype_to_indexes": {
                "XmlWinEventLog:Security": ["soc_windows"],
                "XmlWinEventLog": ["soc_sysmon"],
            },
            "index_sourcetype_field_inventory": {
                "soc_sysmon": {
                    "XmlWinEventLog": {
                        "interesting_field_examples": [
                            {"field": "QueryName", "sample_values": ["example.org"], "count": 10},
                            {"field": "Image", "sample_values": ["C:\\\\Windows\\\\System32\\\\nslookup.exe"], "count": 10},
                            {"field": "EventID", "sample_values": ["22"], "count": 10},
                        ]
                    }
                }
            },
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            query = (
                "search (index=windows_sysmon OR index=windows) sourcetype=XmlWinEventLog "
                "Channel=\"Microsoft-Windows-Sysmon/Operational\" "
                "(EventID=22 OR EventCode=22 OR QueryName=*) "
                "| table _time Computer Image QueryName"
            )
            rendered = apply_environment_query_constraints(
                "Show Windows Sysmon DNS queries in the last 24 hours.",
                "windows_sysmon_dns_activity",
                query,
                profile_path=path,
            )
            self.assertIn("index=soc_sysmon", rendered)
            self.assertNotIn("index=windows_sysmon", rendered)
            self.assertNotIn("index=windows ", rendered)

    def test_apply_constraints_rewrites_cross_platform_auth_to_discovered_indexes(self) -> None:
        profile = {
            "indexes": [
                {"index": "soc_linux", "sourcetypes": ["auth.log"]},
                {"index": "soc_windows", "sourcetypes": ["XmlWinEventLog:Security", "XmlWinEventLog"]},
            ],
            "sourcetype_to_indexes": {
                "auth.log": ["soc_linux"],
                "XmlWinEventLog:Security": ["soc_windows"],
                "XmlWinEventLog": ["soc_windows"],
            },
            "index_sourcetype_field_inventory": {
                "soc_linux": {
                    "auth.log": {
                        "interesting_field_examples": [
                            {"field": "user", "sample_values": ["root"], "count": 10},
                            {"field": "rhost", "sample_values": ["10.0.0.8"], "count": 10},
                        ]
                    }
                },
                "soc_windows": {
                    "XmlWinEventLog:Security": {
                        "interesting_field_examples": [
                            {"field": "TargetUserName", "sample_values": ["alice"], "count": 10},
                            {"field": "IpAddress", "sample_values": ["10.0.0.5"], "count": 10},
                            {"field": "EventCode", "sample_values": ["4625"], "count": 10},
                        ]
                    }
                },
            },
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            query = (
                "search ((index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
                "(\"Failed password\" OR \"authentication failure\")) OR "
                "((index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog "
                "(EventCode=4625 OR EventID=4625 OR \"An account failed to log on\"))) "
                "| stats count by index"
            )
            rendered = apply_environment_query_constraints(
                "Show failed login activity across Windows and Linux in the last 24 hours.",
                "failed_login_activity",
                query,
                profile_path=path,
            )
            self.assertIn("index=soc_linux", rendered)
            self.assertIn("index=soc_windows", rendered)
            self.assertNotIn("index=windows_sysmon", rendered)

    def test_suggest_domains_with_intent_down_ranks_irrelevant_web_sourcetypes(self) -> None:
        profile = {
            "indexes": [
                {"index": "soc_linux", "sourcetypes": ["access_combined", "linux_secure", "auth.log"]},
            ],
            "sourcetype_to_indexes": {
                "access_combined": ["soc_linux"],
                "linux_secure": ["soc_linux"],
                "auth.log": ["soc_linux"],
            },
            "sourcetype_field_inventory": {
                "access_combined": {"interesting_fields": ["clientip", "status", "uri_path"]},
                "linux_secure": {"interesting_fields": ["user", "src_ip", "host"]},
                "auth.log": {"interesting_fields": ["user", "rhost", "host"]},
            },
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            hints = suggest_domains_for_question(
                "Show failed login activity in the last 24 hours",
                intent="failed_login_activity",
                profile_path=path,
                max_indexes=3,
            )
            self.assertTrue(hints)
            self.assertEqual(hints[0]["index"], "soc_linux")
            self.assertEqual(hints[0]["sourcetypes"][:2], ["linux_secure", "auth.log"])
            self.assertNotEqual(hints[0]["sourcetypes"][0], "access_combined")

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
