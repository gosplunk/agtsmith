#!/usr/bin/env python3
"""Unit tests for environment profile helpers."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from environment_profile import (
    apply_environment_query_constraints,
    build_environment_context,
    build_tag_context,
    extract_indexes_from_query,
    extract_sourcetypes_from_query,
    infer_index_aliases_from_profile,
    load_index_alias_overrides,
    normalize_query_index_aliases,
    save_index_alias_overrides,
    resolve_authoritative_domains_for_question,
    suggest_domains_for_question,
    validate_query_against_environment,
)
from intent_field_contracts import validate_platform_sourcetype_coherence
from query_templates import TEMPLATES
from build_environment_profile import (
    _build_sourcetype_field_inventory,
    _field_summary_query,
)


class EnvironmentProfileTests(unittest.TestCase):
    def test_field_inventory_excludes_legacy_malformed_generator_events(self) -> None:
        query = _field_summary_query(
            ["botsv3"],
            "XmlWinEventLog",
            200,
        )
        self.assertIn(
            "(NOT lab_data_source=agtsmith_generator OR "
            "lab_data_version=fidelity_v2)",
            query,
        )
        self.assertIn('sourcetype="XmlWinEventLog"', query)

    def test_selected_field_inventory_refreshes_multiple_sourcetypes(self) -> None:
        rows = [
            {
                "index": "botsv3",
                "sourcetypes": ["XmlWinEventLog", "stream:dns"],
            },
            {
                "index": "aws_prod",
                "sourcetypes": ["aws:cloudtrail"],
            },
        ]
        query_result = {
            "structured": {
                "results": [
                    {
                        "field": "host",
                        "count": "10",
                        "distinct_count": "2",
                        "values": ["host-a", "host-b"],
                    }
                ]
            }
        }
        with mock.patch(
            "build_environment_profile.run_splunk_query_args",
            return_value=query_result,
        ) as run_query:
            inventory, meta = _build_sourcetype_field_inventory(
                rows=rows,
                earliest_time="-24h",
                latest_time="now",
                existing_profile={},
                refresh_mode="one",
                requested_sourcetype=(
                    "XmlWinEventLog,aws:cloudtrail,not-present"
                ),
                sample_size=25,
                field_row_limit=20,
            )
        self.assertEqual(
            set(inventory),
            {"XmlWinEventLog", "aws:cloudtrail"},
        )
        self.assertEqual(meta["effective_refresh_mode"], "selected")
        self.assertEqual(meta["unknown_requested_sourcetypes"], ["not-present"])
        self.assertEqual(meta["target_count"], 2)
        self.assertEqual(run_query.call_count, 2)

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

    def test_apply_environment_query_constraints_preserves_windows_branch_on_botsv3_mixed_lab(self) -> None:
        profile = {
            "indexes": [
                {"index": "linux", "sourcetypes": ["auth.log", "syslog"]},
                {"index": "botsv3", "sourcetypes": ["access_combined", "XmlWinEventLog", "linux_secure"]},
            ],
            "sourcetype_to_indexes": {
                "auth.log": ["linux"],
                "syslog": ["linux"],
                "access_combined": ["botsv3"],
                "XmlWinEventLog": ["botsv3"],
                "linux_secure": ["botsv3"],
            },
            "sourcetype_field_inventory": {
                "auth.log": {"interesting_fields": ["user", "src_ip", "host"]},
                "XmlWinEventLog": {"interesting_fields": ["TargetUserName", "Source_Network_Address", "EventCode"]},
            },
        }
        query = (
            'search ('
            '(index=linux (source="/var/log/auth.log" OR source="/var/log/secure") ("Failed password")) '
            'OR '
            '((index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog (EventCode=4625 OR EventID=4625))'
            ') '
            '| eval platform=case(match(index,"(?i)linux"),"linux",true(),"windows") '
            '| stats count by platform index host user_name src_ip'
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            rendered = apply_environment_query_constraints(
                "Show failed login activity in the last 7 days on my windows or linux machines.",
                "failed_login_activity",
                query,
                profile_path=path,
            )
            self.assertIn("index=linux", rendered)
            self.assertIn("index=botsv3", rendered)
            self.assertIn("4625", rendered)
            self.assertIn("platform", rendered)

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

    def test_single_index_botsv3_failed_login_keeps_platform_sourcetypes_separate(self) -> None:
        """Repro: single-index botsv3 must not pair linux_secure with EventCode=4625."""
        profile = {
            "indexes": [
                {
                    "index": "botsv3",
                    "sourcetypes": ["linux_secure", "XmlWinEventLog", "WinEventLog:Security"],
                    "styles": ["linux", "windows"],
                }
            ],
            "sourcetype_to_indexes": {
                "linux_secure": ["botsv3"],
                "XmlWinEventLog": ["botsv3"],
                "WinEventLog:Security": ["botsv3"],
            },
        }
        template = next(item for item in TEMPLATES if item.intent == "failed_login_activity")
        question = "Show failed logon activity in the last 24 hours"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            rendered = apply_environment_query_constraints(
                question,
                "failed_login_activity",
                template.query,
                profile_path=path,
            )
            append_start = rendered.lower().find("| append [")
            self.assertGreater(append_start, 0, "expected cross-platform append branch")
            append_block = rendered[append_start:]
            main_branch = rendered[:append_start]

            self.assertIn("index=botsv3", rendered)
            self.assertIn("linux_secure", main_branch)
            self.assertNotRegex(main_branch.lower(), r"eventcode=4625|eventid=4625")
            self.assertRegex(append_block.lower(), r"xmlwineventlog|wineventlog:security")
            self.assertRegex(append_block.lower(), r"eventcode=4625|eventid=4625")
            self.assertNotIn("linux_secure", append_block)

            coherent, reason = validate_platform_sourcetype_coherence(rendered, "failed_login_activity")
            self.assertTrue(coherent, reason)

    def test_resolve_authoritative_domains_prefers_linux_over_botsv3_for_auth(self) -> None:
        profile = {
            "indexes": [
                {
                    "index": "botsv3",
                    "sourcetypes": ["linux_secure", "XmlWinEventLog", "access_combined"],
                },
                {
                    "index": "linux",
                    "sourcetypes": ["auth.log", "linux_secure", "syslog"],
                },
            ],
            "sourcetype_to_indexes": {
                "linux_secure": ["linux", "botsv3"],
                "auth.log": ["linux"],
                "syslog": ["linux"],
                "XmlWinEventLog": ["botsv3"],
                "access_combined": ["linux", "botsv3"],
            },
            "index_sourcetype_field_inventory": {
                "linux": {
                    "auth.log": {
                        "interesting_field_examples": [
                            {"field": "user", "sample_values": ["root"], "count": 10},
                            {"field": "rhost", "sample_values": ["10.0.0.8"], "count": 10},
                        ]
                    }
                },
                "botsv3": {
                    "linux_secure": {
                        "interesting_field_examples": [
                            {"field": "user", "sample_values": ["root"], "count": 10},
                            {"field": "rhost", "sample_values": ["10.0.0.8"], "count": 10},
                        ]
                    },
                    "XmlWinEventLog": {
                        "interesting_field_examples": [
                            {"field": "TargetUserName", "sample_values": ["alice"], "count": 10},
                            {"field": "EventCode", "sample_values": ["4625"], "count": 10},
                        ]
                    },
                },
            },
        }
        question = "Failed logons in the last 24 hours"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            hints = resolve_authoritative_domains_for_question(
                question,
                "failed_login_activity",
                profile_path=path,
            )
            self.assertTrue(hints)
            self.assertEqual(hints[0]["index"], "linux")
            self.assertIn("auth.log", hints[0]["sourcetypes"])

    def test_failed_logons_real_profile_like_fixture_is_linux_only(self) -> None:
        profile = {
            "indexes": [
                {"index": "linux", "sourcetypes": ["auth.log", "linux_secure", "syslog"]},
                {"index": "botsv3", "sourcetypes": ["linux_secure", "XmlWinEventLog", "access_combined"]},
            ],
            "sourcetype_to_indexes": {
                "auth.log": ["linux"],
                "linux_secure": ["linux", "botsv3"],
                "syslog": ["linux"],
                "XmlWinEventLog": ["botsv3"],
                "access_combined": ["linux", "botsv3"],
            },
            "index_sourcetype_field_inventory": {
                "linux": {
                    "auth.log": {
                        "interesting_field_examples": [
                            {"field": "user", "sample_values": ["root"], "count": 10},
                            {"field": "rhost", "sample_values": ["10.0.0.8"], "count": 10},
                        ]
                    }
                },
                "botsv3": {
                    "linux_secure": {
                        "interesting_field_examples": [
                            {"field": "user", "sample_values": ["root"], "count": 10},
                            {"field": "rhost", "sample_values": ["10.0.0.8"], "count": 10},
                        ]
                    },
                    "XmlWinEventLog": {
                        "interesting_field_examples": [
                            {"field": "TargetUserName", "sample_values": ["alice"], "count": 10},
                            {"field": "EventCode", "sample_values": ["4625"], "count": 10},
                        ]
                    },
                },
            },
        }
        question = "Failed logons in the last 24 hours"
        template = next(item for item in TEMPLATES if item.intent == "linux_auth_failures")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            from minimal_question_to_answer import map_question_to_template, template_to_query_args

            mapped = map_question_to_template(question, profile_path=path)
            self.assertEqual(mapped.intent, "linux_auth_failures")
            args = template_to_query_args(mapped, question, profile_path=path)
            rendered = str(args.get("query", ""))
            self.assertIn("index=linux", rendered)
            self.assertIn("sourcetype=auth.log", rendered)
            self.assertNotIn("4625", rendered)
            self.assertNotIn("| append [", rendered)

            coherent, reason = validate_platform_sourcetype_coherence(rendered, "linux_auth_failures")
            self.assertTrue(coherent, reason)

    def test_windows_auth_failures_resolves_botsv3_without_field_inventory(self) -> None:
        profile = {
            "indexes": [
                {
                    "index": "botsv3",
                    "sourcetypes": ["linux_secure", "XmlWinEventLog", "access_combined"],
                },
            ],
            "sourcetype_to_indexes": {
                "linux_secure": ["botsv3"],
                "XmlWinEventLog": ["botsv3"],
                "access_combined": ["botsv3"],
            },
            "sourcetype_field_inventory": {},
            "index_sourcetype_field_inventory": {},
        }
        question = "Show Windows failed logon events (EventCode 4625) in the last 24 hours"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            domains = resolve_authoritative_domains_for_question(
                question,
                "windows_auth_failures",
                profile_path=path,
            )
            self.assertTrue(domains, "expected botsv3 domain for windows_auth_failures")
            self.assertEqual(domains[0]["index"], "botsv3")
            self.assertTrue(
                any(st.lower() == "xmlwineventlog" for st in domains[0].get("sourcetypes", [])),
                domains[0].get("sourcetypes"),
            )

            template_query = (
                "search (index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog "
                "(EventCode=4625 OR EventID=4625 OR \"An account failed to log on\") "
                "| eval src_ip=coalesce(Source_Network_Address,IpAddress,src,src_ip) "
                "| table _time host user_name src_ip EventCode"
            )
            rendered = apply_environment_query_constraints(
                question,
                "windows_auth_failures",
                template_query,
                profile_path=path,
            )
            self.assertIn("index=botsv3", rendered)
            self.assertNotIn("index=windows", rendered)


class IndexAliasTests(unittest.TestCase):
    def test_normalize_query_index_aliases_windows_to_botsv3(self) -> None:
        profile = {
            "indexes": [{"index": "botsv3", "sourcetypes": ["XmlWinEventLog"]}],
            "sourcetype_to_indexes": {"XmlWinEventLog": ["botsv3"]},
        }
        query = (
            'search (index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog '
            '(EventCode=4625 OR EventID=4625) | stats count by host'
        )
        normalized = normalize_query_index_aliases(query, profile)
        self.assertIn("index=botsv3", normalized)
        self.assertNotIn("index=windows", normalized)

    def test_infer_index_aliases_soc_windows(self) -> None:
        profile = {
            "indexes": [
                {"index": "soc_linux", "sourcetypes": ["linux_secure"]},
                {"index": "soc_windows", "sourcetypes": ["XmlWinEventLog"]},
            ],
            "sourcetype_to_indexes": {
                "linux_secure": ["soc_linux"],
                "XmlWinEventLog": ["soc_windows"],
            },
        }
        aliases = infer_index_aliases_from_profile(profile)
        self.assertEqual(aliases.get("windows"), "soc_windows")
        self.assertEqual(aliases.get("soc_windows"), "soc_windows")

    def test_inferred_alias_does_not_shadow_concrete_main_index(self) -> None:
        profile = {
            "indexes": [
                {"index": "main", "sourcetypes": ["netstat"]},
                {"index": "aws_prod", "sourcetypes": ["aws:cloudtrail"]},
            ],
            "sourcetype_to_indexes": {
                "netstat": ["main"],
                "aws:cloudtrail": ["aws_prod"],
            },
        }
        aliases = infer_index_aliases_from_profile(profile)
        self.assertNotIn("main", aliases)
        normalized = normalize_query_index_aliases(
            'search index="main" sourcetype="netstat" | stats count',
            profile,
        )
        self.assertIn('index="main"', normalized)
        self.assertNotIn("index=aws_prod sourcetype=netstat", normalized)

    def test_save_and_load_index_alias_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "aliases.json"
            save_index_alias_overrides({"windows": "prod_win", "main": "aws_prod"}, path=path)
            loaded = load_index_alias_overrides(path=path)
            self.assertEqual(loaded.get("windows"), "prod_win")
            self.assertEqual(loaded.get("main"), "aws_prod")

    def test_validate_environment_accepts_alias_index(self) -> None:
        profile = {
            "indexes": [{"index": "botsv3", "sourcetypes": ["XmlWinEventLog"]}],
            "sourcetype_to_indexes": {"XmlWinEventLog": ["botsv3"]},
            "index_aliases": {"windows": "botsv3"},
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            ok, reason = validate_query_against_environment(
                {
                    "query": "search index=windows sourcetype=XmlWinEventLog EventCode=4625 | stats count by host",
                    "earliest_time": "-24h",
                    "latest_time": "now",
                    "row_limit": 20,
                },
                profile_path=path,
            )
            self.assertTrue(ok, reason)


if __name__ == "__main__":
    unittest.main()
