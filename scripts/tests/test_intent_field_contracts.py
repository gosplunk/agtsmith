#!/usr/bin/env python3
"""Unit tests for deterministic intent field-contract validation."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from intent_field_contracts import validate_query_for_intent


class IntentFieldContractsTests(unittest.TestCase):
    def test_apache_top_ips_contract_passes_dataset_aligned_query(self) -> None:
        ok, reason = validate_query_for_intent(
            "apache_access_top_ips",
            {
                "query": "search index=linux sourcetype=access_combined | stats count by clientip status method | sort - count",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 10,
            },
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "intent_contract_ok")

    def test_apache_top_ips_contract_blocks_wrong_index_alias(self) -> None:
        ok, reason = validate_query_for_intent(
            "apache_access_top_ips",
            {
                "query": "search index=apache_access_logs sourcetype=access_combined | stats count by clientip | sort - count",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 10,
            },
        )
        self.assertFalse(ok)
        self.assertIn("intent_contract", reason)

    def test_linux_priv_escalation_requires_sudo_or_su(self) -> None:
        ok, reason = validate_query_for_intent(
            "linux_privilege_escalation",
            {
                "query": "search index=linux sourcetype=auth.log failed password | stats count by host",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 10,
            },
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "intent_contract_missing_group_3")

    def test_linux_auth_allows_eventtype_variant(self) -> None:
        ok, reason = validate_query_for_intent(
            "linux_auth_failures",
            {
                "query": "search index=linux eventtype=failed_login | stats count by host user src_ip port | sort - count",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 10,
            },
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "intent_contract_ok")

    def test_linux_auth_allows_field_native_stats_shape(self) -> None:
        ok, reason = validate_query_for_intent(
            "linux_auth_failures",
            {
                "query": (
                    "search index=linux sourcetype=auth.log (\"Failed password\" OR \"authentication failure\" OR \"Invalid user\") "
                    "| stats count by host user src_ip port | sort - count"
                ),
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 10,
            },
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "intent_contract_ok")

    def test_linux_auth_blocks_match_capture_antipattern(self) -> None:
        ok, reason = validate_query_for_intent(
            "linux_auth_failures",
            {
                "query": (
                    "search index=linux sourcetype=auth.log (\"Failed password\" OR \"authentication failure\" OR \"Invalid user\") "
                    "| eval user_name=case(match(_raw, \"(?i)invalid\\s+user\\s+(?<invalid_user>\\S+)\"), invalid_user, true(), \"unknown\") "
                    "| eval src_ip=case(match(_raw, \"(?i)from\\s+(?<ssh_src_ip>\\d{1,3}(?:\\.\\d{1,3}){3})\"), ssh_src_ip, true(), \"unknown\") "
                    "| stats count by host user_name src_ip"
                ),
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 10,
            },
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "intent_contract_linux_auth_invalid_match_capture")

    def test_windows_auth_failures_requires_windows_shape(self) -> None:
        ok, reason = validate_query_for_intent(
            "windows_auth_failures",
            {
                "query": "search index=* NOT index=_* failed password | stats count by host",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 10,
            },
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "intent_contract_missing_group_1")

    def test_windows_auth_failures_passes_expected_query_shape(self) -> None:
        ok, reason = validate_query_for_intent(
            "windows_auth_failures",
            {
                "query": (
                    "search (index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog "
                    "(EventCode=4625 OR EventID=4625 OR \"An account failed to log on\") "
                    "| eval src_ip=coalesce(Source_Network_Address,IpAddress,src,src_ip,clientip,ip) "
                    "| eval user_name=coalesce(TargetUserName,SubjectUserName,Account_Name,user,username,Caller_User_Name) "
                    "| table _time index host Computer Channel EventCode EventID user_name src_ip "
                    "TargetUserName SubjectUserName Account_Name Caller_User_Name Source_Network_Address IpAddress"
                ),
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 10,
            },
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "intent_contract_ok")

    def test_linux_privilege_escalation_first_seen_requires_first_seen_shape(self) -> None:
        ok, reason = validate_query_for_intent(
            "linux_privilege_escalation_first_seen",
            {
                "query": (
                    "search index=linux sourcetype=auth.log \"sudo:\" "
                    "| stats count by host user"
                ),
                "earliest_time": "-7d",
                "latest_time": "now",
                "row_limit": 50,
            },
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "intent_contract_missing_group_4")

    def test_linux_privilege_escalation_first_seen_passes_expected_query_shape(self) -> None:
        ok, reason = validate_query_for_intent(
            "linux_privilege_escalation_first_seen",
            {
                "query": (
                    "search index=linux sourcetype=auth.log (\"session opened for user root by\" OR \"sudo:\") "
                    "| eval src_ip=coalesce(rhost,src,src_ip,ip) "
                    "| stats earliest(_time) as first_seen latest(_time) as last_seen count by host user src_ip "
                    "| sort 0 first_seen"
                ),
                "earliest_time": "-7d",
                "latest_time": "now",
                "row_limit": 50,
            },
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "intent_contract_ok")


if __name__ == "__main__":
    unittest.main()
