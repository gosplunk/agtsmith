#!/usr/bin/env python3
"""Focused tests for provenance-aware fields-first SPL strategy."""

from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spl_field_strategy import (  # noqa: E402
    analytical_plan_required_roles,
    apply_field_policy_to_plan,
    clear_field_verification_cache,
    field_strategy_for_analytical_plan,
    field_exists,
    resolve_field_strategy,
    rewrite_query_fields_first,
)
from query_templates import TEMPLATES  # noqa: E402
from run_unknown_env_benchmark import evaluate_field_strategy_oracle  # noqa: E402


APACHE_QUERY = (
    'search index=linux sourcetype=access_combined '
    '| rex field=_raw "^(?<clientip>\\S+) \\S+ \\S+ \\[[^\\]]+\\] '
    '\\"(?<method>[A-Z]+) (?<uri_path>\\S+) [^\\"]+\\" (?<status>\\d{3})" '
    "| stats count by clientip status method | sort - count"
)


class SplFieldStrategyTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_field_verification_cache()

    @staticmethod
    def _bound(index_expr: str = "index=linux") -> dict:
        return {
            "intent": "apache_access_top_ips",
            "index_expr": index_expr,
            "sourcetype": "access_combined",
            "role_mappings": {
                "src_ip": ["clientip"],
                "status": ["status"],
                "method": ["method"],
                "uri": ["uri_path"],
                "user_agent": ["useragent"],
            },
        }

    def test_verified_apache_fields_remove_redundant_rex(self) -> None:
        calls: list[tuple[str, str]] = []

        def verify(index: str, sourcetype: str, _earliest: str, _latest: str) -> set[str]:
            calls.append((index, sourcetype))
            return {"clientip", "status", "method", "useragent"}

        strategy = resolve_field_strategy(
            "Show top Apache client IPs",
            {
                "intent": "apache_access_top_ips",
                "canonical_template_query": APACHE_QUERY,
                "tool_args": {"earliest_time": "-24h", "latest_time": "now"},
            },
            field_bind_output=self._bound(),
            verifier=verify,
            profile={},
        )
        rewritten, actions = rewrite_query_fields_first(APACHE_QUERY, strategy)
        self.assertNotIn("| rex ", rewritten.lower())
        self.assertIn("| stats count by clientip status method", rewritten)
        self.assertEqual(strategy["trusted_coalesce_hints"], {})
        self.assertEqual(calls, [("linux", "access_combined")])
        self.assertTrue(any(action.startswith("removed_redundant_rex") for action in actions))

    def test_raw_only_apache_keeps_regex_fallback(self) -> None:
        strategy = resolve_field_strategy(
            "Show top Apache client IPs",
            {"intent": "apache_access_top_ips", "canonical_template_query": APACHE_QUERY},
            field_bind_output=self._bound(),
            verifier=lambda *_args: {"host", "_raw"},
            profile={},
        )
        rewritten, actions = rewrite_query_fields_first(APACHE_QUERY, strategy)
        self.assertIn("| rex ", rewritten.lower())
        self.assertTrue(any(action.startswith("preserved_rex_fallback") for action in actions))

    def test_json_fields_choose_spath_instead_of_rex(self) -> None:
        query = (
            'search index=cloud sourcetype=aws:cloudtrail '
            '| rex field=_raw "\\"eventName\\":\\"(?<eventName>[^\\"]+)" '
            "| stats count by eventName"
        )
        strategy = {
            "structured_json": True,
            "raw_parse_required": False,
            "trusted_fields": [],
            "roles": {"action": {"trusted_fields": []}},
        }
        rewritten, actions = rewrite_query_fields_first(query, strategy)
        self.assertNotIn("| rex ", rewritten.lower())
        self.assertIn("| spath input=_raw", rewritten.lower())
        self.assertTrue(any(action.startswith("replaced_rex_with_spath") for action in actions))

    def test_trusted_json_fields_remove_redundant_spath(self) -> None:
        query = (
            "search index=main sourcetype=stream:http "
            "| spath input=_raw path=http_method output=http_method "
            "| spath input=_raw path=status output=status "
            "| stats count by http_method status"
        )
        strategy = {
            "structured_json": True,
            "raw_parse_required": False,
            "trusted_fields": ["http_method", "status"],
            "roles": {
                "method": {"trusted_fields": ["http_method"]},
                "status": {"trusted_fields": ["status"]},
            },
        }
        rewritten, actions = rewrite_query_fields_first(query, strategy)
        self.assertNotIn("| spath ", rewritten.lower())
        self.assertIn("| stats count by http_method status", rewritten.lower())
        self.assertEqual(
            [action for action in actions if action.startswith("removed_redundant_spath")],
            [
                "removed_redundant_spath:http_method",
                "removed_redundant_spath:status",
            ],
        )

    def test_strategy_exposes_rex_and_spath_template_fallbacks(self) -> None:
        query = (
            "search index=main sourcetype=stream:http "
            "| spath input=_raw path=http_method output=http_method "
            '| rex field=_raw "\\"status\\":(?<status>\\d+)" '
            "| stats count by http_method status"
        )
        strategy = resolve_field_strategy(
            "Show HTTP methods and status",
            {"intent": "stream_http_activity", "canonical_template_query": query},
            field_bind_output={
                "intent": "stream_http_activity",
                "index_expr": "index=main",
                "sourcetype": "stream:http",
            },
            verifier=lambda *_args: {"host", "_raw"},
            profile={},
        )
        self.assertEqual(
            strategy["fallback_extractions"],
            [
                "spath input=_raw path=http_method output=http_method",
                'rex field=_raw "\\"status\\":(?<status>\\d+)"',
            ],
        )

    def test_templates_expose_native_and_fallback_shapes(self) -> None:
        apache = next(template for template in TEMPLATES if template.intent == "apache_access_top_ips")
        self.assertNotIn("| rex ", apache.native_query.lower())
        self.assertTrue(any(stage.lower().startswith("rex ") for stage in apache.fallback_extractions))

        vpc = next(template for template in TEMPLATES if template.intent == "aws_vpc_flow_activity")
        self.assertTrue(vpc.raw_parse_required)
        self.assertIn("| rex ", vpc.native_query.lower())

    def test_cross_index_field_does_not_authorize_rex_removal(self) -> None:
        calls: list[str] = []

        def verify(index: str, _sourcetype: str, _earliest: str, _latest: str) -> set[str]:
            calls.append(index)
            if index == "linux":
                return {"clientip", "status", "method"}
            return {"host", "_raw"}

        strategy = resolve_field_strategy(
            "Show top Apache client IPs across web indexes",
            {"intent": "apache_access_top_ips", "canonical_template_query": APACHE_QUERY},
            field_bind_output=self._bound("(index=linux OR index=archive)"),
            verifier=verify,
            profile={},
        )
        rewritten, _actions = rewrite_query_fields_first(APACHE_QUERY, strategy)
        self.assertEqual(calls, ["linux", "archive"])
        self.assertEqual(strategy["trusted_fields"], [])
        self.assertIn("| rex ", rewritten.lower())

    def test_stale_or_sparse_profile_is_candidate_only_never_trusted(self) -> None:
        now = datetime.now(timezone.utc)
        profile = {
            "index_sourcetype_field_inventory": {
                "linux": {
                    "access_combined": {
                        "timestamp_utc": (now - timedelta(days=2)).isoformat(),
                        "fields": [{"field": "clientip", "count": 10, "sample_values": ["192.0.2.1"]}],
                    }
                }
            }
        }
        stale = field_exists("linux", "access_combined", "clientip", profile=profile, now=now)
        self.assertFalse(stale["exists"])
        self.assertEqual(stale["evidence_level"], "hint")

        profile["index_sourcetype_field_inventory"]["linux"]["access_combined"] = {
            "timestamp_utc": now.isoformat(),
            "fields": [{"field": "clientip", "count": 10, "sample_values": []}],
        }
        sparse = field_exists("linux", "access_combined", "clientip", profile=profile, now=now)
        self.assertFalse(sparse["candidate"])
        self.assertFalse(sparse["exists"])

    def test_vpc_flow_required_rex_is_preserved(self) -> None:
        query = (
            "search index=main sourcetype=aws:cloudwatchlogs:vpcflow "
            '| rex field=_raw "^(?<src_ip>\\S+) (?<dest_ip>\\S+) (?<action>\\S+)$" '
            "| stats count by src_ip dest_ip action"
        )
        strategy = {
            "intent": "aws_vpc_flow_activity",
            "raw_parse_required": True,
            "trusted_fields": ["src_ip", "dest_ip", "action"],
        }
        plan, policy = apply_field_policy_to_plan(
            {
                "selected_tool": "splunk_run_query",
                "intent": "aws_vpc_flow_activity",
                "tool_args": {
                    "query": query,
                    "earliest_time": "-24h",
                    "latest_time": "now",
                    "row_limit": 20,
                },
            },
            strategy,
        )
        self.assertIn("| rex ", plan["tool_args"]["query"].lower())
        self.assertFalse(policy["changed"])
        self.assertIn("preserved_raw_required_extraction", policy["actions"])

    def test_live_verification_is_cached_per_domain_and_window(self) -> None:
        calls = 0

        def verify(*_args: str) -> set[str]:
            nonlocal calls
            calls += 1
            return {"clientip", "status", "method"}

        kwargs = {
            "question": "Show top Apache client IPs",
            "planner_output": {"intent": "apache_access_top_ips", "canonical_template_query": APACHE_QUERY},
            "field_bind_output": self._bound(),
            "verifier": verify,
            "profile": {},
        }
        resolve_field_strategy(**kwargs)
        second = resolve_field_strategy(**kwargs)
        self.assertEqual(calls, 1)
        self.assertTrue(second["domain_verifications"][0]["cache_hit"])

    def test_unknown_environment_field_strategy_oracles(self) -> None:
        cases_path = Path(__file__).resolve().parents[2] / "benchmarks/unknown_env_cases.json"
        cases = json.loads(cases_path.read_text(encoding="utf-8"))
        oracle_cases = [
            case
            for case in cases
            if isinstance(case, dict) and case.get("benchmark_mode") == "field_strategy_oracle"
        ]
        self.assertEqual(
            {case["id"] for case in oracle_cases},
            {
                "fields_first_native_apache",
                "fields_first_raw_only_apache",
                "fields_first_json_spath_fallback",
                "fields_first_cross_index_false_positive",
                "fields_first_stale_profile_evidence",
                "fields_first_sparse_profile_evidence",
                "fields_first_vpc_rex_preservation",
            },
        )
        results = [evaluate_field_strategy_oracle(case) for case in oracle_cases]
        failures = {row["id"]: row["findings"] for row in results if not row["passed"]}
        self.assertEqual(failures, {})

    def test_analytical_plan_strategy_adapter_is_role_bounded(self) -> None:
        plan = {
            "datasets": [
                {
                    "index": "main",
                    "filters": [{"field": "status", "operator": "eq", "value": 500}],
                }
            ],
            "analysis": {
                "dimensions": ["src_ip"],
                "measures": [{"name": "users", "function": "dc", "field": "user"}],
            },
        }
        self.assertEqual(
            analytical_plan_required_roles(plan),
            ["src_ip", "user", "status"],
        )
        adapted = field_strategy_for_analytical_plan(
            plan,
            {
                "roles": {
                    "src_ip": {"trusted_fields": ["clientip"]},
                    "user": {"trusted_fields": ["username"]},
                    "process": {"trusted_fields": ["Image"]},
                },
                "trusted_fields": ["clientip", "username", "Image"],
            },
        )
        self.assertEqual(set(adapted["roles"]), {"src_ip", "user"})
        self.assertNotIn("process", adapted["roles"])


if __name__ == "__main__":
    unittest.main()
