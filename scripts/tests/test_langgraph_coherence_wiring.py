#!/usr/bin/env python3
"""Unit tests for LangGraph platform coherence validation wiring."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import langgraph_multi_model_soc as mm


class LangGraphCoherenceWiringTests(unittest.TestCase):
    def test_validate_final_plan_rewrites_incoherent_auth_before_validation(self) -> None:
        state = {
            "supported": True,
            "question": "Show failed logon activity in the last 24 hours",
            "final_plan": {
                "selected_tool": "splunk_run_query",
                "intent": "failed_login_activity",
                "tool_args": {
                    "query": "search index=botsv3 sourcetype=linux_secure EventCode=4625 | stats count by host",
                    "earliest_time": "-24h",
                    "latest_time": "now",
                    "row_limit": 10,
                },
                "confidence": 0.9,
            },
        }
        out = mm.validate_final_plan_node(state)
        self.assertTrue(out.get("validation_ok", False))
        query = str(out.get("final_plan", {}).get("tool_args", {}).get("query", ""))
        ok, reason = mm.validate_platform_sourcetype_coherence(query, "failed_login_activity")
        self.assertTrue(ok, msg=f"expected coherent query after normalization, got {reason}: {query[:160]}")
        self.assertNotRegex(query.lower(), r"linux_secure[^|]*eventcode=4625")

    def test_env_constraints_not_doubled_for_template_fallback(self) -> None:
        plan = mm._default_plan_from_template("Show failed logon activity in the last 24 hours")
        args = plan.get("tool_args", {})
        self.assertTrue(args.get("_env_constraints_applied"))
        query_once = str(args.get("query", ""))
        normalized = mm._normalize_candidate(plan, "Show failed logon activity in the last 24 hours", fallback_reason="test")
        normalized_args = normalized.get("tool_args", {})
        self.assertEqual(str(normalized_args.get("query", "")), query_once)

    def test_missing_writer_query_uses_deterministic_template_fallback(self) -> None:
        question = "Show failed Splunk logins today."
        normalized = mm._normalize_candidate(
            {
                "selected_tool": "splunk_run_query",
                "intent": "internal_auth_failures",
                "tool_args": {
                    "earliest_time": "@d",
                    "latest_time": "now",
                    "row_limit": 10,
                },
            },
            question,
            fallback_reason="test",
        )
        args = normalized.get("tool_args", {})
        self.assertEqual(normalized.get("intent"), "internal_auth_failures")
        self.assertEqual(normalized.get("source"), "deterministic_missing_query_fallback")
        self.assertIn("index=_audit", str(args.get("query", "")))
        self.assertEqual(args.get("earliest_time"), "@d")


if __name__ == "__main__":
    unittest.main()
