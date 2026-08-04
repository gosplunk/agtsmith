#!/usr/bin/env python3
"""Focused tests for deterministic AnalyticalPlan compilation."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from query_policy import validate_query_args  # noqa: E402
from spl_plan_compiler import (  # noqa: E402
    AnalyticalPlanCompileError,
    analytical_plan_to_tool_args,
    compile_analytical_plan,
)


class SplPlanCompilerTests(unittest.TestCase):
    @staticmethod
    def _plan() -> dict:
        return {
            "version": "1.0",
            "datasets": [
                {
                    "index": "main",
                    "sourcetype": "access_combined",
                    "platform": "linux",
                    "filters": [
                        {"field": "status", "operator": "gte", "value": 400},
                    ],
                }
            ],
            "normalizations": [
                {
                    "output": "src_ip",
                    "kind": "coalesce",
                    "fields": ["clientip", "src"],
                }
            ],
            "analysis": {
                "dimensions": ["src_ip"],
                "time_bin": {"field": "_time", "span": "5m", "alias": "bucket"},
                "measures": [
                    {"name": "events", "function": "count"},
                    {
                        "name": "server_errors",
                        "function": "count",
                        "condition": {"field": "status", "operator": "gte", "value": 500},
                    },
                    {"name": "users", "function": "dc", "field": "user"},
                    {"name": "first_seen", "function": "earliest", "field": "_time"},
                    {"name": "last_seen", "function": "latest", "field": "_time"},
                ],
                "intersections": [
                    {"name": "identified_pairs", "fields": ["src_ip", "user"]},
                ],
                "ratios": [
                    {
                        "name": "error_pct",
                        "numerator": "server_errors",
                        "denominator": "events",
                        "scale": 100,
                        "zero_policy": "zero",
                    }
                ],
                "post_aggregation_predicates": [
                    {"field": "events", "operator": "gte", "value": 2},
                ],
                "ranking": [{"field": "error_pct", "direction": "desc", "limit": 10}],
                "output_fields": [
                    "bucket", "src_ip", "events", "server_errors", "users",
                    "first_seen", "last_seen", "identified_pairs", "error_pct",
                ],
            },
            "execution": {
                "earliest": "-24h",
                "latest": "now",
                "row_limit": 50,
                "materialization": "bounded",
            },
        }

    def test_compiles_composable_analytical_primitives(self) -> None:
        query = compile_analytical_plan(self._plan())
        self.assertIn('search (index="main" sourcetype="access_combined"', query)
        self.assertIn("eval src_ip=coalesce(clientip,src)", query)
        self.assertIn("bin _time span=5m", query)
        self.assertIn("count(eval(status>=500)) as server_errors", query)
        self.assertIn("earliest(_time) as first_seen", query)
        self.assertIn("count(eval(isnotnull(src_ip) AND isnotnull(user))) as identified_pairs", query)
        self.assertIn("eval error_pct=if(events=0,0,(server_errors/events)*100)", query)
        self.assertIn("where events>=2", query)
        self.assertIn("sort 0 -error_pct", query)
        self.assertTrue(query.endswith("| head 10"))

    def test_tool_args_keep_time_and_row_bounds_outside_spl(self) -> None:
        payload = analytical_plan_to_tool_args(self._plan(), intent="composed_web_analysis")
        self.assertEqual(payload["tool_args"]["earliest_time"], "-24h")
        self.assertEqual(payload["tool_args"]["latest_time"], "now")
        self.assertEqual(payload["tool_args"]["row_limit"], 50)
        valid, reason = validate_query_args(
            payload["tool_args"],
            question="Analyze linux web errors in main",
        )
        self.assertTrue(valid, reason)

    def test_rejects_identifier_injection_and_unsafe_time(self) -> None:
        plan = self._plan()
        plan["analysis"]["dimensions"] = ["src_ip | outputlookup stolen"]
        plan["execution"]["earliest"] = "yesterday | delete"
        with self.assertRaises(AnalyticalPlanCompileError) as raised:
            compile_analytical_plan(plan)
        self.assertIn("dimension_invalid", str(raised.exception))
        self.assertIn("earliest_time_invalid", str(raised.exception))

    def test_wildcard_scope_excludes_internal_indexes(self) -> None:
        plan = self._plan()
        plan["datasets"] = [{"index": "*"}]
        query = compile_analytical_plan(plan)
        self.assertIn("index=* NOT index=_*", query)


if __name__ == "__main__":
    unittest.main()
