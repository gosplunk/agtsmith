#!/usr/bin/env python3
"""Unit tests for constrained SPL write plan schema."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spl_query_schema import (  # noqa: E402
    ANALYTICAL_PLAN_VERSION,
    AnalyticalPlan,
    WritePlan,
    infer_write_plan_from_query,
    materialize_write_plan,
    parse_analytical_plan,
    parse_write_plan,
    validate_analytical_plan,
    validate_write_plan,
    write_plan_to_tool_args,
)


class SplQuerySchemaTests(unittest.TestCase):
    def test_materialize_stats_by(self) -> None:
        plan = WritePlan(
            index_expr="index=main",
            sourcetype="access_combined",
            filters=['status>=400'],
            aggregation="count",
            group_by=["clientip"],
            head_limit=10,
        )
        query = materialize_write_plan(plan)
        self.assertTrue(query.startswith("search index=main"))
        self.assertIn('sourcetype="access_combined"', query)
        self.assertIn("stats count as count by clientip", query)

    def test_parse_write_plan_from_dict(self) -> None:
        plan = parse_write_plan({"write_plan": {"index_expr": "index=botsv3", "aggregation": "count"}})
        self.assertIsNotNone(plan)
        assert plan is not None
        self.assertEqual(plan.index_expr, "index=botsv3")

    def test_validate_blocks_disallowed_aggregation(self) -> None:
        plan = WritePlan(index_expr="index=main", aggregation="join")
        ok, reason = validate_write_plan(plan)
        self.assertFalse(ok)
        self.assertIn("aggregation_not_allowed", reason)

    def test_infer_and_roundtrip(self) -> None:
        query = 'search index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4625 | stats count by user'
        inferred = infer_write_plan_from_query(query, {"earliest_time": "-24h", "latest_time": "now", "row_limit": 50})
        rebuilt = materialize_write_plan(inferred)
        self.assertIn("index=wineventlog", rebuilt)
        self.assertIn("EventCode=4625", rebuilt)

    def test_write_plan_to_tool_args(self) -> None:
        plan = WritePlan(index_expr="index=main", aggregation="count")
        payload = write_plan_to_tool_args(plan, intent="top_sources")
        self.assertEqual(payload["selected_tool"], "splunk_run_query")
        self.assertIn("search index=main", payload["tool_args"]["query"])

    def test_analytical_plan_versioned_roundtrip(self) -> None:
        raw = {
            "version": ANALYTICAL_PLAN_VERSION,
            "datasets": [{"index": "main", "sourcetype": "access_combined"}],
            "analysis": {
                "dimensions": ["status"],
                "measures": [{"name": "events", "function": "count"}],
                "output_fields": ["status", "events"],
            },
            "execution": {
                "earliest": "-24h",
                "latest": "now",
                "row_limit": 50,
                "materialization": "bounded",
            },
        }
        plan = parse_analytical_plan({"analytical_plan": raw})
        self.assertIsInstance(plan, AnalyticalPlan)
        assert plan is not None
        valid, errors = validate_analytical_plan(plan)
        self.assertTrue(valid, errors)
        self.assertEqual(plan.to_dict()["version"], ANALYTICAL_PLAN_VERSION)

    def test_analytical_plan_rejects_unbounded_or_unknown_operations(self) -> None:
        plan = AnalyticalPlan.from_dict(
            {
                "version": ANALYTICAL_PLAN_VERSION,
                "datasets": [{"index": "main"}],
                "analysis": {
                    "measures": [{"name": "bad", "function": "transaction"}],
                },
                "execution": {
                    "earliest": "alltime",
                    "latest": "now",
                    "row_limit": 1000,
                },
            }
        )
        valid, errors = validate_analytical_plan(plan)
        self.assertFalse(valid)
        self.assertIn("measure_function_not_allowed:transaction", errors)
        self.assertIn("earliest_time_invalid", errors)
        self.assertIn("row_limit_out_of_range", errors)


if __name__ == "__main__":
    unittest.main()
