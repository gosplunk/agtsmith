#!/usr/bin/env python3
"""Template-to-AnalyticalPlan parity coverage tests."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from query_policy import validate_query_args  # noqa: E402
from query_templates import TEMPLATES  # noqa: E402
from spl_template_plan_adapter import template_parity_inventory  # noqa: E402


class SplTemplatePlanAdapterTests(unittest.TestCase):
    def test_every_template_is_represented_or_explicit_fallback(self) -> None:
        inventory = template_parity_inventory()
        self.assertEqual(len(inventory), len(TEMPLATES))
        self.assertEqual(
            [row.intent for row in inventory],
            [template.intent for template in TEMPLATES],
        )
        self.assertTrue(all(row.status in {"represented", "fallback_only"} for row in inventory))
        self.assertTrue(all(row.reason for row in inventory))
        self.assertTrue(any(row.status == "represented" for row in inventory))
        self.assertTrue(any(row.status == "fallback_only" for row in inventory))
        for row in inventory:
            if row.status == "represented":
                self.assertIsNotNone(row.plan)
                self.assertTrue(row.compiled_query.startswith("search "))
                self.assertEqual(row.reason, "semantic_shape_parity")
            else:
                self.assertIsNone(row.plan)
                self.assertEqual(
                    row.fallback_query,
                    next(template.query for template in TEMPLATES if template.intent == row.intent),
                )

    def test_represented_templates_compile_under_read_only_policy(self) -> None:
        failures: dict[str, str] = {}
        for row in template_parity_inventory():
            if row.status != "represented" or row.plan is None:
                continue
            args = {
                "query": row.compiled_query,
                "earliest_time": row.plan.execution.earliest,
                "latest_time": row.plan.execution.latest,
                "row_limit": row.plan.execution.row_limit,
            }
            question = (
                f"show Splunk internal {row.intent}"
                if any(branch.index.startswith("_") for branch in row.plan.datasets)
                else f"show {row.intent}"
            )
            valid, reason = validate_query_args(args, question=question)
            if not valid:
                failures[row.intent] = reason
        self.assertEqual(failures, {})

    def test_simple_stats_template_retains_semantic_shape(self) -> None:
        row = next(
            item
            for item in template_parity_inventory()
            if item.intent == "cisco_asa_network_flows"
        )
        self.assertEqual(row.status, "represented")
        assert row.plan is not None
        self.assertEqual(row.plan.datasets[0].index, "main")
        self.assertEqual(row.plan.datasets[0].sourcetype, "cisco:asa")
        self.assertEqual(
            row.plan.dimensions,
            ["action", "src_ip", "dest_ip", "dest_port", "transport"],
        )
        self.assertEqual(row.plan.measures, [{"name": "count", "function": "count", "field": ""}])
        self.assertIn("stats count as count by action src_ip dest_ip dest_port transport", row.compiled_query)


if __name__ == "__main__":
    unittest.main()
