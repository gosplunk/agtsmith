#!/usr/bin/env python3
"""Focused unit and negative tests for deterministic semantic coverage."""

from __future__ import annotations

import sys
import unittest
from copy import deepcopy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spl_plan_compiler import analytical_plan_to_tool_args  # noqa: E402
from spl_semantic_coverage import (  # noqa: E402
    build_coverage_spec,
    evaluate_semantic_coverage,
)


def _plan() -> dict:
    return {
        "version": "1.0",
        "datasets": [
            {
                "index": "locked",
                "sourcetype": "access_combined",
                "filters": [{"field": "status", "operator": "gte", "value": 500}],
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
            "dimensions": ["src_ip", "status"],
            "measures": [{"name": "events", "function": "count"}],
            "post_aggregation_predicates": [],
            "time_bin": {"field": "_time", "span": "10m", "alias": "bucket"},
            "ratios": [],
            "intersections": [],
            "ranking": [{"field": "events", "direction": "desc", "limit": 5}],
            "output_fields": ["bucket", "src_ip", "status", "events"],
        },
        "execution": {
            "earliest": "-24h",
            "latest": "now",
            "row_limit": 20,
            "materialization": "bounded",
        },
    }


QUESTION = (
    "In index=locked sourcetype=access_combined show top 5 counts by client IP "
    "where status>=500 every 10 minutes"
)


class SemanticCoverageTests(unittest.TestCase):
    def test_extracts_deterministic_question_and_plan_contract(self) -> None:
        spec = build_coverage_spec(QUESTION, _plan())
        self.assertEqual(spec.explicit_indexes, ("locked",))
        self.assertEqual(spec.explicit_sourcetypes, ("access_combined",))
        self.assertIn("status:gte:500", spec.question_filters)
        self.assertIn("src_ip", spec.question_dimensions)
        self.assertIn("count:*", spec.question_measures)
        self.assertIn("time_bin:10m", spec.question_shapes)
        self.assertIn("ranking:desc:5", spec.question_shapes)

    def test_compiled_plan_scores_plan_spl_and_output_schema(self) -> None:
        args = analytical_plan_to_tool_args(_plan())["tool_args"]
        report = evaluate_semantic_coverage(
            question=QUESTION,
            analytical_plan=_plan(),
            query_args=args,
            safety_ok=True,
        )
        self.assertTrue(report["passed"], report["hard_failures"])
        self.assertEqual(report["plan"]["score"], 1.0)
        self.assertEqual(report["spl"]["score"], 1.0)
        self.assertEqual(report["output_schema"]["score"], 1.0)
        self.assertEqual(report["live_evidence"]["status"], "pending_candidate_probe")

    def test_canonicalizes_bound_native_measure_aliases_in_spl(self) -> None:
        plan = {
            "version": "1.0",
            "datasets": [{"index": "main", "sourcetype": "netstat"}],
            "normalizations": [
                {"output": "dest", "kind": "native", "fields": ["dest"]}
            ],
            "analysis": {
                "dimensions": ["src_ip"],
                "measures": [
                    {"name": "events", "function": "count"},
                    {"name": "dest_values", "function": "values", "field": "dest"},
                ],
                "intersections": [],
                "output_fields": ["src_ip", "events", "dest_values"],
            },
            "execution": {
                "earliest": "-7d",
                "latest": "now",
                "row_limit": 100,
                "materialization": "bounded",
            },
        }
        report = evaluate_semantic_coverage(
            question=(
                "For index main sourcetype netstat, group by src and collect "
                "dest values during the last 7 days."
            ),
            analytical_plan=plan,
            query_args={
                "query": (
                    'search (index="main" sourcetype="netstat") | '
                    "stats count as events values(dest) as dest_values by src_ip"
                ),
                "earliest_time": "-7d",
                "latest_time": "now",
                "row_limit": 100,
            },
        )
        self.assertNotIn("measure:values:dest_ip", report["hard_failures"])

    def test_hard_fails_dataset_filter_dimension_measure_and_shape_omissions(self) -> None:
        broken_plan = deepcopy(_plan())
        broken_plan["datasets"][0]["index"] = "other"
        broken_plan["datasets"][0]["filters"] = []
        broken_plan["analysis"]["dimensions"] = []
        broken_plan["analysis"]["measures"] = [{"name": "users", "function": "dc", "field": "user"}]
        broken_plan["analysis"]["time_bin"] = None
        broken_plan["analysis"]["ranking"] = []
        broken_plan["analysis"]["output_fields"] = ["users"]
        report = evaluate_semantic_coverage(
            question=QUESTION,
            analytical_plan=broken_plan,
            query_args=analytical_plan_to_tool_args(broken_plan)["tool_args"],
        )
        failures = report["hard_failures"]
        self.assertTrue(any(item.startswith("dataset:explicit_index_lock_violation") for item in failures))
        self.assertIn("filter:status:gte:500", failures)
        self.assertIn("dimension:src_ip", failures)
        self.assertIn("measure:count:*", failures)
        self.assertIn("shape:time_bin", failures)
        self.assertIn("shape:ranking", failures)
        self.assertFalse(report["repair_feedback"]["raw_spl_repair_allowed"])

    def test_hard_fails_compiled_spl_that_drops_output_and_changes_shape(self) -> None:
        query_args = {
            "query": (
                'search index="locked" sourcetype="access_combined" status>=500 '
                "| stats count as events | fields events | head 5"
            ),
            "earliest_time": "-24h",
            "latest_time": "now",
            "row_limit": 20,
        }
        report = evaluate_semantic_coverage(
            question=QUESTION,
            analytical_plan=_plan(),
            query_args=query_args,
        )
        self.assertFalse(report["passed"])
        self.assertIn("dimension:src_ip", report["hard_failures"])
        self.assertIn("shape:time_bin", report["hard_failures"])
        self.assertIn("output_field:bucket", report["hard_failures"])
        self.assertIn("output_field:src_ip", report["hard_failures"])

    def test_accepts_conditional_aggregate_measures(self) -> None:
        plan = deepcopy(_plan())
        plan["analysis"]["dimensions"] = ["src_ip"]
        plan["analysis"]["time_bin"] = None
        plan["analysis"]["ranking"] = []
        plan["analysis"]["measures"] = [
            {
                "name": "server_errors",
                "function": "count",
                "condition": {"field": "status", "operator": "gte", "value": 500},
            },
            {
                "name": "error_bytes",
                "function": "sum",
                "field": "bytes",
                "condition": {"field": "status", "operator": "gte", "value": 500},
            },
        ]
        plan["analysis"]["output_fields"] = ["src_ip", "server_errors", "error_bytes"]
        question = (
            "Show conditional counts and total bytes by source IP in "
            "index=locked sourcetype=access_combined where status>=500"
        )
        args = analytical_plan_to_tool_args(plan)["tool_args"]
        report = evaluate_semantic_coverage(
            question=question,
            analytical_plan=plan,
            query_args=args,
        )
        self.assertTrue(report["passed"], report["hard_failures"])
        self.assertEqual(report["spl"]["missing"]["measures"], [])

    def test_reuses_apache_dimension_adapter_and_marks_unresolved_fields(self) -> None:
        plan = _plan()
        plan["normalizations"] = []
        args = analytical_plan_to_tool_args(plan)["tool_args"]
        report = evaluate_semantic_coverage(
            question=QUESTION,
            analytical_plan=plan,
            query_args=args,
            field_strategy={
                "roles": {
                    "src_ip": {
                        "trusted_fields": [],
                        "classification": "unresolved",
                    }
                }
            },
        )
        self.assertTrue(report["spl"]["apache_dimension_adapter"]["ok"])
        self.assertIn("unsupported_field:src_ip", report["hard_failures"])

    def test_accepts_profile_candidate_field_evidence_without_live_trust(self) -> None:
        plan = _plan()
        plan["normalizations"] = []
        args = analytical_plan_to_tool_args(plan)["tool_args"]
        report = evaluate_semantic_coverage(
            question=QUESTION,
            analytical_plan=plan,
            query_args=args,
            field_strategy={
                "roles": {
                    "src_ip": {
                        "trusted_fields": [],
                        "candidate_fields": ["clientip"],
                        "classification": "native",
                    }
                }
            },
        )
        self.assertNotIn("unsupported_field:src_ip", report["hard_failures"])

    def test_conflicting_sourcetype_and_platform_are_hard_failures(self) -> None:
        plan = _plan()
        plan["datasets"][0]["platform"] = "web"
        report = evaluate_semantic_coverage(
            question=QUESTION,
            analytical_plan=plan,
            query_args={
                "query": (
                    'search index="locked" sourcetype="stream:http" platform="windows" status>=500 '
                    "| bin _time span=10m | eval bucket=_time "
                    "| stats count as events by bucket src_ip | sort 0 -events "
                    "| fields bucket src_ip events | head 5"
                ),
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 20,
            },
        )
        self.assertTrue(
            any(item.startswith("dataset:sourcetype_scope_mismatch") for item in report["hard_failures"])
        )
        self.assertTrue(
            any(item.startswith("dataset:conflicting_platform") for item in report["hard_failures"])
        )


if __name__ == "__main__":
    unittest.main()
