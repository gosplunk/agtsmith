#!/usr/bin/env python3
"""Focused tests for bounded deterministic candidate evidence selection."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from semantic_candidate_select import (  # noqa: E402
    MAX_GLOBAL_QUERY_EXECUTIONS,
    confidence_cap_for_evidence,
    new_query_budget,
    reserve_query,
    score_live_evidence,
    select_semantic_candidate,
)


def _candidate(source: str, score: float, *, passed: bool = True) -> dict:
    return {
        "selected_tool": "splunk_run_query",
        "intent": "unknown_composition",
        "source": source,
        "candidate_source": source,
        "tool_args": {
            "query": f'search index="locked" sourcetype="{source}" | stats count as events by src_ip',
            "earliest_time": "-24h",
            "latest_time": "now",
            "row_limit": 20,
        },
        "semantic_coverage": {
            "passed": passed,
            "static_score": score,
            "hard_failures": [] if passed else ["dimension:src_ip"],
            "spec": {"output_fields": ["src_ip", "events"]},
        },
    }


class SemanticCandidateSelectTests(unittest.TestCase):
    def test_collects_three_probes_two_and_forces_probe_row_limit_five(self) -> None:
        calls: list[tuple[dict, float]] = []

        def fake_probe(args: dict, timeout: float) -> dict:
            calls.append((dict(args), timeout))
            return {
                "structured": {
                    "total_rows": 1,
                    "results": [{"src_ip": "192.0.2.1", "events": "4"}],
                }
            }

        result = select_semantic_candidate(
            candidates=[
                _candidate("primary_typed_plan", 0.95),
                _candidate("structured_plan_repair", 0.93),
                _candidate("compiled_template_fallback", 0.91),
                _candidate("ignored_fourth", 1.0),
            ],
            mode="prefer",
            probe_runner=fake_probe,
            query_budget=new_query_budget(),
        )
        self.assertEqual(result["candidate_count"], 3)
        self.assertEqual(result["probes_used"], 2)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(args["row_limit"] == 5 for args, _ in calls))
        self.assertTrue(all(timeout <= 15.0 for _, timeout in calls))
        self.assertEqual(result["query_budget"]["used"], 2)

    def test_rejects_unrelated_nonzero_and_selects_related_candidate(self) -> None:
        def fake_probe(args: dict, _timeout: float) -> dict:
            sourcetype = "primary_typed_plan" if "primary_typed_plan" in args["query"] else "repair"
            row = {"unexpected": "1"} if sourcetype == "primary_typed_plan" else {
                "src_ip": "192.0.2.2",
                "events": "8",
            }
            return {"structured": {"total_rows": 1, "results": [row]}}

        result = select_semantic_candidate(
            candidates=[
                _candidate("primary_typed_plan", 0.99),
                _candidate("structured_plan_repair", 0.95),
            ],
            mode="prefer",
            probe_runner=fake_probe,
        )
        statuses = {
            row["source"]: row["evidence_status"]
            for row in result["telemetry"]
        }
        self.assertEqual(statuses["primary_typed_plan"], "unrelated_nonzero")
        self.assertEqual(statuses["structured_plan_repair"], "related_nonzero")
        self.assertEqual(
            result["selected_candidate"]["candidate_source"],
            "structured_plan_repair",
        )

    def test_observe_preserves_original_while_reporting_shadow_winner(self) -> None:
        def fake_probe(args: dict, _timeout: float) -> dict:
            return {
                "structured": {
                    "total_rows": 1,
                    "results": [{"src_ip": "192.0.2.3", "events": "2"}],
                }
            }

        original = _candidate("legacy_original", 0.80)
        stronger = _candidate("primary_typed_plan", 0.99)
        result = select_semantic_candidate(
            candidates=[original, stronger],
            mode="observe",
            probe_runner=fake_probe,
        )
        self.assertTrue(result["observe_preserved_original"])
        self.assertEqual(result["selected_candidate"]["candidate_source"], "legacy_original")
        self.assertNotEqual(
            result["selected_candidate_id"],
            result["shadow_selected_candidate_id"],
        )

    def test_enforce_blocks_compatibility_only_candidate(self) -> None:
        candidate = _candidate("legacy_fallback", 0.5)
        candidate["semantic_coverage"]["compatibility_candidate"] = True
        result = select_semantic_candidate(
            candidates=[candidate],
            mode="enforce",
            probe_runner=lambda _args, _timeout: {
                "structured": {
                    "total_rows": 1,
                    "results": [{"src_ip": "192.0.2.4", "events": "1"}],
                }
            },
        )
        self.assertTrue(result["blocked"])

    def test_global_query_budget_never_exceeds_hard_limit(self) -> None:
        budget = new_query_budget()
        for ordinal in range(MAX_GLOBAL_QUERY_EXECUTIONS + 2):
            reserved, budget = reserve_query(budget, purpose=f"test_{ordinal}")
            self.assertEqual(reserved, ordinal < MAX_GLOBAL_QUERY_EXECUTIONS)
        self.assertEqual(budget["used"], MAX_GLOBAL_QUERY_EXECUTIONS)
        self.assertEqual(budget["remaining"], 0)
        self.assertTrue(budget["exhausted"])

    def test_result_schema_scoring_and_confidence_caps(self) -> None:
        report = {"spec": {"output_fields": ["src_ip", "events"]}}
        unrelated = score_live_evidence(
            report,
            {"structured": {"total_rows": 1, "results": [{"host": "srv1"}]}},
        )
        self.assertEqual(unrelated["status"], "unrelated_nonzero")
        self.assertTrue(unrelated["rejected"])
        self.assertLessEqual(confidence_cap_for_evidence(unrelated), 0.25)


if __name__ == "__main__":
    unittest.main()
