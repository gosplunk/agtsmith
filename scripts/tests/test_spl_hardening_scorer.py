#!/usr/bin/env python3
"""Regression tests for benchmark semantic equivalence and hard quality gates."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from run_spl_hardening_benchmark import Case, _score_case


def _case(**overrides: object) -> Case:
    values: dict[str, object] = {
        "id": "test",
        "family": "top_indexes",
        "question": "Which indexes had the most events over the last day?",
        "expected_intent": "top_indexes",
        "expected_shape": "stats",
        "preferred_indexes": (),
        "preferred_sourcetypes": (),
        "required_query_terms": ("stats", "by index"),
        "forbidden_query_terms": (),
        "required_result_fields": ("index", "count"),
        "allow_zero_rows": False,
        "min_rows": 1,
        "expected_earliest_time": "-24h",
        "expected_latest_time": "now",
        "expected_mitre_techniques": (),
        "min_mitre_pivots": 0,
    }
    values.update(overrides)
    return Case(**values)


class SplHardeningScorerTests(unittest.TestCase):
    def test_equivalent_rolling_day_values_do_not_create_time_failure(self) -> None:
        result = _score_case(
            _case(),
            actual_intent="top_indexes",
            query_args={
                "query": "search index=* NOT index=_* | stats count by index | sort - count",
                "earliest_time": "-1d",
                "latest_time": "now",
                "row_limit": 10,
            },
            policy_ok=True,
            policy_reason="query_policy_ok",
            structured={"results": [{"index": "main", "count": "5"}], "total_rows": 1},
            error="",
            mitre_bundle={},
        )
        self.assertNotIn("time_window_mismatch", result["failure_class"])
        self.assertFalse(any(str(item).startswith("time_mismatch_") for item in result["findings"]))
        self.assertTrue(result["quality_gate_passed"])

    def test_contract_failure_cannot_receive_passing_score(self) -> None:
        result = _score_case(
            _case(
                family="windows_auth_failures",
                question="Show Windows failed logons in the last 24 hours.",
                expected_intent="windows_auth_failures",
                expected_shape="stats",
                required_query_terms=("failed", "stats"),
                required_result_fields=("host", "count"),
            ),
            actual_intent="windows_auth_failures",
            query_args={
                "query": "search index=windows failed | stats count by host",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 10,
            },
            policy_ok=True,
            policy_reason="query_policy_ok",
            structured={"results": [{"host": "win1", "count": "2"}], "total_rows": 1},
            error="",
            mitre_bundle={},
        )
        self.assertEqual(result["failure_class"], "intent_contract_failure")
        self.assertLessEqual(result["score"], 84)
        self.assertFalse(result["quality_gate_passed"])

    def test_required_rows_failure_cannot_receive_passing_score(self) -> None:
        result = _score_case(
            _case(),
            actual_intent="top_indexes",
            query_args={
                "query": "search index=* NOT index=_* | stats count by index | sort - count",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 10,
            },
            policy_ok=True,
            policy_reason="query_policy_ok",
            structured={"results": [], "total_rows": 0},
            error="",
            mitre_bundle={},
        )
        self.assertEqual(result["failure_class"], "empty_result")
        self.assertLessEqual(result["score"], 84)
        self.assertFalse(result["quality_gate_passed"])


if __name__ == "__main__":
    unittest.main()
