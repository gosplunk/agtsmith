#!/usr/bin/env python3
"""Offline tests for operational SPL accuracy scoring."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from run_operational_spl_accuracy import (
    AccuracyCase,
    _entity_recall,
    _jaccard,
    _load_cases,
    _passes_score,
    _row_keys,
    _score_rows,
    evaluate_case,
)


class OperationalSplAccuracyTests(unittest.TestCase):
    def test_jaccard_identical_sets(self) -> None:
        keys = {"linux|10", "main|3"}
        self.assertEqual(_jaccard(keys, keys), 1.0)

    def test_entity_recall_ignores_count_drift(self) -> None:
        canonical = {"linux|100", "main|200"}
        pipeline = {"linux|999", "main|888"}
        entity_canonical = {"linux", "main"}
        entity_pipeline = {"linux", "main"}
        self.assertEqual(_entity_recall(entity_pipeline, entity_canonical), 1.0)
        self.assertEqual(_jaccard(pipeline, canonical), 0.0)

    def test_row_keys_builds_composite(self) -> None:
        rows = [{"index": "linux", "count": 10}, {"index": "main", "count": 3}]
        keys = _row_keys(rows, ("index", "count"))
        self.assertIn("linux|10", keys)
        self.assertIn("main|3", keys)

    def test_passes_score_rejects_count_drift_despite_entity_recall(self) -> None:
        case = AccuracyCase(
            id="x",
            category="inventory",
            question="q",
            expected_intent="top_indexes",
            canonical_spl="search index=* | stats count by index",
            earliest_time="-1h",
            latest_time="now",
            compare_fields=("index", "count"),
            profile_window="-1h",
            min_jaccard=0.9,
            entity_fields=("index",),
            min_entity_recall=1.0,
        )
        score = {
            "jaccard": 0.0,
            "entity_recall": 1.0,
            "entity_jaccard": 1.0,
            "equivalence_score": 0.85,
            "count_delta_pct": 0.5,
        }
        self.assertFalse(_passes_score(score, case=case))

    def test_passes_score_accepts_small_count_drift_with_equivalent_entities(self) -> None:
        case = AccuracyCase(
            id="x",
            category="inventory",
            question="q",
            expected_intent="top_indexes",
            canonical_spl="search index=* | stats count by index",
            earliest_time="-1h",
            latest_time="now",
            compare_fields=("index", "count"),
            profile_window="-1h",
            min_jaccard=0.9,
            entity_fields=("index",),
            min_entity_recall=1.0,
        )
        score = {
            "jaccard": 0.0,
            "entity_recall": 1.0,
            "entity_jaccard": 1.0,
            "equivalence_score": 0.85,
            "count_delta_pct": 0.01,
        }
        self.assertTrue(_passes_score(score, case=case))

    def test_profile_score_tolerates_wider_count_drift_than_pipeline(self) -> None:
        case = AccuracyCase(
            id="x",
            category="inventory",
            question="q",
            expected_intent="top_indexes",
            canonical_spl="search index=* | stats count by index",
            earliest_time="-1h",
            latest_time="now",
            compare_fields=("index", "count"),
            profile_window="-1h",
            min_jaccard=0.9,
            entity_fields=("index",),
            min_entity_recall=1.0,
        )
        score = {
            "jaccard": 0.0,
            "entity_recall": 1.0,
            "entity_jaccard": 1.0,
            "equivalence_score": 0.85,
            "count_delta_pct": 0.27,
        }
        self.assertFalse(
            _passes_score(score, case=case),
            "pipeline tolerance should still reject this drift",
        )
        self.assertTrue(
            _passes_score(score, case=case, max_count_delta_pct=case.profile_max_count_delta_pct),
            "snapshot profile tolerance should accept typical refresh-interval drift",
        )

    def test_evaluate_case_offline_routing(self) -> None:
        case = AccuracyCase(
            id="indexes_with_data_last_hour",
            category="inventory",
            question="Which indexes have data in the last hour?",
            expected_intent="top_indexes",
            canonical_spl="search index=* NOT index=_* | stats count by index | sort - count",
            earliest_time="-1h",
            latest_time="now",
            compare_fields=("index", "count"),
            profile_window="-1h",
            min_jaccard=0.9,
            entity_fields=("index",),
            min_entity_recall=1.0,
        )
        profile = {
            "timestamp_utc": "2026-07-30T12:00:00+00:00",
            "index_activity": {
                "windows": {"-1h": [{"index": "linux", "count": 1}]},
            },
        }
        result = evaluate_case(case, profile=profile, row_limit=20, offline=True)
        self.assertEqual(result["actual_intent"], "top_indexes")
        self.assertTrue(result["policy_ok"])
        self.assertIn("pipeline_score", result)

    def test_score_rows_reports_entity_recall(self) -> None:
        case = AccuracyCase(
            id="indexes",
            category="inventory",
            question="Which indexes have data?",
            expected_intent="top_indexes",
            canonical_spl="search index=* | stats count by index",
            earliest_time="-1h",
            latest_time="now",
            compare_fields=("index", "count"),
            profile_window="",
            min_jaccard=0.9,
            entity_fields=("index",),
            min_entity_recall=1.0,
        )
        score = _score_rows(
            case=case,
            candidate_rows=[{"index": "main", "count": 1}, {"index": "linux", "count": 2}],
            reference_rows=[{"index": "main", "count": 99}, {"index": "linux", "count": 88}],
        )
        self.assertEqual(score["entity_recall"], 1.0)
        self.assertEqual(score["jaccard"], 0.0)

    def test_apache_fields_first_parity_case_removes_fallback_offline(self) -> None:
        root = Path(__file__).resolve().parents[2]
        cases = _load_cases(root / "benchmarks/operational_spl_accuracy.json")
        case = next(row for row in cases if row.id == "apache_fields_first_parity_7d")
        profile = {
            "sourcetype_to_indexes": {"access_combined": ["linux"]},
            "index_sourcetype_field_inventory": {},
        }
        result = evaluate_case(case, profile=profile, row_limit=50, offline=True)
        self.assertTrue(result["passed"], result["findings"])
        self.assertNotIn("| rex ", result["pipeline_query"].lower())
        self.assertEqual(
            set(result["field_strategy_trusted_fields"]),
            {"clientip", "status", "method"},
        )
        self.assertTrue(
            any(
                action.startswith("removed_redundant_rex")
                for action in result["field_policy_actions"]
            )
        )


if __name__ == "__main__":
    unittest.main()
