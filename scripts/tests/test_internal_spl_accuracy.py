#!/usr/bin/env python3
"""Offline tests for internal SPL accuracy harness."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from run_internal_spl_accuracy import (
    InternalCase,
    _load_cases,
    _structural_findings,
    _taxonomy_summary,
    classify_failure,
)


class InternalSplAccuracyTests(unittest.TestCase):
    def test_load_cases_from_oracle_file(self) -> None:
        cases = _load_cases(Path(__file__).resolve().parents[2] / "benchmarks" / "internal_spl_oracles.json")
        self.assertGreaterEqual(len(cases), 10)
        self.assertTrue(all(isinstance(case, InternalCase) for case in cases))

    def test_structural_findings_detect_wrong_index(self) -> None:
        case = InternalCase(
            id="x",
            category="platform_ops",
            question="Show scheduler activity in _internal",
            expected_intent="splunk_internal_health",
            canonical_spl="search index=_internal sourcetype=scheduler | stats count by host",
            earliest_time="-24h",
            latest_time="now",
            compare_fields=("host", "count"),
            profile_window="",
            min_jaccard=0.8,
            entity_fields=("host",),
            min_entity_recall=0.8,
            index_scope="_internal",
            sourcetype_tags=("scheduler",),
        )
        findings = _structural_findings(case, "search index=main sourcetype=scheduler | stats count by host")
        self.assertTrue(any("wrong_index_scope" in item for item in findings))

    def test_classify_routing_wrong_intent(self) -> None:
        case = InternalCase(
            id="x",
            category="platform_ops",
            question="Show splunkd volume",
            expected_intent="internal_splunkd_health",
            canonical_spl="search index=_internal sourcetype=splunkd | stats count by host component",
            earliest_time="-24h",
            latest_time="now",
            compare_fields=("host", "component", "count"),
            profile_window="",
            min_jaccard=0.7,
            entity_fields=("host",),
            min_entity_recall=0.7,
            index_scope="_internal",
            sourcetype_tags=("splunkd",),
        )
        bucket = classify_failure(
            case=case,
            findings=["intent_mismatch:splunk_internal_health->internal_splunkd_health"],
            template_intent="splunk_internal_health",
            tool="splunk_run_query",
            canonical_rows=10,
            pipeline_rows=10,
        )
        self.assertEqual(bucket, "routing_wrong_intent")

    def test_taxonomy_summary_counts_buckets(self) -> None:
        summary = _taxonomy_summary(
            [
                {"failure_bucket": "pass"},
                {"failure_bucket": "routing_wrong_intent"},
                {"failure_bucket": "pass"},
            ]
        )
        self.assertEqual(summary["pass"], 2)
        self.assertEqual(summary["routing_wrong_intent"], 1)


if __name__ == "__main__":
    unittest.main()
