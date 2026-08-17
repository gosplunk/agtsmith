#!/usr/bin/env python3
"""Offline tests for Linux SPL accuracy harness."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from run_linux_spl_accuracy import (
    LinuxCase,
    _load_cases,
    _structural_findings,
    _taxonomy_summary,
    classify_failure,
)


class LinuxSplAccuracyTests(unittest.TestCase):
    def test_load_cases_from_oracle_file(self) -> None:
        cases = _load_cases(Path(__file__).resolve().parents[2] / "benchmarks" / "linux_spl_oracles.json")
        self.assertGreaterEqual(len(cases), 10)
        self.assertTrue(all(isinstance(case, LinuxCase) for case in cases))

    def test_structural_findings_detect_wrong_index(self) -> None:
        case = LinuxCase(
            id="x",
            category="platform_ops",
            question="Show Linux failed login activity",
            expected_intent="linux_auth_failures",
            canonical_spl='search index=linux (source="/var/log/auth.log") | stats count by host',
            earliest_time="-24h",
            latest_time="now",
            compare_fields=("host", "count"),
            profile_window="",
            entity_fields=("host",),
            min_jaccard=0.8,
            min_entity_recall=0.8,
            index_scope="linux",
            sourcetype_tags=(),
        )
        findings = _structural_findings(case, "search index=main sourcetype=linux_secure | stats count by host")
        self.assertTrue(any("wrong_index_scope" in item for item in findings))

    def test_classify_routing_wrong_intent(self) -> None:
        case = LinuxCase(
            id="x",
            category="platform_ops",
            question="Show failed sudo on Linux",
            expected_intent="linux_privilege_escalation",
            canonical_spl='search index=linux (source="/var/log/auth.log") | stats count by host',
            earliest_time="-24h",
            latest_time="now",
            compare_fields=("host", "count"),
            profile_window="",
            entity_fields=("host",),
            min_jaccard=0.7,
            min_entity_recall=0.7,
            index_scope="linux",
            sourcetype_tags=(),
        )
        bucket = classify_failure(
            case=case,
            findings=["intent_mismatch:linux_session_activity->linux_privilege_escalation"],
            template_intent="linux_session_activity",
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
