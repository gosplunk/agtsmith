#!/usr/bin/env python3
"""Unit tests for deterministic core-TDIR enrichment."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tdir_core import build_tdir_case


class TdirCoreTests(unittest.TestCase):
    def test_failed_login_case_high_signal(self) -> None:
        case = build_tdir_case(
            question="Show failed login activity in last 24h",
            intent="failed_login_activity",
            selected_tool="splunk_run_query",
            query_args={"query": "search ...", "earliest_time": "-24h", "latest_time": "now", "row_limit": 10},
            structured={
                "results": [
                    {"user": "svc-account", "src": "10.1.2.3", "count": "768"},
                    {"user": "admin", "src": "10.1.2.4", "count": "21"},
                ],
                "total_rows": 2,
            },
            pipeline="multi_model_reviewer",
        )
        self.assertEqual(case["severity"], "high")
        self.assertGreaterEqual(int(case["risk_score"]), 80)
        self.assertEqual(case["phase_status"]["soar_automation"], "not_enabled_yet")
        self.assertTrue(case["recommended_next_pivots"])
        self.assertNotIn("Pivot to index inventory for broader visibility.", case["recommended_next_pivots"])

    def test_zero_row_case(self) -> None:
        case = build_tdir_case(
            question="Show apache 404 spike in last 24h",
            intent="apache_404_spike",
            selected_tool="splunk_run_query",
            query_args={"query": "search ...", "earliest_time": "-24h", "latest_time": "now", "row_limit": 10},
            structured={"results": [], "total_rows": 0},
            pipeline="agentic_loop",
        )
        self.assertEqual(case["severity"], "info")
        self.assertEqual(int(case["risk_score"]), 10)
        self.assertIn("No matching events", case["incident_hypothesis"])


if __name__ == "__main__":
    unittest.main()
