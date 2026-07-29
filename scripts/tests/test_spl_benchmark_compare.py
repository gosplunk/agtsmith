#!/usr/bin/env python3
"""Tests for spl_benchmark_compare."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spl_benchmark_compare import compare


class SplBenchmarkCompareTests(unittest.TestCase):
    def test_compare_detects_no_regression(self) -> None:
        report = {
            "summary": {"avg_score": 95, "pass_rate_pct": 100.0},
            "results": [{"id": "case_a", "score": 95}, {"id": "case_b", "score": 100}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base.json"
            cur = Path(tmp) / "cur.json"
            base.write_text(json.dumps(report), encoding="utf-8")
            cur.write_text(json.dumps(report), encoding="utf-8")
            outcome = compare(baseline=base, current=cur)
        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["pass_rate_delta"], 0.0)


if __name__ == "__main__":
    unittest.main()
