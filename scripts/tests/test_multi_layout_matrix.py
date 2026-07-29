#!/usr/bin/env python3
"""Tests for multi-layout matrix runner."""

from __future__ import annotations

import unittest
from pathlib import Path

from run_multi_layout_matrix import run_matrix

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class MultiLayoutMatrixTests(unittest.TestCase):
    def test_run_matrix_passes_all_fixtures(self) -> None:
        exit_code, payload = run_matrix(oracles_path=PROJECT_ROOT / "benchmarks" / "gold_spl_oracles.json")
        self.assertEqual(exit_code, 0, payload.get("results"))
        self.assertGreaterEqual(payload.get("passed", 0), 1)
        variants = payload.get("variants", {})
        self.assertIn("minimal_ci", variants)
        self.assertIn("cloud_only", variants)
        self.assertEqual(variants["minimal_ci"]["failed"], 0)
        self.assertEqual(variants["cloud_only"]["failed"], 0)


if __name__ == "__main__":
    unittest.main()
