#!/usr/bin/env python3
"""Unit tests for SPL phase gate runner."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from run_spl_phase_gate import evaluate_gate  # noqa: E402


class SplPhaseGateTests(unittest.TestCase):
    def test_phase_zero_passes_without_cards(self) -> None:
        metrics = {"writer_avg": 76.0, "hardening_pass_rate": 95.0}
        progress = {"phases": {}, "baseline": metrics}
        gate = evaluate_gate(0, metrics, progress)
        self.assertTrue(gate["passed"])

    def test_phase_one_requires_cards(self) -> None:
        metrics = {"writer_avg": 76.0, "cards_available": False, "cards_count": 0}
        progress = {"phases": {"0": {"metrics": {"writer_avg": 76.0}}}, "baseline": {"writer_avg": 76.0}}
        gate = evaluate_gate(1, metrics, progress)
        self.assertFalse(gate["passed"])

    def test_regression_gt_one_point_fails(self) -> None:
        metrics = {"writer_avg": 74.0, "cards_available": True, "cards_count": 3}
        progress = {
            "phases": {"0": {"metrics": {"writer_avg": 76.0}}},
            "baseline": {"writer_avg": 76.0},
        }
        gate = evaluate_gate(1, metrics, progress)
        self.assertFalse(gate["passed"])

    def test_phase_six_requires_domain_patterns(self) -> None:
        metrics = {
            "writer_avg": 87.0,
            "domain_patterns_available": False,
            "domain_pattern_count": 0,
            "writer_mode": "constrained",
        }
        progress = {
            "phases": {"5": {"metrics": {"writer_avg": 87.0}}},
            "baseline": {"writer_avg": 85.0},
        }
        gate = evaluate_gate(6, metrics, progress)
        self.assertFalse(gate["passed"])


if __name__ == "__main__":
    unittest.main()
