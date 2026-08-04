#!/usr/bin/env python3
"""Unit tests for autonomy fix dispatch."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spl_autonomy_fix_dispatch import build_fix_plan, classify_failure  # noqa: E402


class SplAutonomyFixDispatchTests(unittest.TestCase):
    def test_classify_environment_binding(self) -> None:
        self.assertEqual(classify_failure("environment:unknown_sourcetype"), "environment_binding")

    def test_build_fix_plan_prioritizes_top_class(self) -> None:
        plan = build_fix_plan(
            [
                {"reason": "environment:bad_sourcetype"},
                {"reason": "environment:bad_index"},
                {"reason": "policy:missing_search_prefix"},
            ]
        )
        self.assertEqual(plan["primary_class"], "environment_binding")
        self.assertIn("rebuild_cards", plan["actions"])


if __name__ == "__main__":
    unittest.main()
