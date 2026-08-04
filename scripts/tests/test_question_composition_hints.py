#!/usr/bin/env python3
"""Regression tests for generalized compositional question hints."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from question_intelligence import (  # noqa: E402
    extract_explicit_dataset_locks,
    infer_analytical_shape_hints,
)


class QuestionCompositionHintTests(unittest.TestCase):
    def test_preserves_cross_event_and_intersection_composition(self) -> None:
        question = (
            "Join auth/linux_secure and web/proxy:access through src / clientip, "
            "collect the observed TargetUserName and Computer values, and count "
            "events where both are present."
        )
        hints = infer_analytical_shape_hints(question)

        self.assertEqual(
            hints["requested_datasets"],
            {
                "indexes": ["auth", "web"],
                "sourcetypes": ["linux_secure", "proxy:access"],
            },
        )
        self.assertIn("src_ip", hints["dimensions"])
        self.assertEqual(
            {measure["field_hint"] for measure in hints["measures"] if measure["function"] == "values"},
            {"user", "host"},
        )
        self.assertEqual(hints["intersections"][0]["fields"], ["user", "host"])

    def test_ratio_only_request_does_not_invent_comparison_measures(self) -> None:
        hints = infer_analytical_shape_hints(
            "For index cloud sourcetype azure:audit, calculate by ipAddress "
            "the percentage of events with result_state=succeeded."
        )

        self.assertEqual(hints["dimensions"], ["src_ip"])
        self.assertEqual(hints["comparisons"], [])
        self.assertEqual(
            [measure for measure in hints["measures"] if measure.get("condition")],
            [],
        )
        self.assertEqual(extract_explicit_dataset_locks(
            "Join auth/linux_secure and web/proxy:access through src"
        )["indexes"], ["auth", "web"])


if __name__ == "__main__":
    unittest.main()
