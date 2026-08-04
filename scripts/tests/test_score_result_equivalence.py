#!/usr/bin/env python3
"""Focused tests for plan-aware result equivalence."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from score_result_equivalence import score_result_equivalence  # noqa: E402


def _plan(entity: str, value_name: str) -> dict:
    return {
        "normalizations": [
            {
                "output": entity,
                "kind": "native",
                "fields": ["sourceIPAddress"],
            }
        ],
        "analysis": {
            "dimensions": [entity],
            "measures": [
                {"name": "events", "function": "count"},
                {"name": value_name, "function": "values", "field": "operation"},
            ],
            "output_fields": [entity, "events", value_name],
        },
    }


class ScoreResultEquivalenceTests(unittest.TestCase):
    def test_aligns_native_dimension_aliases_from_typed_plans(self) -> None:
        reference = _plan("entity", "operation_values")
        candidate = _plan("sourceipaddress", "native_operation_values")
        reference_rows = [
            {"entity": "192.0.2.1", "events": "2", "operation_values": "PutObject"}
        ]
        candidate_rows = [
            {
                "sourceipaddress": "192.0.2.1",
                "events": "2",
                "native_operation_values": "PutObject",
            }
        ]
        score = score_result_equivalence(
            candidate_rows=candidate_rows,
            reference_rows=reference_rows,
            compare_fields=["entity", "events", "operation_values"],
            entity_fields=["entity"],
            reference_plan=reference,
            candidate_plan=candidate,
        )
        self.assertEqual(score["equivalence_score"], 1.0)

    def test_does_not_claim_equivalence_for_unrelated_aliases(self) -> None:
        reference = _plan("entity", "operation_values")
        candidate = {
            **_plan("sourceipaddress", "native_operation_values"),
            "analysis": {
                "dimensions": ["host"],
                "measures": [
                    {"name": "events", "function": "count"},
                    {"name": "native_operation_values", "function": "values", "field": "host"},
                ],
                "output_fields": ["host", "events", "native_operation_values"],
            },
        }
        score = score_result_equivalence(
            candidate_rows=[{"host": "srv-1", "events": "2", "native_operation_values": "srv-1"}],
            reference_rows=[{"entity": "192.0.2.1", "events": "2", "operation_values": "PutObject"}],
            compare_fields=["entity", "events", "operation_values"],
            entity_fields=["entity"],
            reference_plan=reference,
            candidate_plan=candidate,
        )
        self.assertLess(score["equivalence_score"], 0.75)


if __name__ == "__main__":
    unittest.main()
