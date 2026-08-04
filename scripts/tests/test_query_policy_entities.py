#!/usr/bin/env python3
"""Tests for explicit host-constraint policy enforcement."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from query_policy import validate_query_args


def _args(query: str) -> dict[str, object]:
    return {
        "query": query,
        "earliest_time": "-24h",
        "latest_time": "now",
        "row_limit": 10,
    }


class QueryPolicyEntityTests(unittest.TestCase):
    def test_rejects_stopword_host_constraint(self) -> None:
        ok, reason = validate_query_args(
            _args("search host IN (is) index=linux | stats count by host"),
            question="Which host is being targeted most?",
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "fabricated_host_constraint:is")

    def test_rejects_host_constraint_absent_from_question(self) -> None:
        ok, reason = validate_query_args(
            _args("search host IN (prod-web-01) index=linux | stats count by host"),
            question="Show failed Linux logins.",
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "host_constraint_not_explicit:prod-web-01")

    def test_accepts_explicit_host_constraint(self) -> None:
        ok, reason = validate_query_args(
            _args("search host IN (prod-web-01) index=linux | stats count by host"),
            question="Show failed Linux logins for host=prod-web-01.",
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "query_policy_ok")


if __name__ == "__main__":
    unittest.main()
