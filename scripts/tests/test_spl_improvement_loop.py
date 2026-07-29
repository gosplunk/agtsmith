#!/usr/bin/env python3
"""Tests for SPL improvement loop MCP evidence gate."""

from __future__ import annotations

import unittest

from spl_improvement_loop import propose_candidate_from_failure


class SplImprovementLoopTests(unittest.TestCase):
    def test_empty_result_requires_live_mcp_evidence(self) -> None:
        row = {
            "score": 10,
            "failure_class": "empty_result",
            "intent": "failed_login_activity",
            "question": "failed logons",
            "query": "search index=foo",
            "id": "case1",
        }
        self.assertIsNone(propose_candidate_from_failure(row))

    def test_empty_result_with_mcp_executed_allows_candidate(self) -> None:
        row = {
            "score": 10,
            "failure_class": "empty_result",
            "intent": "failed_login_activity",
            "question": "failed logons",
            "query": "search index=foo",
            "id": "case1",
            "mcp_executed": True,
        }
        candidate = propose_candidate_from_failure(row)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.get("kind"), "post_result_pivot_hint")


if __name__ == "__main__":
    unittest.main()
