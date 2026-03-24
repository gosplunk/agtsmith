#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spl_rag_context import build_spl_rag_context


class TestSplRagContext(unittest.TestCase):
    def test_context_is_non_empty_for_common_question(self) -> None:
        ctx = build_spl_rag_context("Show failed login activity in the last 24 hours")
        self.assertTrue(ctx.strip())
        self.assertIn("[ENV_CONSTRAINTS]", ctx)
        self.assertIn("CIM", ctx)

    def test_context_filters_write_commands(self) -> None:
        ctx = build_spl_rag_context("Show failed login activity in the last 24 hours").lower()
        self.assertNotIn("| collect", ctx)
        self.assertNotIn("| sendalert", ctx)
        self.assertNotIn("| outputlookup", ctx)


if __name__ == "__main__":
    unittest.main()
