#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spl_rag_context import build_spl_rag_context
import local_learning as ll


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

    def test_context_includes_approved_spl_pattern_asset(self) -> None:
        record = ll._candidate(
            intent="apache_access_top_ips",
            kind="spl_pattern_asset",
            proposal={
                "query_template": "search index=linux sourcetype=access_combined | stats count by clientip",
                "required_fields": ["clientip", "status"],
                "use_when": "Use for Apache access-analysis questions.",
                "why": "Matches the environment.",
            },
            reason="Approved test asset",
        )
        approved = dict(record)
        approved["status"] = "approved"
        with ll.learning_record_override([approved]):
            ctx = build_spl_rag_context("Show top apache client IPs in linux", max_chars=2400)
        self.assertIn("[LOCAL_LEARNING_APPROVED]", ctx)
        self.assertIn("kind=spl_pattern_asset", ctx)
        self.assertIn("search index=linux sourcetype=access_combined | stats count by clientip", ctx)
        self.assertIn("required_fields=clientip, status", ctx)


if __name__ == "__main__":
    unittest.main()
