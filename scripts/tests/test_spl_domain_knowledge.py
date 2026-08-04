#!/usr/bin/env python3
"""Tests for SPL domain knowledge layer."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spl_domain_knowledge import (  # noqa: E402
    apply_domain_postprocess,
    match_patterns,
    resolve_domain_knowledge,
    validate_query_against_domain_knowledge,
)


class SplDomainKnowledgeTests(unittest.TestCase):
    def test_how_many_indexes_matches_cardinality_pattern(self) -> None:
        question = "how many indexes do I have in this splunk environment?"
        resolution = resolve_domain_knowledge(question)
        self.assertIsNotNone(resolution)
        assert resolution is not None
        self.assertEqual(resolution.pattern_id, "index_count_cardinality")
        self.assertEqual(resolution.preferred_tool, "splunk_run_query")
        self.assertIn("dc(index)", resolution.query.lower())

    def test_rejects_event_total_for_index_count(self) -> None:
        question = "how many indexes do I have?"
        bad = "search index=* NOT index=_* | stats count"
        ok, reason = validate_query_against_domain_knowledge(bad, question=question)
        self.assertFalse(ok)
        self.assertTrue(reason.startswith("domain_"))

    def test_apply_domain_postprocess_fixes_bad_query(self) -> None:
        question = "how many indexes do I have?"
        bad = "search index=* NOT index=_* | stats count"
        fixed = apply_domain_postprocess(bad, question=question)
        self.assertIn("dc(index)", fixed.lower())

    def test_busiest_indexes_matches_volume_pattern(self) -> None:
        question = "Which indexes had the most events in the last 24 hours?"
        matches = match_patterns(question, intent="top_indexes")
        self.assertTrue(matches)
        self.assertIn(matches[0][0].id, {"index_volume_ranking", "template_top_indexes"})

    def test_internal_health_scopes_internal_index(self) -> None:
        question = "Show Splunk internal sourcetype volume in the last 24 hours"
        resolution = resolve_domain_knowledge(question)
        self.assertIsNotNone(resolution)
        assert resolution is not None
        self.assertIn("_internal", resolution.query)

    def test_internal_audit_failures_pattern(self) -> None:
        question = "Show _audit auth failures today"
        resolution = resolve_domain_knowledge(question)
        self.assertIsNotNone(resolution)
        assert resolution is not None
        self.assertEqual(resolution.pattern_id, "internal_audit_auth_failures")
        self.assertIn("index=_audit", resolution.query)

    def test_internal_health_rejects_stats_by_source(self) -> None:
        question = "Show Splunk internal sourcetype volume in the last 24 hours"
        bad = "search index=_internal | stats count by source | sort - count"
        ok, reason = validate_query_against_domain_knowledge(bad, question=question)
        self.assertFalse(ok)
        self.assertIn("domain_anti_pattern", reason)

    def test_cross_platform_failed_login_accepts_separate_append_branch(self) -> None:
        question = "Show failed logon activity in the last 24 hours"
        query = (
            'search index=linux sourcetype=linux_secure "Failed password" '
            '| eval platform="linux" '
            "| append [ search index=windows sourcetype=XmlWinEventLog EventCode=4625 "
            '| eval platform="windows" ] '
            "| stats count by platform host"
        )
        ok, reason = validate_query_against_domain_knowledge(
            query,
            question=question,
            intent="failed_login_activity",
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "domain_ok")


if __name__ == "__main__":
    unittest.main()
