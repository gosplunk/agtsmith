#!/usr/bin/env python3
"""Tests for explicit sourcetype routing guards."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from langgraph_multi_model_soc import _enforce_question_alignment
from minimal_question_to_answer import map_question_to_template
from question_intelligence import (
    domain_oracle_threshold_for_question,
    extract_explicit_sourcetype,
    query_conflicts_with_explicit_sourcetype,
)
from spl_domain_knowledge import bind_domain_knowledge_for_plan


QUESTION = (
    "Investigate suspicious web access in access_combined over the last 24 hours. "
    "Show top client IPs and status codes."
)
DEMO_QUESTION = QUESTION + " using the public BOTSv3 demo dataset across all time"
OSQUERY_SPL = (
    "search index=botsv3 sourcetype=osquery:results "
    "| spath input=_raw path=name output=query_name "
    "| spath input=_raw path=action output=action "
    "| spath input=_raw path=hostIdentifier output=hostIdentifier "
    "| spath input=_raw path=columns.path output=path "
    "| spath input=_raw path=columns.cmdline output=cmdline "
    "| stats count by hostIdentifier action path cmdline "
    "| sort - count | head 20"
)


class ExplicitSourcetypeRoutingTests(unittest.TestCase):
    def test_extract_access_combined(self) -> None:
        self.assertEqual(extract_explicit_sourcetype(QUESTION), "access_combined")

    def test_osquery_query_conflicts_with_access_combined(self) -> None:
        self.assertTrue(query_conflicts_with_explicit_sourcetype(QUESTION, OSQUERY_SPL))

    def test_domain_oracle_threshold_lower_for_access_combined(self) -> None:
        threshold = domain_oracle_threshold_for_question(
            QUESTION,
            domain_intent="apache_access_top_ips",
            mapped_intent="apache_access_top_ips",
        )
        self.assertEqual(threshold, 0.75)

    def test_domain_oracle_confidence_crosses_threshold(self) -> None:
        bound = bind_domain_knowledge_for_plan(QUESTION, {"intent": "apache_access_top_ips"})
        self.assertTrue(bound.get("matched"))
        self.assertGreaterEqual(float(bound.get("confidence", 0)), 0.75)
        self.assertEqual(bound.get("intent"), "apache_access_top_ips")
        self.assertIn("access_combined", str(bound.get("query", "")))

    def test_apache_pattern_wins_for_explicit_access_combined(self) -> None:
        bound = bind_domain_knowledge_for_plan(QUESTION, {"intent": "apache_access_top_ips"})
        self.assertEqual(bound.get("intent"), "apache_access_top_ips")
        self.assertIn("access_combined", str(bound.get("query", "")))
        self.assertNotIn("osquery", str(bound.get("query", "")))

    def test_enforce_alignment_forces_apache_template(self) -> None:
        mapped = map_question_to_template(QUESTION)
        plan = {
            "selected_tool": "splunk_run_query",
            "tool_args": {"query": OSQUERY_SPL, "earliest_time": "-24h", "latest_time": "now", "row_limit": 20},
            "intent": "osquery_process_activity",
            "confidence": 0.9,
            "reason": "writer_model",
            "source": "writer_model",
        }
        aligned = _enforce_question_alignment(QUESTION, plan)
        query = str(aligned.get("tool_args", {}).get("query", ""))
        self.assertIn("access_combined", query)
        self.assertNotIn("osquery", query)
        self.assertEqual(aligned.get("reason"), "question_alignment_override:explicit_access_combined")

    def test_demo_suffix_still_aligns_access_combined(self) -> None:
        mapped = map_question_to_template(DEMO_QUESTION)
        plan = {
            "selected_tool": "splunk_run_query",
            "tool_args": {"query": OSQUERY_SPL, "earliest_time": "0", "latest_time": "now", "row_limit": 20},
            "intent": "osquery_process_activity",
            "confidence": 0.9,
            "reason": "writer_model",
            "source": "writer_model",
        }
        aligned = _enforce_question_alignment(DEMO_QUESTION, plan)
        query = str(aligned.get("tool_args", {}).get("query", ""))
        self.assertIn("access_combined", query)
        self.assertNotIn("osquery", query)


if __name__ == "__main__":
    unittest.main()
