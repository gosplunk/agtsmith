#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import langgraph_multi_model_soc as mm
from spl_writer_prompt import (
    build_standalone_writer_user_payload,
    build_writer_system_prompt,
    build_writer_user_payload,
    few_shot_examples_for_intent,
)


class SplWriterPromptTests(unittest.TestCase):
    def test_few_shots_include_intent_match(self) -> None:
        examples = few_shot_examples_for_intent("linux_auth_failures", max_examples=2)
        self.assertTrue(examples)
        self.assertEqual(examples[0]["intent"], "linux_auth_failures")
        self.assertIn("tool_args", examples[0])
        self.assertTrue(str(examples[0]["tool_args"].get("query", "")).startswith("search "))

    def test_writer_system_prompt_includes_rules_and_examples(self) -> None:
        prompt = build_writer_system_prompt(intent="apache_404_spike")
        self.assertIn("SPL composition rules", prompt)
        self.assertIn("Few-shot gold examples", prompt)
        self.assertIn("apache_404_spike", prompt)
        self.assertIn("field_strategy is authoritative", prompt)

    def test_standalone_user_payload_includes_canonical_anchor(self) -> None:
        question = "Show failed SSH login activity in the last 24 hours on my linux systems."
        payload = build_standalone_writer_user_payload(question, intent="linux_auth_failures")
        self.assertIn("canonical_anchor_query", payload)
        self.assertIn("index=linux", str(payload["canonical_anchor_query"]))

    def test_writer_bypass_for_template_override_modes(self) -> None:
        question = "Show failed SSH login activity in the last 24 hours on my linux systems."
        mapped = mm.map_question_to_template(question)
        with mock.patch.dict(os.environ, {"AGTSMITH_TEMPLATE_OVERRIDE": "never"}, clear=False):
            self.assertIsNone(mm._writer_bypass_for_template_override(question, mapped))
        for mode in ("fallback", "always"):
            with mock.patch.dict(os.environ, {"AGTSMITH_TEMPLATE_OVERRIDE": mode}, clear=False):
                bypass = mm._writer_bypass_for_template_override(question, mapped)
                self.assertIsNotNone(bypass)
                self.assertEqual(bypass.get("source"), "writer_template_bypass")

    def test_writer_bypass_preserves_first_seen_intent_and_shape(self) -> None:
        for question in (
            "Show new sudo behavior over the last day.",
            "Show first observed root sessions today.",
        ):
            with self.subTest(question=question):
                mapped = mm.map_question_to_template(question)
                bypass = mm._writer_bypass_for_template_override(question, mapped)
                self.assertIsNotNone(bypass)
                self.assertEqual(bypass.get("intent"), "linux_privilege_escalation_first_seen")
                query = str((bypass.get("tool_args") or {}).get("query", "")).lower()
                self.assertIn("earliest(_time)", query)
                self.assertIn("first_seen", query)
                self.assertNotIn("| table _time", query)

    def test_privilege_activity_template_preserves_complete_evidence_fields(
        self,
    ) -> None:
        question = "Show sudo activity on linux in the last 24 hours."
        mapped = mm.map_question_to_template(question)
        bypass = mm._writer_bypass_for_template_override(question, mapped)
        self.assertIsNotNone(bypass)
        query = str((bypass.get("tool_args") or {}).get("query", ""))
        self.assertIn("pkexec_actor", query)
        self.assertIn('fillnull value="unknown" actor target_user command', query)
        self.assertIn("process_name=case(", query)

    def test_writer_bypass_covers_internal_auth_failures(self) -> None:
        for question in (
            "Show failed Splunk logins today.",
            "Show _audit auth failures today.",
        ):
            with self.subTest(question=question):
                mapped = mm.map_question_to_template(question)
                bypass = mm._writer_bypass_for_template_override(question, mapped)
                self.assertIsNotNone(bypass)
                self.assertEqual(bypass.get("intent"), "internal_auth_failures")
                args = bypass.get("tool_args") or {}
                self.assertIn("index=_audit", str(args.get("query", "")))
                self.assertEqual(args.get("earliest_time"), "@d")

    def test_writer_bypass_keeps_credential_json_extraction(self) -> None:
        question = "Show Windows credential access activity in the last 30 days and preserve the evidence rows."
        mapped = mm.map_question_to_template(question)
        bypass = mm._writer_bypass_for_template_override(question, mapped)
        self.assertIsNotNone(bypass)
        query = str((bypass.get("tool_args") or {}).get("query", "")).lower()
        self.assertIn("| spath input=_raw", query)
        self.assertIn("subjectusername", query)
        self.assertIn("targetname", query)

    def test_writer_bypass_requires_complete_sysmon_network_evidence(self) -> None:
        question = (
            "Show Windows Sysmon network connections in the last 30 days with "
            "process image, source IP, destination IP, destination port, and protocol."
        )
        mapped = mm.map_question_to_template(question)
        bypass = mm._writer_bypass_for_template_override(question, mapped)
        self.assertIsNotNone(bypass)
        query = str((bypass.get("tool_args") or {}).get("query", "")).lower()
        self.assertIn("| spath input=_raw", query)
        self.assertIn(
            "| search image=* sourceip=* destinationip=* destinationport=* protocol=*",
            query,
        )

    def test_writer_payload_includes_domain_oracle(self) -> None:
        payload = build_writer_user_payload(
            question="how many indexes do I have?",
            planner_output={"intent": "top_indexes", "selected_tool": "splunk_run_query", "tool_args": {}},
            domain_knowledge_output={
                "matched": True,
                "pattern_id": "index_count_cardinality",
                "preferred_tool": "splunk_get_indexes",
                "query": "search index=* NOT index=_* | stats dc(index) as index_count",
                "explanation": "Count distinct indexes.",
                "anti_patterns": [r"\|\s*stats\s+count\s*$"],
                "context": "SPL domain oracle",
            },
        )
        self.assertIn("domain_knowledge", payload)
        self.assertEqual(payload["domain_knowledge"]["pattern_id"], "index_count_cardinality")
        self.assertIn("dc(index)", payload["domain_knowledge"]["canonical_query"])

    def test_writer_payload_exposes_only_bounded_strategy_contract(self) -> None:
        payload = build_writer_user_payload(
            question="Show top Apache client IPs",
            planner_output={"intent": "apache_access_top_ips"},
            field_strategy_output={
                "intent": "apache_access_top_ips",
                "indexes": ["linux"],
                "sourcetype": "access_combined",
                "trusted_fields": ["clientip", "status", "method"],
                "trusted_role_mappings": {"src_ip": ["clientip"]},
                "trusted_coalesce_hints": {"src_ip": "clientip"},
                "roles": {"src_ip": {"classification": "native", "evidence": [{"sample": "secret"}]}},
                "forbid_unnecessary_extraction": True,
                "evidence": [{"sample": "must_not_leak"}],
            },
        )
        strategy = payload["field_strategy"]
        self.assertEqual(strategy["trusted_native_fields"], ["clientip", "status", "method"])
        self.assertTrue(strategy["forbid_unnecessary_extraction"])
        self.assertNotIn("evidence", strategy)
        self.assertNotIn("sample", str(strategy))


if __name__ == "__main__":
    unittest.main()
