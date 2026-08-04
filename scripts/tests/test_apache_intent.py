#!/usr/bin/env python3
"""Deterministic Apache intent, query, contract, and fields-first corpus."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from intent_field_contracts import validate_query_for_intent
from minimal_question_to_answer import map_question_to_template, template_to_query_args
from spl_domain_knowledge import resolve_domain_knowledge
from spl_field_strategy import clear_field_verification_cache, resolve_field_strategy, rewrite_query_fields_first


ROOT = Path(__file__).resolve().parents[2]
CASES = json.loads((ROOT / "benchmarks/apache_intent_cases.json").read_text(encoding="utf-8"))
EXACT_PROMPT = (
    "Investigate suspicious activity in access_combined over the last 7 days. "
    "Show client IPs, status codes, methods, requested paths, and user agents."
)


class ApacheIntentCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_field_verification_cache()

    def test_broad_apache_corpus_routes_and_materializes_complete_queries(self) -> None:
        self.assertGreaterEqual(len(CASES), 20)
        for case in CASES:
            question = case["question"]
            with self.subTest(case=case["id"]):
                template = map_question_to_template(question)
                self.assertEqual(template.intent, case["expected_intent"])
                args = template_to_query_args(template, question, apply_environment=False)
                query = str(args["query"])
                query_l = query.lower()
                if case.get("expected_earliest"):
                    self.assertEqual(args["earliest_time"], case["expected_earliest"])
                for field in case.get("required_result_fields", []):
                    self.assertIn(field.lower(), query_l)
                for term in case.get("required_query_terms", []):
                    self.assertIn(term.lower(), query_l)
                for term in case.get("forbidden_query_terms", []):
                    self.assertNotIn(term.lower(), query_l)
                ok, reason = validate_query_for_intent(
                    template.intent,
                    args,
                    question=question,
                )
                self.assertTrue(ok, reason)

    def test_exact_prompt_requires_every_dimension_and_suspicious_predicate(self) -> None:
        template = map_question_to_template(EXACT_PROMPT)
        self.assertEqual(template.intent, "apache_suspicious_activity")
        args = template_to_query_args(template, EXACT_PROMPT, apply_environment=False)
        query_l = str(args["query"]).lower()
        for field in ("clientip", "status", "method", "uri_path", "useragent", "suspicious_reason"):
            self.assertIn(field, query_l)
        self.assertIn("where isnotnull(suspicious_reason)", query_l)
        self.assertEqual(args["earliest_time"], "-7d")

    def test_exact_prompt_contract_rejects_observed_incomplete_query(self) -> None:
        ok, reason = validate_query_for_intent(
            "apache_suspicious_activity",
            {
                "query": (
                    "search index=botsv3 sourcetype=access_combined "
                    "| stats count by clientip status method | sort - count"
                )
            },
            question=EXACT_PROMPT,
        )
        self.assertFalse(ok)
        self.assertIn("missing_group", reason)

    def test_exact_prompt_fields_first_removes_rex_when_all_native_fields_verified(self) -> None:
        template = map_question_to_template(EXACT_PROMPT)
        args = template_to_query_args(template, EXACT_PROMPT, apply_environment=False)
        strategy = resolve_field_strategy(
            EXACT_PROMPT,
            {
                "intent": template.intent,
                "canonical_template_query": args["query"],
                "tool_args": args,
            },
            field_bind_output={
                "intent": template.intent,
                "index_expr": "index=botsv3",
                "sourcetype": "access_combined",
            },
            verifier=lambda *_args: {"clientip", "status", "method", "uri_path", "uri", "useragent", "_raw"},
            profile={},
        )
        rewritten, actions = rewrite_query_fields_first(args["query"], strategy)
        self.assertNotIn("| rex ", rewritten.lower())
        self.assertTrue(any(action.startswith("removed_redundant_rex") for action in actions))
        for field in ("clientip", "status", "method", "uri_path", "useragent"):
            self.assertIn(field, rewritten.lower())

    def test_exact_prompt_keeps_rex_when_required_native_path_is_missing(self) -> None:
        template = map_question_to_template(EXACT_PROMPT)
        args = template_to_query_args(template, EXACT_PROMPT, apply_environment=False)
        strategy = resolve_field_strategy(
            EXACT_PROMPT,
            {"intent": template.intent, "canonical_template_query": args["query"], "tool_args": args},
            field_bind_output={
                "intent": template.intent,
                "index_expr": "index=raw_web",
                "sourcetype": "access_combined",
            },
            verifier=lambda *_args: {"clientip", "status", "method", "useragent", "_raw"},
            profile={},
        )
        rewritten, _actions = rewrite_query_fields_first(args["query"], strategy)
        self.assertIn("| rex ", rewritten.lower())

    def test_domain_oracle_uses_same_exact_prompt_family(self) -> None:
        resolution = resolve_domain_knowledge(EXACT_PROMPT, intent="apache_suspicious_activity")
        self.assertIsNotNone(resolution)
        assert resolution is not None
        self.assertEqual(resolution.intent, "apache_suspicious_activity")
        self.assertIn("suspicious_reason", resolution.query)
        self.assertNotIn("stream:http", resolution.query)


if __name__ == "__main__":
    unittest.main()
