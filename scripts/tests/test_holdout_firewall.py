#!/usr/bin/env python3
"""Focused tests for protected eval21 split and leakage controls."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from build_spl_domain_patterns import build_patterns
from holdout_firewall import (
    assert_no_holdout_leakage,
    filter_holdout_records,
    holdout_leak_reasons,
    load_split_manifest,
    protected_material,
    protected_sha256,
)
from query_templates import TEMPLATES
from run_holdout_eval import reproduce_baseline
from score_result_equivalence import (
    empty_result_score,
    entity_recall,
    jaccard,
    row_ratio,
    score_result_equivalence,
    top_k_overlap,
)
from spl_improvement_loop import propose_candidate_from_failure

ROOT = Path(__file__).resolve().parents[2]
CASES_PATH = ROOT / "benchmarks" / "holdout_eval21_cases.json"
MANIFEST_PATH = ROOT / "benchmarks" / "scenario_splits" / "manifest.json"


class ResultEquivalenceTests(unittest.TestCase):
    def test_shared_equivalence_primitives(self) -> None:
        self.assertEqual(jaccard({"a", "b"}, {"b", "c"}), 1 / 3)
        self.assertEqual(entity_recall({"a"}, {"a", "b"}), 0.5)
        self.assertEqual(row_ratio(2, 4), 0.5)
        self.assertEqual(empty_result_score(0, 0), 1.0)
        self.assertEqual(empty_result_score(0, 1), 0.0)

    def test_top_k_and_composite_score(self) -> None:
        candidate = [{"host": "a"}, {"host": "b"}]
        reference = [{"host": "a"}, {"host": "c"}]
        self.assertEqual(
            top_k_overlap(candidate, reference, fields=("host",), k=2),
            1 / 3,
        )
        score = score_result_equivalence(
            candidate_rows=candidate,
            reference_rows=reference,
            compare_fields=("host",),
            entity_fields=("host",),
        )
        self.assertEqual(score["row_ratio"], 1.0)
        self.assertEqual(score["entity_recall"], 0.5)


class HoldoutFirewallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        cls.first = cls.corpus["cases"][0]

    def test_manifest_freezes_all_21_cases(self) -> None:
        manifest = load_split_manifest(MANIFEST_PATH)
        holdout = manifest["splits"]["holdout"]
        case_ids = [row["id"] for row in self.corpus["cases"]]
        self.assertEqual(len(holdout), 21)
        self.assertEqual(holdout, case_ids)
        self.assertEqual(set(holdout) & set(manifest["splits"]["train"]), set())
        self.assertEqual(set(holdout) & set(manifest["splits"]["dev"]), set())

    def test_rejects_id_question_query_failure_and_hash(self) -> None:
        baseline = json.loads(
            (ROOT / "benchmarks" / "holdout_eval21_baseline.json").read_text(encoding="utf-8")
        )
        records = [
            {"case_id": self.first["id"]},
            {"text": f"prefix {self.first['question']} suffix"},
            {"query": self.first["reference_spl"]},
            {"failure": baseline["cases"][0]["finding"]},
            {"sha256": protected_sha256(self.first["question"])},
            {"id": "safe", "text": "independent training example"},
        ]
        allowed, rejected = filter_holdout_records(records)
        self.assertEqual(allowed, [records[-1]])
        self.assertEqual(len(rejected), 5)

    def test_improvement_loop_rejects_holdout_failure(self) -> None:
        row = {
            "id": self.first["id"],
            "question": self.first["question"],
            "expected_intent": "linux_auth_failures",
            "score": 0,
            "failure_class": "policy_failure",
            "query": self.first["reference_spl"],
        }
        self.assertIsNone(propose_candidate_from_failure(row))

    def test_domain_patterns_reject_holdout_corpus(self) -> None:
        payload = build_patterns(
            templates=False,
            operational_cases=CASES_PATH,
            gold_oracles=ROOT / "benchmarks" / "does-not-exist.json",
        )
        self.assertEqual(payload["holdout_rejected_count"], 21)
        self.assertFalse(
            any(str(row.get("id", "")).startswith("benchmark_") for row in payload["patterns"])
        )

    def test_current_templates_contain_no_protected_holdout_material(self) -> None:
        payload = [
            {
                "intent": template.intent,
                "keywords": list(template.keywords),
                "query": template.query,
                "summary_hint": template.summary_hint,
            }
            for template in TEMPLATES
        ]
        self.assertEqual(holdout_leak_reasons(payload), [])
        assert_no_holdout_leakage(payload, asset_name="query_templates")

    def test_protected_material_includes_questions_queries_failures_and_hashes(self) -> None:
        material = protected_material()
        self.assertEqual(len(material["ids"]), 21)
        self.assertIn(self.first["question"].casefold(), material["fragments"])
        self.assertIn(self.first["reference_spl"].casefold(), material["fragments"])
        self.assertIn(protected_sha256(self.first["question"]), material["hashes"])

    def test_frozen_baseline_reproduces(self) -> None:
        report = reproduce_baseline()
        self.assertTrue(report["reproduced"])
        self.assertEqual(report["case_count"], 21)
        self.assertEqual(
            report["aggregate"],
            {"average": 26.4, "pass": 0, "partial": 2, "fail": 19},
        )


if __name__ == "__main__":
    unittest.main()
