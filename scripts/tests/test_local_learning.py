#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import local_learning as ll


class TestLocalLearning(unittest.TestCase):
    def test_spl_pattern_asset_is_sanitized(self) -> None:
        proposal, changed = ll._sanitize_learning_proposal(
            "spl_pattern_asset",
            {
                "query_template": "  search index=linux sourcetype=access_combined | stats count by clientip  ",
                "required_fields": ["clientip", "status", ""],
                "required_sourcetypes": ["access_combined", "auth-too_small"],
                "why": "  Useful for apache web questions. ",
            },
        )
        self.assertTrue(changed)
        self.assertEqual(proposal["query_template"], "search index=linux sourcetype=access_combined | stats count by clientip")
        self.assertEqual(proposal["required_fields"], ["clientip", "status"])
        self.assertEqual(proposal["required_sourcetypes"], ["access_combined"])
        self.assertEqual(proposal["why"], "Useful for apache web questions.")

    def test_spl_pattern_asset_targets_writer_scope(self) -> None:
        intents = ll._candidate_writer_target_intents(
            {"intent": "apache_access_top_ips", "kind": "spl_pattern_asset"},
            ["apache_access_top_ips", "failed_login_activity"],
        )
        self.assertEqual(intents, ["apache_access_top_ips"])

    def test_repository_compiles_active_and_history_assets(self) -> None:
        rows = [
            {
                "id": "a1",
                "intent": "apache_access_top_ips",
                "kind": "spl_pattern_asset",
                "status": "approved",
                "proposal": {
                    "query_template": "search index=linux sourcetype=access_combined | stats count by clientip",
                    "required_fields": ["clientip"],
                    "why": "Approved apache asset.",
                },
                "reason": "Useful pattern",
                "created_at": "2026-04-02T00:00:00+00:00",
                "updated_at": "2026-04-02T00:00:00+00:00",
            },
            {
                "id": "a2",
                "intent": "linux_auth_failures",
                "kind": "spl_pattern_asset",
                "status": "pending",
                "proposal": {
                    "query_template": "search index=linux source=\"/var/log/auth.log\" | stats count by user_name",
                    "required_sources": ["/var/log/auth.log"],
                },
                "reason": "Pending pattern",
                "created_at": "2026-04-02T00:00:00+00:00",
                "updated_at": "2026-04-02T00:00:00+00:00",
            },
        ]
        repo = ll._compile_spl_optimization_repository(rows)
        self.assertEqual(len(repo["active_assets"]), 1)
        self.assertEqual(len(repo["history_assets"]), 2)
        self.assertEqual(repo["active_assets"][0]["intent"], "apache_access_top_ips")


    def test_observed_assets_are_written_to_repository_history_even_when_not_selected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            old_registry = ll.REGISTRY_PATH
            old_repo = ll.SPL_OPTIMIZATION_REPOSITORY_PATH
            old_root = ll.LEARNING_ROOT
            try:
                ll.LEARNING_ROOT = tmp_root
                ll.REGISTRY_PATH = tmp_root / "local_learning_registry.json"
                ll.SPL_OPTIMIZATION_REPOSITORY_PATH = tmp_root / "spl_optimization_repository.json"
                ll.save_learning_registry({"version": 1, "records": []})
                observed = [{
                    "id": "obs1",
                    "intent": "apache_access_top_ips",
                    "kind": "spl_pattern_asset",
                    "status": "generated",
                    "proposal": {
                        "query_template": "search index=linux sourcetype=access_combined | stats count by clientip",
                        "required_fields": ["clientip"],
                        "why": "Generated apache asset.",
                    },
                    "reason": "Generated during optimization",
                    "selection_reason": "Did not beat current approved baseline",
                    "benchmark_impact": {"avg_score_delta": 0.0, "pass_rate_delta": 0.0},
                    "created_at": "2026-04-02T00:00:00+00:00",
                    "updated_at": "2026-04-02T00:00:00+00:00",
                }]
                outcome = ll._upsert_candidates([], observed_assets=observed)
                self.assertEqual(outcome["created"], 0)
                import json
                repo = json.loads(ll.SPL_OPTIMIZATION_REPOSITORY_PATH.read_text())
                self.assertEqual(len(repo["active_assets"]), 0)
                self.assertEqual(len(repo["history_assets"]), 1)
                self.assertEqual(repo["history_assets"][0]["status"], "generated")
                self.assertEqual(repo["history_assets"][0]["query_template"], "search index=linux sourcetype=access_combined | stats count by clientip")
            finally:
                ll.REGISTRY_PATH = old_registry
                ll.SPL_OPTIMIZATION_REPOSITORY_PATH = old_repo
                ll.LEARNING_ROOT = old_root


    def test_learning_registry_summary_preserves_existing_repository_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            old_registry = ll.REGISTRY_PATH
            old_repo = ll.SPL_OPTIMIZATION_REPOSITORY_PATH
            old_root = ll.LEARNING_ROOT
            try:
                ll.LEARNING_ROOT = tmp_root
                ll.REGISTRY_PATH = tmp_root / "local_learning_registry.json"
                ll.SPL_OPTIMIZATION_REPOSITORY_PATH = tmp_root / "spl_optimization_repository.json"
                ll.save_learning_registry({"version": 1, "records": []})
                ll.write_spl_optimization_repository({
                    "active_assets": [],
                    "history_assets": [{
                        "id": "obs2",
                        "intent": "windows_auth_failures",
                        "status": "generated",
                        "query_template": "search index=windows sourcetype=XmlWinEventLog EventCode=4625 | stats count by user_name",
                        "required_fields": ["user_name", "EventCode"],
                        "required_sources": [],
                        "required_sourcetypes": ["XmlWinEventLog"],
                        "match_tokens": ["windows", "failed login"],
                        "use_when": "Use for Windows failed logon questions.",
                        "avoid_when": [],
                        "why": "Generated windows asset.",
                        "reason": "Generated during optimization",
                        "created_at": "2026-04-02T00:00:00+00:00",
                        "updated_at": "2026-04-02T00:00:00+00:00",
                        "selection_reason": "observed_only",
                        "benchmark_impact": {"avg_score_delta": 0.0},
                    }],
                })
                summary = ll.learning_registry_summary()
                self.assertEqual(summary["repository"]["history_assets"], 1)
                import json
                repo = json.loads(ll.SPL_OPTIMIZATION_REPOSITORY_PATH.read_text())
                self.assertEqual(len(repo["history_assets"]), 1)
                self.assertEqual(repo["history_assets"][0]["intent"], "windows_auth_failures")
            finally:
                ll.REGISTRY_PATH = old_registry
                ll.SPL_OPTIMIZATION_REPOSITORY_PATH = old_repo
                ll.LEARNING_ROOT = old_root


    def test_repository_asset_can_be_approved_into_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            old_registry = ll.REGISTRY_PATH
            old_repo = ll.SPL_OPTIMIZATION_REPOSITORY_PATH
            old_root = ll.LEARNING_ROOT
            try:
                ll.LEARNING_ROOT = tmp_root
                ll.REGISTRY_PATH = tmp_root / "local_learning_registry.json"
                ll.SPL_OPTIMIZATION_REPOSITORY_PATH = tmp_root / "spl_optimization_repository.json"
                ll.save_learning_registry({"version": 1, "records": []})
                ll.write_spl_optimization_repository({
                    "active_assets": [],
                    "history_assets": [{
                        "id": "asset1",
                        "intent": "apache_access_top_ips",
                        "status": "pending",
                        "query_template": "search index=linux sourcetype=access_combined | stats count by clientip",
                        "required_fields": ["clientip"],
                        "required_sources": [],
                        "required_sourcetypes": ["access_combined"],
                        "match_tokens": ["apache", "top ip"],
                        "use_when": "Use for apache access-analysis questions.",
                        "avoid_when": [],
                        "why": "Generated apache asset.",
                        "reason": "Generated during optimization",
                        "created_at": "2026-04-02T00:00:00+00:00",
                        "updated_at": "2026-04-02T00:00:00+00:00",
                        "selection_reason": "no_gain",
                        "benchmark_impact": {"avg_score_delta": 0.0},
                    }],
                })
                self.assertTrue(ll.set_learning_record_status("asset1", "approved"))
                reg = ll.load_learning_registry()
                self.assertEqual(len(reg["records"]), 1)
                self.assertEqual(reg["records"][0]["status"], "approved")
                import json
                repo = json.loads(ll.SPL_OPTIMIZATION_REPOSITORY_PATH.read_text())
                self.assertEqual(len(repo["active_assets"]), 1)
                self.assertEqual(repo["active_assets"][0]["intent"], "apache_access_top_ips")
            finally:
                ll.REGISTRY_PATH = old_registry
                ll.SPL_OPTIMIZATION_REPOSITORY_PATH = old_repo
                ll.LEARNING_ROOT = old_root

    def test_set_learning_record_status_refreshes_repository(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            old_registry = ll.REGISTRY_PATH
            old_repo = ll.SPL_OPTIMIZATION_REPOSITORY_PATH
            old_root = ll.LEARNING_ROOT
            try:
                ll.LEARNING_ROOT = tmp_root
                ll.REGISTRY_PATH = tmp_root / "local_learning_registry.json"
                ll.SPL_OPTIMIZATION_REPOSITORY_PATH = tmp_root / "spl_optimization_repository.json"
                ll.save_learning_registry(
                    {
                        "version": 1,
                        "records": [
                            ll._candidate(
                                intent="apache_access_top_ips",
                                kind="spl_pattern_asset",
                                proposal={
                                    "query_template": "search index=linux sourcetype=access_combined | stats count by clientip",
                                    "required_fields": ["clientip"],
                                },
                                reason="Fresh asset",
                            )
                        ],
                    }
                )
                record_id = ll.load_learning_registry()["records"][0]["id"]
                self.assertTrue(ll.set_learning_record_status(record_id, "approved"))
                repo = ll._ensure_spl_optimization_repository()
                self.assertTrue(repo.exists())
                data = repo.read_text()
                self.assertIn("apache_access_top_ips", data)
                self.assertIn("active_assets", data)
            finally:
                ll.REGISTRY_PATH = old_registry
                ll.SPL_OPTIMIZATION_REPOSITORY_PATH = old_repo
                ll.LEARNING_ROOT = old_root


if __name__ == "__main__":
    unittest.main()
