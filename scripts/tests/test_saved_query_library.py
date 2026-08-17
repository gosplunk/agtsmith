#!/usr/bin/env python3
"""Tests for analyst saved query library."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import local_learning as ll
import saved_query_library as sql


class SavedQueryLibraryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        tmp_root = Path(self._tmpdir.name)
        ll.LEARNING_ROOT = tmp_root / "learning"
        ll.REGISTRY_PATH = ll.LEARNING_ROOT / "local_learning_registry.json"
        ll.SPL_OPTIMIZATION_REPOSITORY_PATH = ll.LEARNING_ROOT / "spl_optimization_repository.json"
        ll.ensure_learning_registry()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_save_analyst_query_creates_approved_record(self) -> None:
        saved = sql.save_analyst_query(
            question="show failed logins for alice",
            query="search index=wineventlog EventCode=4625 user=alice",
            intent="windows_auth_failures",
            saved_by="analyst1",
        )
        self.assertEqual(saved["status"], "approved")
        self.assertEqual(saved["source"], "analyst_saved")
        rows = sql.list_saved_queries()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], saved["id"])

    def test_save_analyst_query_upserts_same_stable_id(self) -> None:
        first = sql.save_analyst_query(
            question="show failed logins",
            query="search index=wineventlog EventCode=4625",
            intent="windows_auth_failures",
        )
        second = sql.save_analyst_query(
            question="show failed logins",
            query="search index=wineventlog EventCode=4625",
            intent="windows_auth_failures",
            result_excerpt="rows_returned=12",
        )
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(len(sql.list_saved_queries()), 1)
        self.assertIn("rows_returned=12", str(second.get("supporting_result_excerpt", "")))

    def test_save_analyst_query_different_spl_gets_new_record(self) -> None:
        first = sql.save_analyst_query(
            question="show failed logins",
            query="search index=wineventlog EventCode=4625",
            intent="windows_auth_failures",
        )
        second = sql.save_analyst_query(
            question="show failed logins",
            query="search index=wineventlog EventCode=4625 user=bob",
            intent="windows_auth_failures",
        )
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(len(sql.list_saved_queries()), 2)

    def test_exact_alias_match_shortcut(self) -> None:
        record = sql.save_analyst_query(
            question="show failed logins for alice",
            query="search index=wineventlog EventCode=4625 user=alice",
            intent="windows_auth_failures",
            aliases=["4625 failures for alice"],
        )
        with mock.patch("saved_query_library.saved_query_shortcut_enabled", return_value=True):
            shortcut = sql.retrieve_saved_query_shortcut("4625 failures for alice", "windows_auth_failures")
        self.assertEqual(shortcut["mode"], "auto")
        self.assertEqual(shortcut["record_id"], record["id"])

    def test_stale_saved_query(self) -> None:
        saved = sql.save_analyst_query(
            question="show dns lookups",
            query="search index=dns query_type=A",
            intent="dns_activity",
        )
        ok = sql.delete_or_stale_saved_query(saved["id"])
        self.assertTrue(ok)
        self.assertEqual(sql.list_saved_queries(status="approved"), [])

    def test_save_analyst_query_accepts_generating_rest_query(self) -> None:
        query = (
            "| rest splunk_server=local /services/data/indexes "
            "| table title disabled currentDBSizeMB totalEventCount splunk_server"
        )
        saved = sql.save_analyst_query(
            question="Which indexes do I have access to?",
            query=query,
            intent="inventory_indexes",
        )
        self.assertEqual(saved["source"], "analyst_saved")
        self.assertEqual(str(saved.get("supporting_spl", "")), query)

    def test_force_saved_query_id(self) -> None:
        saved = sql.save_analyst_query(
            question="show apache top ips",
            query="search index=apache sourcetype=access_combined_wcookie | top clientip",
            intent="apache_access_top_ips",
        )
        forced = sql.resolve_forced_saved_query(saved["id"])
        self.assertEqual(forced["mode"], "auto")
        self.assertIn("top clientip", forced["query"])

    def test_inventory_saved_query_does_not_shortcut_time_bound_data_question(self) -> None:
        query = (
            "| rest splunk_server=local /services/data/indexes "
            "| table title disabled currentDBSizeMB totalEventCount splunk_server"
        )
        sql.save_analyst_query(
            question="Which indexes do I have access to?",
            query=query,
            intent="inventory_indexes",
        )
        with mock.patch("saved_query_library.saved_query_shortcut_enabled", return_value=True):
            shortcut = sql.retrieve_saved_query_shortcut(
                "Which indexes have data in the last hour?",
                "inventory_indexes",
            )
        self.assertEqual(shortcut["mode"], "none")

    def test_inventory_saved_query_still_shortcuts_access_question(self) -> None:
        query = (
            "| rest splunk_server=local /services/data/indexes "
            "| table title disabled currentDBSizeMB totalEventCount splunk_server"
        )
        saved = sql.save_analyst_query(
            question="Which indexes do I have access to?",
            query=query,
            intent="inventory_indexes",
        )
        with mock.patch("saved_query_library.saved_query_shortcut_enabled", return_value=True):
            shortcut = sql.retrieve_saved_query_shortcut(
                "Which indexes do I have access to?",
                "inventory_indexes",
            )
        self.assertEqual(shortcut["mode"], "auto")
        self.assertEqual(shortcut["record_id"], saved["id"])

    def test_event_search_saved_query_still_shortcuts_different_time_phrase(self) -> None:
        sql.save_analyst_query(
            question="show failed logins in the last 24 hours",
            query="search index=wineventlog EventCode=4625",
            intent="windows_auth_failures",
        )
        with mock.patch("saved_query_library.saved_query_shortcut_enabled", return_value=True):
            shortcut = sql.retrieve_saved_query_shortcut(
                "show failed logins in the last 7 days",
                "windows_auth_failures",
            )
        self.assertIn(shortcut["mode"], {"auto", "suggest"})


if __name__ == "__main__":
    unittest.main()
