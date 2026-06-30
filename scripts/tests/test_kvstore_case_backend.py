#!/usr/bin/env python3
"""Unit tests for KV Store case backend mirror."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from core.case_store.kvstore_backend import CASE_MIRROR_ROOT, KvStoreCaseBackend


class KvStoreCaseBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self._orig = CASE_MIRROR_ROOT
        import core.case_store.kvstore_backend as mod

        mod.CASE_MIRROR_ROOT = Path(self._tmpdir.name)
        mod.CASES_FILE = mod.CASE_MIRROR_ROOT / "cases.json"
        mod.NODES_FILE = mod.CASE_MIRROR_ROOT / "case_nodes.json"
        self.mod = mod
        os.environ["AGTSMITH_KVSTORE_SYNC"] = "0"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()
        import core.case_store.kvstore_backend as mod

        mod.CASE_MIRROR_ROOT = self._orig
        mod.CASES_FILE = self._orig / "cases.json"
        mod.NODES_FILE = self._orig / "case_nodes.json"

    def test_upsert_and_list(self) -> None:
        store = self.mod.KvStoreCaseBackend()
        store.upsert_case(
            "case_1",
            {
                "case_id": "case_1",
                "root_question": "test",
                "status": "complete",
                "created_at": 1,
                "updated_at": 2,
            },
        )
        store.upsert_node(
            "node_1",
            {
                "node_id": "node_1",
                "case_id": "case_1",
                "parent_node_id": "",
                "node_type": "investigation",
                "question": "test",
                "title": "test",
                "intent": "failed_login_activity",
                "supported": True,
                "row_count": 3,
                "created_at": 1,
                "summary": "ok",
                "result_json": "{}",
                "graph_state_json": "{}",
            },
        )
        cases = store.list_cases()
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["node_count"], 1)
        self.assertEqual(cases[0]["latest_rows"], 3)


if __name__ == "__main__":
    unittest.main()
