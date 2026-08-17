#!/usr/bin/env python3
"""Tests for SPL embedding index learning-record ingestion."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import build_spl_embedding_index as bei
import saved_query_library as sql


class BuildSplEmbeddingIndexTests(unittest.TestCase):
    def test_learning_record_text_fields_from_supporting_fields(self) -> None:
        row = {
            "supporting_question": "show failed logins for user alice",
            "supporting_spl": "",
            "proposal": {"query_template": "search index=wineventlog EventCode=4625 user=alice"},
        }
        question, query = sql.learning_record_text_fields(row)
        self.assertEqual(question, "show failed logins for user alice")
        self.assertTrue(query.startswith("search index=wineventlog"))

    def test_learning_record_to_index_doc_uses_saved_query_kind(self) -> None:
        row = {
            "id": "abc123",
            "source": "analyst_saved",
            "intent": "windows_auth_failures",
            "supporting_question": "failed logins",
            "proposal": {"query_template": "search index=wineventlog EventCode=4625"},
        }
        doc = sql.learning_record_to_index_doc(row)
        self.assertIsNotNone(doc)
        assert doc is not None
        self.assertEqual(doc["kind"], "saved_query")
        self.assertEqual(doc["record_id"], "abc123")

    def test_build_documents_skips_empty_learning_rows(self) -> None:
        with mock.patch("build_spl_embedding_index.approved_learning_records", return_value=[{"question": "", "query": ""}]):
            docs = bei.build_documents()
        learning_docs = [doc for doc in docs if str(doc.get("kind", "")).startswith("learning") or doc.get("kind") == "saved_query"]
        self.assertEqual(learning_docs, [])


if __name__ == "__main__":
    unittest.main()
