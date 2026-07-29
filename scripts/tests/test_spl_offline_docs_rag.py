#!/usr/bin/env python3
"""Tests for Splunk Offline Docs RAG retrieval."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spl_offline_docs_rag import build_offline_docs_context, clear_offline_docs_cache, offline_docs_index_available
from spl_rag_context import build_spl_rag_context


class SplOfflineDocsRagTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_offline_docs_cache()

    def tearDown(self) -> None:
        clear_offline_docs_cache()

    def test_build_offline_docs_context_ranks_stats_topic(self) -> None:
        payload = {
            "built_at": "2026-07-28T00:00:00+00:00",
            "topic_count": 2,
            "topics": [
                {
                    "id": "a",
                    "title": "Installation overview",
                    "path": "splunk-enterprise/install/overview",
                    "text": "Install Splunk Enterprise on Linux.",
                },
                {
                    "id": "b",
                    "title": "stats",
                    "path": "splunk-enterprise/search/search-reference/stats",
                    "text": (
                        "The stats command calculates aggregate statistics over search results. "
                        "Example: search index=main | stats count by host user."
                    ),
                },
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            index_path = Path(tmp) / "index.json"
            index_path.write_text(json.dumps(payload), encoding="utf-8")
            ctx = build_offline_docs_context(
                "Show top hosts with failed login counts using stats",
                intent="failed_login_activity",
                index_path=index_path,
            )
        self.assertIn("[SPL_OFFLINE_DOCS]", ctx)
        self.assertIn("search-reference/stats", ctx)
        self.assertIn("stats command", ctx.lower())

    def test_build_spl_rag_context_includes_offline_docs_when_index_present(self) -> None:
        payload = {
            "built_at": "2026-07-28T00:00:00+00:00",
            "topic_count": 1,
            "topics": [
                {
                    "id": "b",
                    "title": "rex",
                    "path": "splunk-enterprise/search/search-reference/rex",
                    "text": "Use rex to extract fields with named groups. Example: search index=main | rex field=_raw \"(?<user>[^ ]+)\"",
                }
            ],
        }
        profile = {
            "timestamp_utc": "2026-07-28T00:00:00+00:00",
            "indexes": [{"index": "linux", "sourcetypes": ["auth.log"]}],
            "sourcetype_to_indexes": {"auth.log": ["linux"]},
            "sourcetype_field_inventory": {},
            "index_sourcetype_field_inventory": {},
        }
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            index_path = tmp_path / "offline_index.json"
            index_path.write_text(json.dumps(payload), encoding="utf-8")
            profile_path = tmp_path / "profile.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            with mock.patch("spl_rag_context.SKILLPACK_PATH", tmp_path / "missing.json"), mock.patch(
                "spl_rag_context.offline_docs_index_available", return_value=True
            ), mock.patch(
                "spl_rag_context.build_offline_docs_context",
                return_value="[SPL_OFFLINE_DOCS]\ntitle=rex\npath=search-reference/rex",
            ):
                ctx = build_spl_rag_context(
                    "Extract usernames from auth logs with rex",
                    intent="linux_auth_failures",
                    max_chars=4000,
                    profile_path=profile_path,
                )
        self.assertIn("[SPL_OFFLINE_DOCS]", ctx)

    def test_offline_docs_index_available_false_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(offline_docs_index_available(index_path=Path(tmp) / "missing.json"))


if __name__ == "__main__":
    unittest.main()
