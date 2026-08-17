#!/usr/bin/env python3
"""Unit tests for embedding-based domain/sourcetype retrieval."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import domain_embedding_retrieval as der


def _unit_vec(active_dims: list[int], size: int = 4) -> list[float]:
    vec = [0.0] * size
    for dim in active_dims:
        vec[dim] = 1.0
    return vec


class BuildDomainDocumentsTests(unittest.TestCase):
    def test_builds_one_document_per_index_sourcetype_pair(self) -> None:
        profile = {
            "indexes": [
                {"index": "o365", "sourcetypes": ["o365:management:activity"]},
                {"index": "soc_linux", "sourcetypes": ["auth.log", "linux_secure"]},
            ],
            "sourcetype_semantics": {
                "o365:management:activity": {
                    "description": "Microsoft 365 management activity logs.",
                    "use_cases": ["identity_auth_activity", "o365_management_activity"],
                },
                "auth.log": {
                    "description": "Linux authentication log stream.",
                    "use_cases": ["linux_auth_failures"],
                },
            },
        }
        docs = der.build_domain_documents(profile)
        self.assertEqual(len(docs), 3)
        o365_doc = next(d for d in docs if d["sourcetype"] == "o365:management:activity")
        self.assertIn("microsoft 365", o365_doc["text"].lower())
        self.assertIn("o365_management_activity", o365_doc["text"])
        linux_secure_doc = next(d for d in docs if d["sourcetype"] == "linux_secure")
        self.assertEqual(linux_secure_doc["text"], "index soc_linux sourcetype linux_secure")

    def test_dedupes_repeated_index_sourcetype_pairs(self) -> None:
        profile = {
            "indexes": [
                {"index": "soc_linux", "sourcetypes": ["auth.log"]},
                {"index": "soc_linux", "sourcetypes": ["auth.log"]},
            ],
            "sourcetype_semantics": {},
        }
        docs = der.build_domain_documents(profile)
        self.assertEqual(len(docs), 1)

    def test_skips_rows_without_index_or_sourcetypes(self) -> None:
        profile = {"indexes": [{"index": "", "sourcetypes": ["x"]}, {"index": "y", "sourcetypes": []}]}
        self.assertEqual(der.build_domain_documents(profile), [])

    def test_empty_or_malformed_profile_returns_empty(self) -> None:
        self.assertEqual(der.build_domain_documents({}), [])
        self.assertEqual(der.build_domain_documents({"indexes": "not-a-list"}), [])


class RetrieveDomainScoresTests(unittest.TestCase):
    def _write_index(self, tmp_path: Path, documents: list[dict]) -> Path:
        idx_path = tmp_path / "domain_embedding_index.json"
        idx_path.write_text(json.dumps({"model": "nomic-embed-text", "documents": documents}), encoding="utf-8")
        return idx_path

    def test_ranks_by_cosine_similarity_and_scopes_key_by_index_and_sourcetype(self) -> None:
        documents = [
            {"index": "O365", "sourcetype": "o365:management:activity", "embedding": _unit_vec([0])},
            {"index": "soc_linux", "sourcetype": "auth.log", "embedding": _unit_vec([1])},
        ]
        with tempfile.TemporaryDirectory() as td:
            idx_path = self._write_index(Path(td), documents)
            with mock.patch("spl_embedding_rag.embed_query", return_value=_unit_vec([0])):
                der._load_domain_index_cached.cache_clear()
                scores = der.retrieve_domain_scores("unsuccessful sign-ins to office 365", path=idx_path)
        self.assertAlmostEqual(scores["o365::o365:management:activity"], 1.0, places=4)
        self.assertNotIn("soc_linux::auth.log", scores)

    def test_returns_empty_when_no_index_present(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "does_not_exist.json"
            der._load_domain_index_cached.cache_clear()
            self.assertEqual(der.retrieve_domain_scores("anything", path=missing), {})

    def test_returns_empty_when_disabled_via_env(self) -> None:
        documents = [{"index": "soc_linux", "sourcetype": "auth.log", "embedding": _unit_vec([0])}]
        with tempfile.TemporaryDirectory() as td:
            idx_path = self._write_index(Path(td), documents)
            der._load_domain_index_cached.cache_clear()
            with mock.patch.dict("os.environ", {"SPL_DOMAIN_EMBEDDING_RETRIEVAL_ENABLED": "0"}, clear=False):
                scores = der.retrieve_domain_scores("anything", path=idx_path)
        self.assertEqual(scores, {})

    def test_returns_empty_when_embedder_unreachable(self) -> None:
        documents = [{"index": "soc_linux", "sourcetype": "auth.log", "embedding": _unit_vec([0])}]
        with tempfile.TemporaryDirectory() as td:
            idx_path = self._write_index(Path(td), documents)
            der._load_domain_index_cached.cache_clear()
            with mock.patch("spl_embedding_rag.embed_query", side_effect=OSError("no ollama")):
                scores = der.retrieve_domain_scores("anything", path=idx_path)
        self.assertEqual(scores, {})

    def test_query_hint_influences_embedding_query_text(self) -> None:
        documents = [{"index": "soc_linux", "sourcetype": "auth.log", "embedding": _unit_vec([0])}]
        with tempfile.TemporaryDirectory() as td:
            idx_path = self._write_index(Path(td), documents)
            der._load_domain_index_cached.cache_clear()
            with mock.patch("spl_embedding_rag.embed_query", return_value=_unit_vec([0])) as mocked:
                der.retrieve_domain_scores("show activity", query_hint="platform=linux activity=failed_login", path=idx_path)
        called_text = mocked.call_args.args[0] if mocked.call_args.args else mocked.call_args.kwargs.get("text", "")
        self.assertIn("platform=linux", called_text)


class IndexLevelScoresTests(unittest.TestCase):
    def test_collapses_to_max_score_per_index(self) -> None:
        domain_scores = {
            "o365::o365:management:activity": 0.4,
            "o365::azure_ad_signin": 0.9,
            "soc_linux::auth.log": 0.3,
        }
        collapsed = der.index_level_scores(domain_scores)
        self.assertEqual(collapsed["o365"], 0.9)
        self.assertEqual(collapsed["soc_linux"], 0.3)

    def test_empty_input_returns_empty(self) -> None:
        self.assertEqual(der.index_level_scores({}), {})


if __name__ == "__main__":
    unittest.main()
