#!/usr/bin/env python3
"""API contract tests for saved query library routes."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))


def _load_web_ui_server():
    path = ROOT / "scripts" / "web_ui_server.py"
    spec = importlib.util.spec_from_file_location("web_ui_server_saved_queries_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SavedQueriesApiTests(unittest.TestCase):
    def test_handler_exposes_saved_queries_routes(self) -> None:
        wus = _load_web_ui_server()
        source = Path(wus.__file__).read_text(encoding="utf-8")
        self.assertIn('parsed.path == "/api/saved-queries"', source)
        self.assertIn("def _api_saved_queries_post", source)
        self.assertIn("def _api_saved_queries_get", source)


if __name__ == "__main__":
    unittest.main()
