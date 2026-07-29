#!/usr/bin/env python3
"""Tests for HEC setup REST form encoding."""

from __future__ import annotations

import sys
import unittest
import urllib.parse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from lab_data import setup_hec  # noqa: E402


class SetupHecTests(unittest.TestCase):
    def test_create_token_form_uses_single_default_index(self) -> None:
        captured: list[list[tuple[str, str]]] = []

        def fake_request(method: str, url: str, headers: dict, data: bytes | None = None):
            del method, url, headers
            assert data is not None
            parsed = urllib.parse.parse_qs(data.decode("utf-8"))
            captured.append({k: v[0] for k, v in parsed.items()})
            return {"entry": [{"content": {"token": "abc123"}}]}

        setup_hec._request = fake_request  # type: ignore[method-assign]
        token = setup_hec._create_hec_token(
            "https://127.0.0.1:8089",
            {},
            name="agtsmith-lab-generator",
            indexes=["botsv3", "linux"],
        )
        self.assertTrue(token)
        form = captured[0]
        self.assertEqual(form["index"], "botsv3")
        self.assertEqual(form["indexes"], "botsv3,linux")


if __name__ == "__main__":
    unittest.main()
