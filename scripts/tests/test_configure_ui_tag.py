#!/usr/bin/env python3
"""Tests for configure_ui_tag.py manifest helpers."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import configure_ui_tag as cut


class ConfigureUiTagTests(unittest.TestCase):
    def test_validate_manifest_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(
                json.dumps(
                    {
                        "configure_ui_tag": "configure-ui-p0",
                        "app_version": "1.5.1",
                        "phase": 0,
                        "captured_at": "2026-07-27T00:00:00+00:00",
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(cut.cmd_validate(type("Args", (), {"path": path})()), 0)

    def test_invalid_tag_rejected(self) -> None:
        with self.assertRaises(ValueError):
            cut._validate_tag("bad tag")


if __name__ == "__main__":
    unittest.main()
