#!/usr/bin/env python3
"""Tests for lab data layout resolution and manifest helpers."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from lab_data.config import (  # noqa: E402
    detect_layout_from_profile,
    format_verify_query,
    layout_index_names,
    read_verify_manifest,
    resolve_domain_target,
    resolve_layout_name,
    write_verify_manifest,
)


class LabDataConfigTests(unittest.TestCase):
    def test_detect_layout_existing_lab(self) -> None:
        profile = {"indexes": [{"index": "linux"}, {"index": "botsv3"}]}
        self.assertEqual(detect_layout_from_profile(profile), "existing_lab")

    def test_detect_layout_multi_index(self) -> None:
        profile = {"indexes": [{"index": "soc_linux"}, {"index": "soc_windows"}]}
        self.assertEqual(detect_layout_from_profile(profile), "multi_index_ideal")

    def test_detect_layout_minimal_ci(self) -> None:
        profile = {"indexes": [{"index": "agtsmith_test"}]}
        self.assertEqual(detect_layout_from_profile(profile), "minimal_ci")

    def test_resolve_domain_target_existing_lab(self) -> None:
        target = resolve_domain_target("existing_lab", "linux_auth")
        self.assertEqual(target["index"], "linux")
        self.assertEqual(target["sourcetype"], "auth.log")

    def test_resolve_domain_target_multi_index(self) -> None:
        target = resolve_domain_target("multi_index_ideal", "windows_auth")
        self.assertEqual(target["index"], "soc_windows")
        self.assertEqual(target["sourcetype"], "XmlWinEventLog:Security")

    def test_layout_index_names_includes_provision(self) -> None:
        names = layout_index_names("multi_index_ideal")
        self.assertIn("soc_linux", names)
        self.assertIn("soc_windows", names)

    def test_format_verify_query(self) -> None:
        query = format_verify_query(
            'search index={index} sourcetype="{sourcetype}" earliest=-24h',
            index="linux",
            sourcetype="auth.log",
        )
        self.assertIn('index=linux', query)
        self.assertIn('sourcetype="auth.log"', query)

    def test_resolve_layout_name_from_env(self) -> None:
        name = resolve_layout_name(None, ui_env={"LAB_DATA_LAYOUT": "minimal_ci"})
        self.assertEqual(name, "minimal_ci")

    def test_verify_manifest_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "verify.json"
            payload = {
                "all_ok": True,
                "benchmark_case_expectations": {
                    "linux_auth_failures_24h": {"min_rows": 1, "actual_rows": 50, "ok": True}
                },
            }
            write_verify_manifest(payload, path=path)
            loaded = read_verify_manifest(path=path)
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertTrue(loaded["all_ok"])
            self.assertIn("linux_auth_failures_24h", loaded["benchmark_case_expectations"])

    def test_resolve_layout_name_from_profile_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "profile.json"
            profile_path.write_text(
                json.dumps({"indexes": [{"index": "linux"}, {"index": "botsv3"}]}),
                encoding="utf-8",
            )
            name = resolve_layout_name(None, profile_path=profile_path, ui_env={})
            self.assertEqual(name, "existing_lab")


if __name__ == "__main__":
    unittest.main()
