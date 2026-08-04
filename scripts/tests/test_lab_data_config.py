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
    load_event_catalog,
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

    def test_detect_layout_cloud_only(self) -> None:
        profile = {"indexes": [{"index": "aws_prod"}, {"index": "o365_prod"}]}
        self.assertEqual(detect_layout_from_profile(profile), "cloud_only")

    def test_detect_layout_expanded_lab(self) -> None:
        profile = {
            "indexes": [
                {"index": "linux"},
                {"index": "botsv3"},
                {"index": "soc_linux"},
                {"index": "soc_windows"},
                {"index": "aws_prod"},
                {"index": "o365_prod"},
            ]
        }
        self.assertEqual(detect_layout_from_profile(profile), "expanded_lab")

    def test_resolve_domain_target_expanded_cloud(self) -> None:
        target = resolve_domain_target("expanded_lab", "aws_cloudtrail")
        self.assertEqual(target["index"], "aws_prod")
        self.assertEqual(target["sourcetype"], "aws:cloudtrail")

    def test_layout_index_names_expanded_lab(self) -> None:
        names = layout_index_names("expanded_lab")
        self.assertIn("aws_prod", names)
        self.assertIn("soc_linux", names)
        self.assertIn("agtsmith_test", names)

    def test_resolve_domain_target_existing_lab(self) -> None:
        target = resolve_domain_target("existing_lab", "linux_auth")
        self.assertEqual(target["index"], "linux")
        self.assertEqual(target["sourcetype"], "auth.log")

    def test_resolve_domain_target_multi_index(self) -> None:
        target = resolve_domain_target("multi_index_ideal", "windows_auth")
        self.assertEqual(target["index"], "soc_windows")
        self.assertEqual(target["sourcetype"], "XmlWinEventLog")

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

    def test_all_event_verify_queries_format_without_placeholder_collisions(self) -> None:
        catalog = load_event_catalog()
        for name, event_set in catalog["event_sets"].items():
            with self.subTest(event_set=name):
                target = resolve_domain_target(
                    "expanded_lab",
                    event_set["domain"],
                )
                query = format_verify_query(
                    event_set["verify_query"],
                    index=target["index"],
                    sourcetype=target["sourcetype"],
                )
                self.assertNotIn("{index}", query)
                self.assertNotIn("{sourcetype}", query)

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

    def test_aggregate_benchmark_expectations_merges_shared_cases(self) -> None:
        from lab_data_verify import _aggregate_benchmark_expectations

        rows = [
            {
                "event_set": "linux_failed_ssh_cross",
                "benchmark_case": "failed_login_cross_platform_24h",
                "min_expected_rows": 1,
                "row_count": 1,
                "ok": True,
            },
            {
                "event_set": "win_4625_cross",
                "benchmark_case": "failed_login_cross_platform_24h",
                "min_expected_rows": 1,
                "row_count": 1,
                "ok": True,
            },
        ]
        merged = _aggregate_benchmark_expectations(rows)
        entry = merged["failed_login_cross_platform_24h"]
        self.assertTrue(entry["ok"])
        self.assertEqual(entry["actual_rows"], 1)
        self.assertEqual(len(entry["event_sets"]), 2)

    def test_verify_row_count_reads_stats_value(self) -> None:
        from lab_data_verify import _row_count

        self.assertEqual(_row_count({"results": [{"count": "0"}]}), 0)
        self.assertEqual(_row_count({"results": [{"count": "80"}]}), 80)

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
