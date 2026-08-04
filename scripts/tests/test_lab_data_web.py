#!/usr/bin/env python3
"""Tests for the loopback Splunk lab-data web studio."""

from __future__ import annotations

import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from lab_data_web import (  # noqa: E402
    PAGE_HTML,
    LabDataWebServer,
    build_catalog,
    validate_generate_request,
)


class LabDataWebCatalogTests(unittest.TestCase):
    def test_expanded_catalog_lists_all_mappings_and_rendered_samples(self) -> None:
        catalog = build_catalog("expanded_lab")
        self.assertEqual(catalog["layout"], "expanded_lab")
        self.assertGreaterEqual(len(catalog["sourcetypes"]), 9)
        self.assertGreaterEqual(len(catalog["event_sets"]), 26)
        self.assertEqual(
            {row["sourcetype"] for row in catalog["sourcetypes"]},
            {row["sourcetype"] for row in catalog["event_sets"]},
            "every listed sourcetype must have at least one generated sample",
        )
        for row in catalog["event_sets"]:
            with self.subTest(event_set=row["id"]):
                self.assertTrue(row["sample"])
                self.assertNotRegex(row["sample"], r"\{[A-Za-z_][A-Za-z0-9_]*\}")

    def test_windows_samples_use_native_xml(self) -> None:
        catalog = build_catalog("expanded_lab")
        windows = next(row for row in catalog["event_sets"] if row["id"] == "win_5379")
        self.assertEqual(windows["format"], "xml")
        self.assertEqual(windows["sourcetype"], "XmlWinEventLog")
        self.assertEqual(windows["source"], "XmlWinEventLog:Security")
        self.assertTrue(windows["sample"].startswith("<Event "))

    def test_syslog_sample_uses_rfc5424_shape(self) -> None:
        catalog = build_catalog("expanded_lab")
        syslog = next(row for row in catalog["event_sets"] if row["id"] == "linux_syslog")
        self.assertEqual(syslog["sourcetype"], "syslog")
        self.assertEqual(syslog["source"], "/var/log/messages")
        self.assertRegex(
            syslog["sample"],
            r"^<\d+>1 \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z linux-core-\d+ ",
        )

    def test_validates_only_allowlisted_bounded_generation(self) -> None:
        request = validate_generate_request(
            {
                "layout": "expanded_lab",
                "event_sets": ["linux_failed_ssh", "win_4625"],
                "count": 25,
                "hours": 12,
            }
        )
        self.assertEqual(request["count"], 25)
        self.assertEqual(len(request["event_sets"]), 2)
        self.assertEqual(request["time_range"]["mode"], "relative")
        self.assertEqual(request["hours"], 12)

        for payload, reason in (
            (
                {"layout": "expanded_lab", "event_sets": ["not_real"], "count": 1, "hours": 1},
                "unknown_event_set",
            ),
            (
                {"layout": "expanded_lab", "event_sets": ["win_4625"], "count": 501, "hours": 1},
                "count_out_of_range",
            ),
            (
                {"layout": "expanded_lab", "event_sets": ["win_4625"], "count": 1, "hours": 3000},
                "hours_out_of_range",
            ),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ValueError, reason):
                    validate_generate_request(payload)

    def test_validates_presets_and_explicit_custom_ranges(self) -> None:
        base = {
            "layout": "expanded_lab",
            "event_sets": ["linux_failed_ssh"],
            "count": 10,
        }
        preset = validate_generate_request({**base, "time_range": "last_7_days"})
        self.assertEqual(preset["hours"], 168)
        self.assertIsNone(preset["start_time"])
        self.assertEqual(preset["time_range"]["label"], "Last 7 days")

        custom = validate_generate_request(
            {
                **base,
                "time_range": "custom",
                "start_time": 1_700_000_000,
                "end_time": 1_700_021_600,
            },
            now_epoch=1_700_021_600,
        )
        self.assertEqual(custom["hours"], 6)
        self.assertEqual(custom["start_time"], 1_700_000_000)
        self.assertEqual(custom["end_time"], 1_700_021_600)
        self.assertEqual(custom["time_range"]["mode"], "explicit")

    def test_rejects_invalid_custom_ranges_and_total_event_overflow(self) -> None:
        base = {
            "layout": "expanded_lab",
            "event_sets": ["linux_failed_ssh"],
            "count": 1,
            "time_range": "custom",
        }
        now = 1_700_000_000
        for overrides, reason in (
            ({"start_time": float("nan"), "end_time": now}, "invalid_start_time"),
            ({"start_time": now, "end_time": now}, "time_range_start_must_precede_end"),
            (
                {"start_time": now - (91 * 24 * 3600), "end_time": now},
                "time_range_exceeds_max_days",
            ),
            (
                {"start_time": now, "end_time": now + 301},
                "time_range_end_too_far_in_future",
            ),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ValueError, reason):
                    validate_generate_request({**base, **overrides}, now_epoch=now)

        all_sets = [row["id"] for row in build_catalog("expanded_lab")["event_sets"]]
        with self.assertRaisesRegex(ValueError, "event_limit_exceeded"):
            validate_generate_request(
                {
                    "layout": "expanded_lab",
                    "event_sets": all_sets,
                    "count": 500,
                    "time_range": "last_hour",
                }
            )

    def test_page_has_modern_controls_without_external_assets_or_html_sinks(self) -> None:
        for marker in (
            "Splunk Lab Data Studio",
            "Available sourcetypes",
            "View sample event",
            "Generate and send to Splunk",
            "Last 7 days",
            'type="datetime-local"',
            "Synthetic timestamps:",
            "__CSRF_TOKEN__",
            "__CSP_NONCE__",
        ):
            self.assertIn(marker, PAGE_HTML)
        self.assertNotIn("innerHTML", PAGE_HTML)
        self.assertNotIn("<script src=", PAGE_HTML)
        self.assertNotIn("<link ", PAGE_HTML)


class LabDataWebHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = LabDataWebServer(("127.0.0.1", 0))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _json(self, path: str) -> dict:
        with urllib.request.urlopen(f"{self.base_url}{path}", timeout=5) as response:
            return json.loads(response.read())

    def test_health_and_catalog_endpoints(self) -> None:
        health = self._json("/api/health")
        self.assertTrue(health["ok"])
        self.assertTrue(health["layouts"])
        catalog = self._json("/api/catalog?layout=expanded_lab")
        self.assertTrue(catalog["ok"])
        self.assertGreaterEqual(len(catalog["event_sets"]), 20)

    def test_generation_requires_csrf_token(self) -> None:
        body = json.dumps(
            {
                "layout": "expanded_lab",
                "event_sets": ["linux_failed_ssh"],
                "count": 1,
                "time_range": "last_hour",
            }
        ).encode()
        request = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(raised.exception.code, 403)

    def test_generation_endpoint_passes_validated_selection_to_generator(self) -> None:
        body = json.dumps(
            {
                "layout": "expanded_lab",
                "event_sets": ["linux_failed_ssh"],
                "count": 1,
                "time_range": "last_hour",
            }
        ).encode()
        request = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Origin": self.base_url,
                "X-CSRF-Token": self.server.csrf_token,
            },
        )
        report = {
            "layout": "expanded_lab",
            "event_count": 1,
            "sent": 1,
            "transport": "hec",
            "hours": 1,
            "time_range": {
                "mode": "relative",
                "start_epoch": 1_700_000_000,
                "end_epoch": 1_700_003_600,
                "span_hours": 1,
            },
            "errors": [],
        }
        with mock.patch("lab_data_web.generate", return_value=report) as generator:
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["sent"], 1)
        self.assertEqual(payload["time_range"]["selection"], "last_hour")
        self.assertEqual(payload["time_range"]["label"], "Last hour")
        generator.assert_called_once_with(
            layout="expanded_lab",
            count=1,
            hours=1.0,
            event_sets=["linux_failed_ssh"],
            dry_run=False,
        )

    def test_generation_endpoint_passes_custom_bounds_to_generator(self) -> None:
        body = json.dumps(
            {
                "layout": "expanded_lab",
                "event_sets": ["linux_failed_ssh"],
                "count": 2,
                "time_range": "custom",
                "start_time": 1_700_000_000,
                "end_time": 1_700_003_600,
            }
        ).encode()
        request = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Origin": self.base_url,
                "X-CSRF-Token": self.server.csrf_token,
            },
        )
        report = {
            "layout": "expanded_lab",
            "event_count": 2,
            "sent": 2,
            "transport": "hec",
            "hours": 1,
            "time_range": {
                "mode": "explicit",
                "start_epoch": 1_700_000_000,
                "end_epoch": 1_700_003_600,
                "span_hours": 1,
            },
            "errors": [],
        }
        with (
            mock.patch("lab_data_web.time.time", return_value=1_700_003_600),
            mock.patch("lab_data_web.generate", return_value=report) as generator,
        ):
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["time_range"]["selection"], "custom")
        generator.assert_called_once_with(
            layout="expanded_lab",
            count=2,
            hours=1.0,
            event_sets=["linux_failed_ssh"],
            dry_run=False,
            start_time=1_700_000_000.0,
            end_time=1_700_003_600.0,
        )


if __name__ == "__main__":
    unittest.main()
