#!/usr/bin/env python3
"""Tests for SPL quality tracker registry and snapshots."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from spl_quality_tracker import (
    DOMAIN_PROGRAMS,
    _jobs_by_id,
    _phase_status,
    build_dashboard_snapshot,
    render_standalone_page,
    start_job,
)


class SplQualityTrackerTests(unittest.TestCase):
    def test_program_registry_has_core_domains(self) -> None:
        ids = {row["id"] for row in DOMAIN_PROGRAMS}
        self.assertTrue({"internal", "linux", "operational", "live_domain"}.issubset(ids))

    def test_jobs_are_unique(self) -> None:
        jobs = _jobs_by_id()
        self.assertGreaterEqual(len(jobs), 20)
        self.assertEqual(len(jobs), len({job["id"] for job in jobs.values()}))

    def test_phase_status_complete_when_both_slo_met(self) -> None:
        status = _phase_status(100.0, 96.0, 2)
        self.assertEqual(status["status"], "complete")
        self.assertTrue(status["template_ok"])
        self.assertTrue(status["multimodel_ok"])

    def test_dashboard_snapshot_shape(self) -> None:
        snap = build_dashboard_snapshot()
        self.assertIn("programs", snap)
        self.assertIn("summary", snap)
        self.assertGreaterEqual(len(snap["programs"]), 5)
        first = snap["programs"][0]
        self.assertIn("jobs", first)
        self.assertIn("phase", first)
        self.assertIn("scores", first)

    def test_start_unknown_job_fails(self) -> None:
        result = start_job("not-a-real-job")
        self.assertFalse(result.get("ok"))
        self.assertEqual(result.get("error"), "unknown_job")

    def test_standalone_page_is_self_contained(self) -> None:
        page = render_standalone_page()
        self.assertIn("SPL Quality Tracker", page)
        self.assertIn("/api/spl-quality/status", page)
        self.assertIn("make spl-quality-tracker", page)


if __name__ == "__main__":
    unittest.main()
