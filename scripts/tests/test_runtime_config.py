#!/usr/bin/env python3
"""Tests for shared runtime model defaults."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from runtime_config import (
    DEFAULT_MODEL_QUERY_PLANNER,
    DEFAULT_MODEL_QUERY_PLANNER_FALLBACK,
    DEFAULT_MODEL_QUERY_REPAIR,
    DEFAULT_MODEL_QUERY_WRITER,
    DEFAULT_MODEL_PEER_REVIEWER,
    DEFAULT_MODEL_PEER_REVIEWER_2,
    DEFAULT_MODEL_US_PEER,
    LEGACY_V14_MODEL_QUERY_PLANNER,
    LEGACY_V14_MODEL_QUERY_WRITER,
    _get_config_value,
    apply_model_family_assignments,
    expected_ollama_models,
    get_env_profile_auto_refresh_enabled,
    get_env_profile_refresh_interval_minutes,
    get_soc_ui_session_remember_timeout_min,
    get_soc_ui_session_timeout_min,
    is_local_ollama_host,
    model_stack_summary,
)


class RuntimeConfigDefaultsTests(unittest.TestCase):
    def test_v15_us_primary_stack(self) -> None:
        self.assertEqual(
            DEFAULT_MODEL_QUERY_PLANNER,
            "TechyShishy/ministral-3:3b-reasoning-2512-q4_K_M",
        )
        self.assertEqual(DEFAULT_MODEL_QUERY_PLANNER_FALLBACK, "ministral-3:3b")
        self.assertEqual(DEFAULT_MODEL_QUERY_WRITER, "granite4:3b")
        self.assertEqual(DEFAULT_MODEL_QUERY_REPAIR, "granite4:3b")
        self.assertEqual(DEFAULT_MODEL_US_PEER, "gemma3:4b")
        self.assertEqual(DEFAULT_MODEL_PEER_REVIEWER, "gemma3:4b")
        self.assertEqual(DEFAULT_MODEL_PEER_REVIEWER_2, "gemma3:4b")

    def test_legacy_v14_constants_preserved(self) -> None:
        self.assertIn("Qwen3-30B-A3B", LEGACY_V14_MODEL_QUERY_PLANNER)
        self.assertEqual(LEGACY_V14_MODEL_QUERY_WRITER, "deepseek-coder-v2:lite")

    def test_expected_ollama_models_use_v151_stack(self) -> None:
        models = expected_ollama_models()
        self.assertIn(DEFAULT_MODEL_QUERY_PLANNER, models)
        self.assertIn(DEFAULT_MODEL_QUERY_PLANNER_FALLBACK, models)
        self.assertIn(DEFAULT_MODEL_QUERY_WRITER, models)
        self.assertNotIn(LEGACY_V14_MODEL_QUERY_PLANNER, models)
        self.assertNotIn(LEGACY_V14_MODEL_QUERY_WRITER, models)

    def test_apply_model_family_assignments_mirrors_generation_and_peer(self) -> None:
        values = {
            "OLLAMA_MODEL_QUERY_WRITER": "granite4:3b",
            "OLLAMA_MODEL_PEER_REVIEWER": "gemma3:4b",
            "OLLAMA_MODEL_SECURITY_REVIEWER": "review-model",
        }
        expanded = apply_model_family_assignments(values)
        self.assertEqual(expanded["OLLAMA_MODEL_QUERY_REPAIR"], "granite4:3b")
        self.assertEqual(expanded["OLLAMA_MODEL_PEER_REVIEWER_2"], "gemma3:4b")
        self.assertEqual(expanded["OLLAMA_MODEL_EVIDENCE_REVIEWER"], "review-model")
        self.assertEqual(expanded["OLLAMA_MODEL_FINAL_SUMMARY"], "review-model")

    def test_model_stack_summary_counts_core_families(self) -> None:
        summary = model_stack_summary()
        self.assertGreaterEqual(int(summary["unique_tag_count"]), 3)
        self.assertEqual(int(summary["role_count"]), 11)
        self.assertIn(DEFAULT_MODEL_QUERY_PLANNER, summary["core_tags"])

    def test_session_timeout_defaults(self) -> None:
        self.assertEqual(get_soc_ui_session_timeout_min(), "60")
        self.assertEqual(get_soc_ui_session_remember_timeout_min(), "480")

    def test_env_profile_auto_refresh_defaults_on_every_sixty_minutes(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ENV_PROFILE_AUTO_REFRESH_ENABLED", None)
            os.environ.pop("ENV_PROFILE_REFRESH_INTERVAL_MINUTES", None)
            self.assertTrue(get_env_profile_auto_refresh_enabled())
            self.assertEqual(get_env_profile_refresh_interval_minutes(), 60)

    def test_env_profile_auto_refresh_can_be_disabled(self) -> None:
        with mock.patch.dict(os.environ, {"ENV_PROFILE_AUTO_REFRESH_ENABLED": "0"}):
            self.assertFalse(get_env_profile_auto_refresh_enabled())

    def test_env_profile_refresh_interval_honors_configured_value(self) -> None:
        with mock.patch.dict(os.environ, {"ENV_PROFILE_REFRESH_INTERVAL_MINUTES": "240"}):
            self.assertEqual(get_env_profile_refresh_interval_minutes(), 240)

    def test_env_profile_refresh_interval_falls_back_on_garbage(self) -> None:
        with mock.patch.dict(os.environ, {"ENV_PROFILE_REFRESH_INTERVAL_MINUTES": "not-a-number"}):
            self.assertEqual(get_env_profile_refresh_interval_minutes(), 60)
        with mock.patch.dict(os.environ, {"ENV_PROFILE_REFRESH_INTERVAL_MINUTES": "-5"}):
            self.assertEqual(get_env_profile_refresh_interval_minutes(), 60)


class RuntimeConfigSecretPreferenceTests(unittest.TestCase):
    def test_prefers_ui_env_when_shell_truncated_mcp_token(self) -> None:
        full_token = "enc:part1=part2=part3=tail"
        truncated = "enc:part1"
        with tempfile.TemporaryDirectory() as tmp:
            ui_env = Path(tmp) / "ui.env"
            ui_env.write_text(f"SPLUNK_LAB_BEARER_TOKEN={full_token}\n", encoding="utf-8")
            with mock.patch("runtime_config.UI_ENV_PATH", ui_env):
                with mock.patch.dict(os.environ, {"SPLUNK_LAB_BEARER_TOKEN": truncated}, clear=False):
                    self.assertEqual(_get_config_value("SPLUNK_LAB_BEARER_TOKEN"), full_token)

    def test_ui_env_always_preferred_for_mcp_token(self) -> None:
        full_token = "enc:part1=part2=part3=tail"
        stale_shell_token = "enc:stale=part2=part3=tail"
        with tempfile.TemporaryDirectory() as tmp:
            ui_env = Path(tmp) / "ui.env"
            ui_env.write_text(f"SPLUNK_LAB_BEARER_TOKEN={full_token}\n", encoding="utf-8")
            with mock.patch("runtime_config.UI_ENV_PATH", ui_env):
                with mock.patch.dict(os.environ, {"SPLUNK_LAB_BEARER_TOKEN": stale_shell_token}, clear=False):
                    self.assertEqual(_get_config_value("SPLUNK_LAB_BEARER_TOKEN"), full_token)

    def test_is_local_ollama_host(self) -> None:
        self.assertTrue(is_local_ollama_host("http://127.0.0.1:11434"))
        self.assertTrue(is_local_ollama_host("http://localhost:11434"))
        self.assertTrue(is_local_ollama_host("http://host.docker.internal:11434"))
        self.assertFalse(is_local_ollama_host("http://192.168.1.50:11434"))


if __name__ == "__main__":
    unittest.main()
