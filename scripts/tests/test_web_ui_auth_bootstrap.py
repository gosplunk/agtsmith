#!/usr/bin/env python3
"""Regression tests for first-run auth bootstrap."""

from __future__ import annotations

import os
import json
import sys
import tempfile
import types
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _install_stub_modules() -> None:
    def _parse_env_file(path: Path) -> tuple[list[str], dict[str, str]]:
        target = Path(path)
        if not target.exists():
            return [], {}
        lines = target.read_text(encoding="utf-8").splitlines()
        values: dict[str, str] = {}
        for line in lines:
            raw = line.strip()
            if not raw or raw.startswith("#") or "=" not in raw:
                continue
            key, value = raw.split("=", 1)
            values[key.strip()] = value.strip()
        return lines, values

    def _write_env_file(updates: dict[str, str], path: Path) -> None:
        target = Path(path)
        _lines, values = _parse_env_file(target)
        values.update(updates)
        body = "\n".join(f"{key}={value}" for key, value in values.items()) + "\n"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")

    stubs: dict[str, types.ModuleType] = {}

    mod = types.ModuleType("langgraph_agentic_soc")
    mod.run_agentic_investigation = lambda *args, **kwargs: {}
    stubs["langgraph_agentic_soc"] = mod

    mod = types.ModuleType("langgraph_case_state")
    mod.bootstrap_graph_case_state = lambda *args, **kwargs: {}
    mod.snapshot_graph_case_state = lambda *args, **kwargs: {}
    stubs["langgraph_case_state"] = mod

    mod = types.ModuleType("langgraph_multi_model_soc")
    mod.describe_multi_model_graph = lambda *args, **kwargs: {}
    mod.run_multi_model_soc = lambda *args, **kwargs: {}
    stubs["langgraph_multi_model_soc"] = mod

    mod = types.ModuleType("local_learning")
    mod.ensure_learning_registry = lambda *args, **kwargs: None
    mod.generate_self_learn_candidates = lambda *args, **kwargs: {}
    mod.learning_registry_summary = lambda *args, **kwargs: {}
    mod.load_learning_progress = lambda *args, **kwargs: {}
    mod.set_learning_record_status = lambda *args, **kwargs: False
    stubs["local_learning"] = mod

    mod = types.ModuleType("minimal_question_to_answer")
    mod.map_question_to_template = lambda *args, **kwargs: None
    mod.run_splunk_get_indexes = lambda *args, **kwargs: {}
    mod.run_splunk_get_info = lambda *args, **kwargs: {}
    mod.run_splunk_get_metadata = lambda *args, **kwargs: {}
    mod.run_splunk_query_args = lambda *args, **kwargs: {}
    mod.summarize_with_ollama_model = lambda *args, **kwargs: ""
    mod.template_to_query_args = lambda *args, **kwargs: {}
    stubs["minimal_question_to_answer"] = mod

    mod = types.ModuleType("ollama_log_stream")
    mod.RemoteLogSourceRegistry = type("RemoteLogSourceRegistry", (), {})
    mod.StreamParams = type("StreamParams", (), {})
    mod.format_sse = lambda *args, **kwargs: b""
    mod.get_remote_health_url = lambda *args, **kwargs: ""
    mod.redact_secrets = lambda value: value
    mod.role_allowed = lambda role: role in {"admin", "ops"}
    stubs["ollama_log_stream"] = mod

    mod = types.ModuleType("environment_profile")
    mod.load_environment_profile = lambda *args, **kwargs: {}
    mod.suggest_domains_for_question = lambda *args, **kwargs: []
    stubs["environment_profile"] = mod

    mod = types.ModuleType("investigation_playbooks")
    mod.playbook_for_intent = lambda *args, **kwargs: {}
    mod.playbook_target_order = lambda *args, **kwargs: []
    mod.playbook_targets_for_intent = lambda *args, **kwargs: []
    stubs["investigation_playbooks"] = mod

    mod = types.ModuleType("runtime_config")
    mod.DEFAULT_MODEL_AGENTIC_CONTINUATION_REVIEWER = "stub"
    mod.DEFAULT_MODEL_EVIDENCE_REVIEWER = "stub"
    mod.DEFAULT_MODEL_FINAL_SUMMARY = "stub"
    mod.DEFAULT_MODEL_PEER_REVIEWER = "stub"
    mod.DEFAULT_MODEL_PEER_REVIEWER_2 = "stub"
    mod.DEFAULT_MODEL_QUERY_PLANNER = "stub"
    mod.DEFAULT_MODEL_QUERY_REPAIR = "stub"
    mod.DEFAULT_MODEL_QUERY_WRITER = "stub"
    mod.DEFAULT_MODEL_SECURITY_REVIEWER = "stub"
    mod.UI_ENV_PATH = Path("/tmp/agtsmith-ui.env")
    mod.display_path = lambda path: str(path)
    mod.get_edge_llm_enabled = lambda: False
    mod.get_edge_llm_host = lambda: ""
    mod.get_edge_llm_model = lambda: ""
    mod.get_edge_llm_role = lambda: ""
    mod.get_edge_llm_timeout_sec = lambda: 30
    mod.get_ollama_host = lambda: ""
    mod.get_splunk_base_url = lambda: ""
    mod.get_splunk_mcp_url = lambda: ""
    mod.get_runtime_secret = lambda name, default="": default
    mod.parse_env_file = _parse_env_file
    mod.write_env_file = _write_env_file
    stubs["runtime_config"] = mod

    mod = types.ModuleType("case_store")
    mod.build_case_timeline = lambda *args, **kwargs: []
    mod.case_store_backend = lambda *args, **kwargs: "memory"
    mod.load_case = lambda *args, **kwargs: {}
    mod.load_case_node = lambda *args, **kwargs: {}
    mod.list_recent_cases = lambda *args, **kwargs: []
    mod.persist_case_result = lambda *args, **kwargs: {}
    stubs["case_store"] = mod

    for name, module in stubs.items():
        sys.modules[name] = module


_install_stub_modules()

import web_ui_server as wus


class WebUiAuthBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self._old_ui_env_path = wus.UI_ENV_PATH
        self._tracked_env = {
            name: os.environ.get(name)
            for name in (
                "SOC_UI_AUTH_ENABLED",
                "SOC_UI_AUTH_INITIALIZED",
                "SOC_UI_AUTH_USERS_JSON",
                "SOC_UI_AUTH_USERNAME",
                "SOC_UI_AUTH_PASSWORD",
                "SOC_UI_AUTH_ROLE",
            )
        }
        self._tmpdir = tempfile.TemporaryDirectory()
        wus.UI_ENV_PATH = Path(self._tmpdir.name) / "ui.env"

    def tearDown(self) -> None:
        wus.UI_ENV_PATH = self._old_ui_env_path
        for name, value in self._tracked_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        self._tmpdir.cleanup()

    def test_first_run_requires_setup_when_uninitialized_placeholder_env_exists(self) -> None:
        os.environ["SOC_UI_AUTH_INITIALIZED"] = "0"
        os.environ["SOC_UI_AUTH_USERNAME"] = "analyst"
        os.environ["SOC_UI_AUTH_PASSWORD"] = "changeme123!"
        os.environ["SOC_UI_AUTH_ROLE"] = "ops"
        os.environ.pop("SOC_UI_AUTH_USERS_JSON", None)

        self.assertTrue(wus._first_run_setup_required())
        self.assertEqual(wus._load_auth_users(), {})

    def test_initialized_single_user_env_is_loaded_without_defaults(self) -> None:
        os.environ["SOC_UI_AUTH_INITIALIZED"] = "1"
        os.environ["SOC_UI_AUTH_USERNAME"] = "opsadmin"
        os.environ["SOC_UI_AUTH_PASSWORD"] = "pbkdf2_sha256$example"
        os.environ["SOC_UI_AUTH_ROLE"] = "admin"
        os.environ.pop("SOC_UI_AUTH_USERS_JSON", None)

        self.assertFalse(wus._first_run_setup_required())
        self.assertEqual(
            wus._load_auth_users(),
            {"opsadmin": {"password": "pbkdf2_sha256$example", "role": "admin"}},
        )

    def test_uninitialized_blank_config_has_no_synthetic_default_user(self) -> None:
        os.environ["SOC_UI_AUTH_INITIALIZED"] = "0"
        os.environ.pop("SOC_UI_AUTH_USERS_JSON", None)
        os.environ.pop("SOC_UI_AUTH_USERNAME", None)
        os.environ.pop("SOC_UI_AUTH_PASSWORD", None)
        os.environ.pop("SOC_UI_AUTH_ROLE", None)

        self.assertTrue(wus._first_run_setup_required())
        self.assertEqual(wus._load_auth_users(), {})


if __name__ == "__main__":
    unittest.main()
