#!/usr/bin/env python3
"""Regression tests for MCP demo mode behavior."""

from __future__ import annotations

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
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(f"{key}={value}" for key, value in values.items()) + "\n", encoding="utf-8")

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
    mod.run_multi_model_soc = lambda question, *args, **kwargs: {
        "result": {
            "summary": f"Analyst answer for {question}",
            "intent": "failed_login_activity",
            "supported": True,
            "selected_tool": "splunk_run_query",
            "query_args": {
                "query": f"search index=linux /* {question} */",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 20,
            },
            "selected_spl_details": [
                {
                    "tool": "splunk_run_query",
                    "query": f"search index=linux /* {question} */",
                    "rows_returned": 1,
                    "total_rows": 1,
                    "writer_model": "stub_query_writer",
                    "execution_ms": 12,
                }
            ],
            "rows_returned": 1,
            "total_rows": 1,
            "evidence": {
                "query_or_args": {
                    "query": f"search index=linux /* {question} */",
                    "earliest_time": "-24h",
                    "latest_time": "now",
                    "row_limit": 20,
                },
                "top_entities": [{"index": "linux", "host": "demo-host"}],
            },
            "search_strategy_summary": "stub assisted pipeline",
            "rag_enabled": True,
            "rag_max_chars": 4096,
        },
        "meta": {"pipeline": "agentic_loop"},
    }
    stubs["langgraph_multi_model_soc"] = mod

    mod = types.ModuleType("local_learning")
    mod.ensure_learning_registry = lambda *args, **kwargs: None
    mod.generate_self_learn_candidates = lambda *args, **kwargs: {}
    mod.learning_registry_summary = lambda *args, **kwargs: {}
    mod.load_learning_progress = lambda *args, **kwargs: {}
    mod.set_learning_record_status = lambda *args, **kwargs: False
    stubs["local_learning"] = mod

    mod = types.ModuleType("minimal_question_to_answer")
    mod.map_question_to_template = lambda *args, **kwargs: types.SimpleNamespace(
        intent="failed_login_activity",
        summary_hint="demo",
        query="search index=linux | head 20",
        row_limit=20,
        earliest_time="-24h",
        latest_time="now",
    )
    mod.run_splunk_get_indexes = lambda *args, **kwargs: {"structured": {"indexes": [{"title": "botsv3"}]}}
    mod.run_splunk_get_info = lambda *args, **kwargs: {"structured": {"items": [{"version": "9.0"}]}}
    mod.run_splunk_get_metadata = lambda *args, **kwargs: {"structured": {"metadata": [{"source": "/var/log/auth.log"}]}}
    mod.run_splunk_query_args = lambda query_args, **kwargs: {
        "structured": {"results": [{"index": "botsv3", "host": "demo-host"}], "total_rows": 1}
    }
    mod.summarize_with_ollama_model = lambda *args, **kwargs: ""
    mod.template_to_query_args = lambda template, question="", **kwargs: {
        "query": f"search index=botsv3 /* {question} */",
        "earliest_time": "-24h",
        "latest_time": "now",
        "row_limit": 20,
    }
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
    mod.load_environment_profile = lambda *args, **kwargs: {"indexes": [{"index": "botsv3", "sourcetypes": ["XmlWinEventLog"]}]}
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

    mod = types.ModuleType("langgraph_minimal_flow")
    mod.determine_splunk_tool = lambda question, intent: ("splunk_run_query", "demo", {}, "deterministic")
    stubs["langgraph_minimal_flow"] = mod

    for name, module in stubs.items():
        sys.modules[name] = module


_install_stub_modules()

import web_ui_server as wus


class WebUiDemoModeTests(unittest.TestCase):
    def test_clean_analyst_summary_text_strips_reasoning_trace(self) -> None:
        raw = (
            "The task is to summarize the provided query results in plain English.\n"
            "<think>hidden chain of thought</think>\n"
            "Here's a concise summary of the query results in plain English:\n"
            "- What was queried: failed logins"
        )
        cleaned = wus._clean_analyst_summary_text(raw)
        self.assertNotIn("The task is to summarize", cleaned)
        self.assertNotIn("<think>", cleaned)
        self.assertTrue(cleaned.startswith("Here's a concise summary"))

    def test_demo_mode_question_adds_botsv3_and_all_time(self) -> None:
        updated = wus._demo_mode_question("Show windows sysmon dns queries")
        self.assertIn("BOTSv3", updated)
        self.assertIn("all time", updated.lower())

    def test_demo_mode_payload_reports_demo_when_botsv3_available(self) -> None:
        original = wus._botsv3_index_available
        try:
            wus._botsv3_index_available = lambda *args, **kwargs: True
            payload = wus._mcp_chat_mode_payload("demo")
            self.assertTrue(payload["demo_effective"])
            self.assertEqual(payload["effective_mode"], "demo")
        finally:
            wus._botsv3_index_available = original

    def test_run_mcp_chat_query_defaults_to_assisted_pipeline(self) -> None:
        payload = wus._run_mcp_chat_query("Show failed login activity")
        result = payload["result"]
        self.assertEqual(result["pipeline"]["effective_pipeline"], "assisted")
        self.assertEqual(result["selected_tool"], "splunk_run_query")

    def test_run_mcp_chat_query_demo_mode_rewrites_searches_for_assisted_pipeline(self) -> None:
        original_bots = wus._botsv3_index_available
        original_run_multi_model_soc = wus.run_multi_model_soc
        try:
            captured: dict[str, str] = {}

            def fake_run_multi_model_soc(question, *args, **kwargs):
                captured["question"] = question
                return {
                    "result": {
                        "summary": "Assisted MCP completed",
                        "intent": "failed_login_activity",
                        "supported": True,
                        "selected_tool": "splunk_run_query",
                        "query_args": {
                            "query": f"search index=botsv3 /* {question} */",
                            "earliest_time": "-24h",
                            "latest_time": "now",
                            "row_limit": 20,
                        },
                        "selected_spl_details": [
                            {
                                "tool": "splunk_run_query",
                                "query": f"search index=botsv3 /* {question} */",
                                "rows_returned": 1,
                                "total_rows": 1,
                                "writer_model": "stub_query_writer",
                            }
                        ],
                        "rows_returned": 1,
                        "total_rows": 1,
                        "evidence": {
                            "query_or_args": {
                                "query": f"search index=botsv3 /* {question} */",
                                "earliest_time": "-24h",
                                "latest_time": "now",
                                "row_limit": 20,
                            },
                            "top_entities": [{"index": "botsv3", "host": "demo-host"}],
                        },
                    },
                    "meta": {"pipeline": "agentic_loop"},
                }

            wus._botsv3_index_available = lambda *args, **kwargs: True
            wus.run_multi_model_soc = fake_run_multi_model_soc
            payload = wus._run_mcp_chat_query("Show windows sysmon dns queries", mode="demo")
            result = payload["result"]
            self.assertEqual(result["selected_tool"], "splunk_run_query")
            self.assertEqual(result["pipeline"]["effective_pipeline"], "assisted")
            self.assertEqual(result["mode"]["effective_mode"], "demo")
            self.assertIn("botsv3", result["effective_question"].lower())
            self.assertIn("all time", result["effective_question"].lower())
            self.assertEqual(captured["question"], result["effective_question"])
            self.assertIn("[Demo Mode]", result["summary"])
        finally:
            wus._botsv3_index_available = original_bots
            wus.run_multi_model_soc = original_run_multi_model_soc

    def test_run_mcp_chat_query_deterministic_pipeline_remains_available(self) -> None:
        original = wus._botsv3_index_available
        try:
            wus._botsv3_index_available = lambda *args, **kwargs: True
            payload = wus._run_mcp_chat_query(
                "Show windows sysmon dns queries",
                mode="demo",
                pipeline="deterministic",
            )
            result = payload["result"]
            self.assertEqual(result["pipeline"]["effective_pipeline"], "deterministic")
            self.assertEqual(result["selected_tool"], "splunk_run_query")
            self.assertEqual(result["query_args"]["earliest_time"], "0")
            self.assertEqual(result["mode"]["effective_mode"], "demo")
            self.assertIn("[Demo Mode]", result["summary"])
        finally:
            wus._botsv3_index_available = original

    def test_run_mcp_chat_query_demo_mode_does_not_rewrite_inventory_tools(self) -> None:
        langgraph_minimal_flow = sys.modules["langgraph_minimal_flow"]
        original_run_multi_model_soc = wus.run_multi_model_soc
        original_determine = langgraph_minimal_flow.determine_splunk_tool
        original = wus._botsv3_index_available
        try:
            captured: dict[str, str] = {}

            def fake_run_multi_model_soc(question, *args, **kwargs):
                captured["question"] = question
                return {
                    "result": {
                        "summary": "Inventory answer",
                        "intent": "top_indexes",
                        "supported": True,
                        "selected_tool": "splunk_get_indexes",
                        "query_args": {},
                        "selected_spl_details": [
                            {
                                "tool": "splunk_get_indexes",
                                "query": "",
                                "rows_returned": 1,
                                "total_rows": 1,
                                "writer_model": "stub_query_writer",
                            }
                        ],
                        "rows_returned": 1,
                        "total_rows": 1,
                        "evidence": {
                            "query_or_args": {},
                            "top_entities": [{"title": "main"}],
                        },
                    },
                    "meta": {"pipeline": "agentic_loop"},
                }

            wus._botsv3_index_available = lambda *args, **kwargs: True
            langgraph_minimal_flow.determine_splunk_tool = lambda question, intent: ("splunk_get_indexes", "inventory", {}, "deterministic")
            wus.run_multi_model_soc = fake_run_multi_model_soc
            payload = wus._run_mcp_chat_query("What indexes can I access?", mode="demo")
            result = payload["result"]
            self.assertEqual(result["selected_tool"], "splunk_get_indexes")
            self.assertEqual(result["effective_question"], "What indexes can I access?")
            self.assertEqual(captured["question"], "What indexes can I access?")
            self.assertEqual(result["pipeline"]["effective_pipeline"], "assisted")
            self.assertEqual(result["mode"]["effective_mode"], "demo")
        finally:
            wus.run_multi_model_soc = original_run_multi_model_soc
            langgraph_minimal_flow.determine_splunk_tool = original_determine
            wus._botsv3_index_available = original


if __name__ == "__main__":
    unittest.main()
