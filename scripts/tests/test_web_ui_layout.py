#!/usr/bin/env python3
"""Regression tests for analyst-facing UI layout structure."""

from __future__ import annotations

import sys
import types
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _install_stub_modules() -> None:
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
    mod.map_question_to_template = lambda *args, **kwargs: types.SimpleNamespace(
        intent="failed_login_activity",
        summary_hint="layout",
        query="search index=test | head 20",
        row_limit=20,
        earliest_time="-24h",
        latest_time="now",
    )
    mod.run_splunk_get_indexes = lambda *args, **kwargs: {}
    mod.run_splunk_get_info = lambda *args, **kwargs: {}
    mod.run_splunk_get_metadata = lambda *args, **kwargs: {}
    mod.run_splunk_query_args = lambda *args, **kwargs: {"structured": {"results": [], "total_rows": 0}}
    mod.summarize_with_ollama_model = lambda *args, **kwargs: ""
    mod.template_to_query_args = lambda *args, **kwargs: {"query": "search index=test", "earliest_time": "-24h", "latest_time": "now"}
    stubs["minimal_question_to_answer"] = mod

    mod = types.ModuleType("ollama_log_stream")
    mod.RemoteLogSourceRegistry = type("RemoteLogSourceRegistry", (), {})
    mod.StreamParams = type("StreamParams", (), {})
    mod.format_sse = lambda *args, **kwargs: b""
    mod.get_remote_health_url = lambda *args, **kwargs: ""
    mod.redact_secrets = lambda value: value
    mod.role_allowed = lambda role: True
    stubs["ollama_log_stream"] = mod

    mod = types.ModuleType("environment_profile")
    mod.load_environment_profile = lambda *args, **kwargs: {}
    mod.suggest_domains_for_question = lambda *args, **kwargs: []
    stubs["environment_profile"] = mod

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
    mod.parse_env_file = lambda path: ([], {})
    mod.write_env_file = lambda updates, path: None
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


class WebUiLayoutTests(unittest.TestCase):
    def test_investigation_layout_exposes_mode_banner_execution_monitor_and_next_action_workspace(self) -> None:
        html = wus.APP_HTML
        self.assertIn('id="invest-mode-banner"', html)
        self.assertIn('Execution Monitor', html)
        self.assertIn('Next Action Workspace', html)
        self.assertIn('Likely Data Sources (planning hint)', html)
        self.assertIn('Answer Card', html)
        self.assertIn('Confidence + Why', html)
        self.assertIn('Primary Next Action', html)
        self.assertIn('Show alternatives', html)
        self.assertIn('SPL Used', html)
        self.assertIn('Why this is the best move', html)
        self.assertIn('When not to choose this', html)
        self.assertIn('nav-version-pill', html)
        self.assertIn(wus.APP_VERSION_LABEL, html)
        self.assertIn('Stage As Primary Action', html)
        self.assertIn('Rerun Question', html)
        self.assertIn('is-secondary-action', html)
        self.assertIn('case_id: String(options.case_id || \'\').trim()', html)
        self.assertIn('parent_node_id: String(options.parent_node_id || \'\').trim()', html)
        self.assertIn('What changes from previous step', html)
        self.assertIn('Mirror: seeded pivot', html)
        self.assertIn('data-entity-action', html)
        self.assertIn('data-ioc-field', html)
        self.assertIn('Decision Now', html)
        self.assertIn('data-tray-tab="pivot"', html)
        self.assertIn('data-tray-tab="timeline"', html)
        self.assertIn('data-tray-panel="context"', html)
        self.assertIn('Decision stays above. Use one lane at a time.', html)
        self.assertIn('TDI status', html)
        self.assertIn('timeline-decision-hero', html)
        self.assertNotIn('Run Pivot Now', html)
        self.assertNotIn('Open In Drawer', html)
        self.assertNotIn('Review Next Action', html)
        self.assertNotIn('Load Into Next Action Workspace', html)

    def test_investigation_layout_collapses_advanced_review_sections_by_default(self) -> None:
        html = wus.APP_HTML
        self.assertIn('class="flow-shell review-fold"', html)
        self.assertIn('<summary>Model Roles</summary>', html)
        self.assertIn('<summary>Execution Audit</summary>', html)
        self.assertIn('<summary>Advanced Review Trace</summary>', html)
        self.assertIn('Assessment, evidence, and next-step guidance stay above. Open this only when you need audit depth.', html)

    def test_mcp_layout_exposes_mode_banner_summary_and_diagnostics_split(self) -> None:
        html = wus._mcp_page_body()
        self.assertIn('id="mcp-mode-banner"', html)
        self.assertIn('Analyst Answer', html)
        self.assertIn('mcp-summary-title', html)
        self.assertIn('Planning Hints | Likely Data Sources', html)
        self.assertIn('Conversation Transcript', html)
        self.assertIn('Diagnostics', html)
        self.assertIn('Result Rows', html)
        self.assertIn('Executed SPL', html)

    def test_spl_asset_repository_uses_contained_two_column_layout(self) -> None:
        wus.learning_registry_summary = lambda *args, **kwargs: {
            "repository": {
                "records": [
                    {
                        "id": "asset-1",
                        "intent": "linux_auth_failures",
                        "use_when": "Use for Linux failed login questions.",
                        "why": "Grounded in local auth sources.",
                        "query_template": "search index=linux source=/var/log/auth.log | stats count by host user_name src_ip",
                        "required_fields": ["host", "user_name", "src_ip"],
                        "required_sources": ["/var/log/auth.log"],
                        "required_sourcetypes": ["auth.log"],
                        "updated_at": "2026-04-14T20:38:54.466869+00:00",
                        "match_tokens": ["failed", "login", "linux"],
                    }
                ]
            },
            "repository_path": "/tmp/spl_optimization_repository.json",
        }
        wus._load_json_if_exists = lambda *args, **kwargs: {"history_assets": []}
        html = wus._spl_asset_repository_page_body()
        self.assertIn('grid-template-columns:minmax(320px,420px) minmax(0,1fr)', html)
        self.assertIn('class="splrepo-side-rail"', html)
        self.assertIn('class="splrepo-spotlight-title-block"', html)
        self.assertIn('class="splrepo-metric splrepo-metric-active splrepo-spotlight-pill"', html)
        self.assertIn('class="splrepo-review-surface"', html)
        self.assertIn('class="splrepo-pattern-preview"', html)
        self.assertIn('class="btn-secondary splrepo-row-toggle"', html)
        self.assertIn('class="splrepo-detail-row"', html)
        self.assertIn('class="splrepo-code-block"', html)
        self.assertIn('.splrepo-row-toggle::before', html)
        self.assertIn('.splrepo-row-toggle[aria-expanded="true"]', html)
        self.assertIn('<colgroup>', html)
        self.assertNotIn('class="splrepo-table-scroll"', html)
        self.assertNotIn('scrollbar-gutter:stable both-edges', html)
        self.assertNotIn('overscroll-behavior:contain', html)
        self.assertNotIn('.splrepo-main{display:grid;gap:16px;order:2;min-width:0;}', html)
        self.assertNotIn('.splrepo-side{display:grid;gap:16px;order:1;position:sticky;top:88px;align-self:start;min-width:0;}', html)


if __name__ == "__main__":
    unittest.main()
