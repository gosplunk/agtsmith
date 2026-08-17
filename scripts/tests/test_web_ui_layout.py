#!/usr/bin/env python3
"""Regression tests for analyst-facing UI layout structure."""

from __future__ import annotations

import os
import json
import sys
import tempfile
import time
import types
from datetime import datetime, timezone
from pathlib import Path
import unittest
from unittest import mock

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
    mod.MCPRequestTimeout = type("MCPRequestTimeout", (TimeoutError,), {})
    stubs["minimal_question_to_answer"] = mod

    mod = types.ModuleType("ollama_log_stream")
    mod.LocalLogSourceRegistry = type("LocalLogSourceRegistry", (), {})
    mod.RemoteLogSourceRegistry = type("RemoteLogSourceRegistry", (), {})
    mod.StreamParams = type("StreamParams", (), {})
    mod.check_remote_health = lambda *args, **kwargs: {"ok": True}
    mod.format_sse = lambda *args, **kwargs: b""
    mod.get_remote_health_url = lambda *args, **kwargs: ""
    mod.redact_secrets = lambda value: value
    mod.role_allowed = lambda role: True
    stubs["ollama_log_stream"] = mod

    mod = types.ModuleType("ollama_ops_monitor")
    mod.build_local_log_command = lambda *args, **kwargs: ""
    mod.collect_ops_snapshot = lambda *args, **kwargs: {}
    mod.collect_analyst_ops_summary = lambda *args, **kwargs: {
        "connected": True,
        "connection_state": "connected",
        "host": "127.0.0.1:11434",
        "models_loaded": 2,
        "models_loaded_names": ["planner:latest", "writer:latest"],
        "gpu_vram_used_gb": 1.0,
        "gpu_vram_total_gb": 8.0,
        "gpu_utilization_pct": 42.0,
        "gpu_metrics_available": True,
        "gpu_metrics_reason": "",
        "gpu_metrics_source": "nvidia_smi",
        "cpu_utilization_pct": 18.5,
        "cpu_metrics_available": True,
        "cpu_metrics_reason": "",
        "cpu_engaged": True,
        "gpu_engaged": True,
        "compute_target": "hybrid",
        "updated_at": "2026-07-29T00:00:00+00:00",
    }
    mod.ollama_log_config_status = lambda *args, **kwargs: {}
    stubs["ollama_ops_monitor"] = mod

    mod = types.ModuleType("investigation_playbooks")
    mod.playbook_for_intent = lambda *args, **kwargs: {}
    mod.playbook_target_order = lambda *args, **kwargs: []
    mod.playbook_targets_for_intent = lambda *args, **kwargs: []
    stubs["investigation_playbooks"] = mod

    mod = types.ModuleType("environment_profile")
    mod.INDEX_ALIASES_OVERRIDE_PATH = Path("/tmp/index_aliases_override.json")
    mod.load_environment_profile = lambda *args, **kwargs: {}
    mod.suggest_domains_for_question = lambda *args, **kwargs: []
    mod.load_index_alias_overrides = lambda *args, **kwargs: {}
    mod.save_index_alias_overrides = lambda aliases, **kwargs: Path("/tmp/index_aliases_override.json")
    mod.infer_index_aliases_from_profile = lambda *args, **kwargs: {}
    mod.build_index_alias_map = lambda *args, **kwargs: {}
    stubs["environment_profile"] = mod

    mod = types.ModuleType("runtime_config")
    mod.DEFAULT_MODEL_AGENTIC_CONTINUATION_REVIEWER = "stub"
    mod.DEFAULT_MODEL_EVIDENCE_REVIEWER = "stub"
    mod.DEFAULT_MODEL_FINAL_SUMMARY = "stub"
    mod.DEFAULT_MODEL_PEER_REVIEWER = "stub"
    mod.DEFAULT_MODEL_PEER_REVIEWER_2 = "stub"
    mod.DEFAULT_MODEL_QUERY_PLANNER = "stub"
    mod.DEFAULT_MODEL_QUERY_PLANNER_FALLBACK = "stub-fallback"
    mod.DEFAULT_MODEL_QUERY_REPAIR = "stub"
    mod.DEFAULT_MODEL_QUERY_WRITER = "stub"
    mod.DEFAULT_MODEL_SECURITY_REVIEWER = "stub"
    mod.DEFAULT_MODEL_ASSIGNMENTS = {}
    mod.MODEL_ASSIGNMENT_KEYS = []
    mod.MODEL_PULL_EXTRA_KEYS = []
    mod.UI_ENV_PATH = Path("/tmp/agtsmith-ui.env")
    mod.display_path = lambda path: str(path)
    mod.expected_ollama_models = lambda values=None: []
    mod.model_stack_summary = lambda values=None: {"unique_tag_count": 0, "role_count": 0, "core_tags": [], "optional_tags": [], "families": []}
    mod.apply_model_family_assignments = lambda values: dict(values)
    mod.get_edge_llm_enabled = lambda: False
    mod.get_edge_llm_host = lambda: ""
    mod.get_edge_llm_model = lambda: ""
    mod.get_edge_llm_role = lambda: ""
    mod.get_edge_llm_timeout_sec = lambda: "60"
    mod.get_env_profile_auto_refresh_enabled = lambda: True
    mod.get_env_profile_refresh_interval_minutes = lambda: 60
    mod.get_soc_ui_session_timeout_min = lambda: "60"
    mod.get_soc_ui_session_remember_timeout_min = lambda: "480"
    mod.get_ollama_host = lambda: ""
    mod.is_local_ollama_host = lambda host=None: True
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

    mod = types.ModuleType("mcp_deterministic_routing")
    mod.resolve_mcp_chat_pipeline = lambda question, pipeline: (
        "assisted",
        {"requested_pipeline": pipeline or "assisted", "effective_pipeline": "assisted", "auto_routed": False},
    )
    mod.classify_mcp_deterministic_eligibility = lambda question: {"eligible": False, "reason": "stub"}
    stubs["mcp_deterministic_routing"] = mod

    for name, module in stubs.items():
        sys.modules[name] = module


_install_stub_modules()

import web_ui_server as wus


class WebUiLayoutTests(unittest.TestCase):
    def test_data_domains_maintenance_reports_profile_and_rag_freshness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_path = root / "profile.json"
            source_path = root / "search-index.json"
            rag_path = root / "rag-index.json"
            profile_path.write_text(
                '{"timestamp_utc": "' + datetime.now(timezone.utc).isoformat() + '"}',
                encoding="utf-8",
            )
            source_path.write_text("{}", encoding="utf-8")
            rag_path.write_text("{}", encoding="utf-8")
            now = time.time()
            os.utime(rag_path, (now - 60, now - 60))
            os.utime(source_path, (now, now))

            with mock.patch.object(wus, "ENV_PROFILE_PATH", profile_path), mock.patch.object(
                wus,
                "DEFAULT_SPL_OFFLINE_DOCS_SOURCE",
                source_path,
            ), mock.patch.object(
                wus,
                "SPL_OFFLINE_DOCS_RAG_PATH",
                rag_path,
            ), mock.patch.dict(
                os.environ,
                {"SPL_OFFLINE_DOCS_SOURCE": str(source_path)},
            ):
                meta = wus._data_domains_maintenance_meta()

        self.assertFalse(meta["profile_stale"])
        self.assertTrue(meta["offline_docs_source_available"])
        self.assertTrue(meta["offline_docs_rag_stale"])
        self.assertTrue(meta["next_refresh_due_utc"])
        self.assertTrue(meta["auto_refresh_enabled"])
        self.assertEqual(meta["refresh_interval_minutes"], 60)

    def test_data_domains_maintenance_hides_next_due_when_auto_refresh_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_path = root / "profile.json"
            profile_path.write_text(
                '{"timestamp_utc": "' + datetime.now(timezone.utc).isoformat() + '"}',
                encoding="utf-8",
            )
            with mock.patch.object(wus, "ENV_PROFILE_PATH", profile_path), mock.patch.object(
                wus, "get_env_profile_auto_refresh_enabled", lambda: False
            ):
                meta = wus._data_domains_maintenance_meta()
        self.assertFalse(meta["auto_refresh_enabled"])
        self.assertEqual(meta["next_refresh_due_utc"], "")

    def test_env_profile_auto_refresh_due_respects_toggle_and_progress(self) -> None:
        with mock.patch.object(wus, "get_env_profile_auto_refresh_enabled", lambda: False):
            self.assertFalse(wus._env_profile_auto_refresh_due())
        with mock.patch.object(wus, "get_env_profile_auto_refresh_enabled", lambda: True), mock.patch.object(
            wus, "_environment_profile_exists", lambda: False
        ):
            self.assertFalse(wus._env_profile_auto_refresh_due())
        with mock.patch.object(wus, "get_env_profile_auto_refresh_enabled", lambda: True), mock.patch.object(
            wus, "_environment_profile_exists", lambda: True
        ), mock.patch.object(wus, "_environment_profile_refresh_in_progress", lambda: True):
            self.assertFalse(wus._env_profile_auto_refresh_due())
        with mock.patch.object(wus, "get_env_profile_auto_refresh_enabled", lambda: True), mock.patch.object(
            wus, "_environment_profile_exists", lambda: True
        ), mock.patch.object(
            wus, "_environment_profile_refresh_in_progress", lambda: False
        ), mock.patch.object(
            wus, "get_env_profile_refresh_interval_minutes", lambda: 60
        ), mock.patch.object(
            wus,
            "_data_domains_maintenance_meta",
            lambda: {"profile_age_minutes": 61},
        ):
            self.assertTrue(wus._env_profile_auto_refresh_due())
        with mock.patch.object(wus, "get_env_profile_auto_refresh_enabled", lambda: True), mock.patch.object(
            wus, "_environment_profile_exists", lambda: True
        ), mock.patch.object(
            wus, "_environment_profile_refresh_in_progress", lambda: False
        ), mock.patch.object(
            wus, "get_env_profile_refresh_interval_minutes", lambda: 60
        ), mock.patch.object(
            wus,
            "_data_domains_maintenance_meta",
            lambda: {"profile_age_minutes": 5},
        ):
            self.assertFalse(wus._env_profile_auto_refresh_due())

    def test_configure_page_exposes_data_domains_scheduler_controls(self) -> None:
        html = wus._configure_page_body_rendered()
        self.assertIn('id="cfg-env-auto-refresh-enabled"', html)
        self.assertIn('id="cfg-env-auto-refresh-interval"', html)
        self.assertIn('value="60"', html)
        self.assertIn('value="240"', html)
        self.assertIn('value="1440"', html)
        self.assertIn("ENV_PROFILE_AUTO_REFRESH_ENABLED", html)
        self.assertIn("ENV_PROFILE_REFRESH_INTERVAL_MINUTES", html)
        # Checkbox defaults to checked so new setups auto-refresh every 60 minutes.
        self.assertIn('id="cfg-env-auto-refresh-enabled" type="checkbox" checked', html)

    def test_environment_page_shows_scheduler_status_and_modern_hero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_path = root / "profile.json"
            profile_path.write_text(
                '{"timestamp_utc": "'
                + datetime.now(timezone.utc).isoformat()
                + '", "indexes": [], "counts": {}, "time_window": {}}',
                encoding="utf-8",
            )
            with mock.patch.object(wus, "ENV_PROFILE_PATH", profile_path):
                html = wus._environment_page_body()
        self.assertIn("envx-hero", html)
        self.assertIn("envx-status-board", html)
        self.assertIn("envx-scheduler-badge", html)
        self.assertIn("Auto-refresh", html)

    def test_configure_page_exposes_role_family_model_map(self) -> None:
        html = wus._configure_page_body_rendered()
        self.assertIn('Model Stack', html)
        self.assertIn('id="cfg-session-timeout"', html)
        self.assertIn('id="cfg-session-remember-timeout"', html)
        self.assertIn('id="cfg-family-grid"', html)
        self.assertIn('id="cfg-inventory-table"', html)
        self.assertIn('cfg-family-shell', html)
        self.assertIn('cfg-family-select', html)
        self.assertIn('id="cfg-lane-nav"', html)
        self.assertIn('id="cfg-next-action"', html)
        self.assertIn('id="cfg-sticky-footer"', html)
        self.assertIn('Configure UI configure-ui-p3', html)
        self.assertIn('Advanced: Per-Stage Overrides', html)
        self.assertIn('id="cfg-model-planner-fallback"', html)
        self.assertIn('Index Alias Mapping', html)
        self.assertIn('id="cfg-index-alias-json"', html)

    def test_configure_page_script_is_valid_javascript(self) -> None:
        html = wus._configure_page_body_rendered()
        start = html.index('<script>')
        end = html.index('cfgLoad();', start) + len('cfgLoad();')
        js = html[start + len('<script>'):end].strip()
        self.assertEqual(js.count('{'), js.count('}'))
        self.assertEqual(js.count('('), js.count(')'))

    def test_investigation_layout_exposes_mode_banner_execution_monitor_and_next_action_workspace(self) -> None:
        html = wus._investigation_page_html({"role": "analyst"})
        self.assertIn('class="sidebar-rail"', html)
        self.assertIn('class="app-shell"', html)
        self.assertIn('class="rail-tooltip"', html)
        self.assertIn('Splunk MCP Chat', html)
        self.assertIn('LangGraph Graph', html)
        self.assertNotIn('class="topnav"', html)
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

    def test_investigation_layout_exposes_collapsible_runtime_rail(self) -> None:
        html = wus._investigation_page_html({"role": "analyst"})
        rail_html = wus._runtime_rail_html()
        self.assertIn('class="runtime-rail"', html)
        self.assertIn('id="runtime-rail-toggle"', html)
        self.assertIn('LangGraph Journey', html)
        self.assertIn('Tasked LLM', html)
        self.assertIn('Ollama Ops', html)
        self.assertLess(rail_html.index('LangGraph Journey'), rail_html.index('Tasked LLM'))
        self.assertLess(rail_html.index('Tasked LLM'), rail_html.index('Ollama Ops'))
        self.assertIn('id="runtime-model-summary"', html)
        self.assertIn('id="runtime-ops-gpu-util"', html)
        self.assertIn('id="runtime-ops-cpu-util"', html)
        self.assertIn('id="runtime-ops-device-gpu"', html)
        self.assertIn('id="runtime-ops-device-cpu"', html)
        self.assertIn('id="runtime-ops-device-label"', html)
        self.assertIn('id="runtime-ops-model-label"', html)
        self.assertIn('Ollama Utilization', html)
        self.assertIn('Glow is live; outline marks the last model task.', html)
        self.assertIn('updateRuntimeRailFromStage', html)
        self.assertIn('/api/runtime/ops-summary', html)
        self.assertIn('agtsmith_runtime_rail_expanded', html)
        self.assertIn('runtime-rail-pulse', html)
        self.assertIn('runtime-journey-step-time', html)
        self.assertIn('runtime-journey-label-wrap', html)
        self.assertIn('runtime-journey-step.is-skipped', html)
        self.assertIn('markJourneySkipped', html)
        self.assertIn('hydrateSkippedFromResult', html)
        rail = wus._runtime_rail_script(show_ops_link=False)
        self.assertIn('const phaseActive = runActive && Boolean(activeNode);', rail)
        self.assertIn('const modelPhase = phaseActive && Boolean(roleKey);', rail)
        self.assertIn("parallel_compute", rail)
        self.assertIn("'CPU phase'", rail)
        self.assertIn('lastTaskedSnapshot', rail)
        self.assertIn('hydrateLastTaskedFromResult', rail)
        self.assertIn('Last task ·', rail)
        self.assertIn("classList.toggle('is-last'", rail)
        self.assertIn('updateOpsPhaseState();', rail)
        self.assertIn('runtime-ops-keep-warm', html)
        self.assertIn('/api/runtime/ollama-keep-warm', rail)
        self.assertIn('setOllamaKeepWarm', rail)
        self.assertIn('resolveJourneyNode', rail)
        self.assertIn("if (node === 'ingest_question') return '';", rail)
        self.assertIn('runtime-journey-legend', html)
        self.assertIn('writer-path-library', html)
        self.assertIn('writer-path-deterministic', html)
        self.assertIn('writer-path-llm', html)
        self.assertIn('--runtime-rail-width: 248px', html)
        self.assertIn('runtime-ops-full-link" href="/admin/ollama-ops" hidden', html)

    def test_investigation_layout_exposes_journey_playbook_overlay(self) -> None:
        html = wus._investigation_page_html({"role": "analyst"})
        self.assertIn('id="runtime-journey-expand"', html)
        self.assertIn('id="runtime-journey-overlay"', html)
        self.assertIn('id="runtime-journey-overlay-backdrop"', html)
        self.assertIn('id="runtime-journey-overlay-close"', html)
        self.assertIn('id="runtime-journey-overlay-playbook"', html)
        self.assertNotIn('id="runtime-journey-overlay-sidebar"', html)
        self.assertNotIn('runtime-journey-overlay-content', html)
        self.assertIn('id="runtime-journey-overlay-profile"', html)
        self.assertIn('id="runtime-journey-overlay-status"', html)
        self.assertIn('id="runtime-journey-overlay-zoom-out"', html)
        self.assertIn('id="runtime-journey-overlay-zoom-in"', html)
        self.assertIn('id="runtime-journey-overlay-zoom-fit"', html)
        self.assertIn('id="runtime-journey-overlay-zoom-value"', html)
        self.assertIn('runtime-journey-overlay-status-spinner', html)
        self.assertIn('runtime-journey-overlay-status-check', html)
        self.assertIn('runtime-journey-overlay', html)
        self.assertIn('playbook-flowchart', html)
        self.assertIn('playbook-flowchart-svg', html)
        overlay_styles = wus._runtime_journey_overlay_styles()
        self.assertIn('backdrop-filter:blur(16px)', overlay_styles)
        self.assertIn('rgba(15,23,42,.92)', overlay_styles)
        self.assertIn('rgba(62,184,255,.25)', overlay_styles)
        self.assertIn('right:calc(var(--runtime-rail-width, 248px) + 16px)', overlay_styles)
        self.assertIn('min(1500px, calc(100vw - 64px - var(--runtime-rail-width, 248px) - 16px))', overlay_styles)
        self.assertIn('padding:12px 16px 16px 12px', overlay_styles)
        self.assertIn('overflow:auto', overlay_styles)
        self.assertIn('scrollbar-gutter:stable both-edges', overlay_styles)
        self.assertIn('max-width:none', overlay_styles)
        self.assertNotIn('overflow-x:hidden', overlay_styles)
        self.assertNotIn('min-height:640px', overlay_styles)
        self.assertIn('branch-operational', overlay_styles)
        self.assertIn('branch-trunk', overlay_styles)
        self.assertIn('playbook-flow-legend', overlay_styles)
        self.assertIn('playbook-flow-process', overlay_styles)
        self.assertIn('phase-trunk', overlay_styles)
        self.assertIn('phase-operational', overlay_styles)
        self.assertIn('phase-security', overlay_styles)
        self.assertIn('phase-gate', overlay_styles)
        self.assertIn('background-size:28px 28px', overlay_styles)
        self.assertIn('playbook-flow-icon-badge', overlay_styles)
        self.assertIn('runtime-journey-overlay-status-spinner', overlay_styles)
        self.assertNotIn('playbook-flow-spinner-arc', overlay_styles)
        self.assertNotIn('playbook-spinner-spin', overlay_styles)
        self.assertIn('playbook-flow-edge-label-bg', overlay_styles)
        self.assertIn('runtime-journey-overlay-profile-pill', overlay_styles)
        self.assertIn('playbook-flow-phase-time', overlay_styles)
        self.assertIn('playbook-flow-lane-header', overlay_styles)
        rail = wus._runtime_rail_script(show_ops_link=False)
        self.assertIn('openJourneyOverlay', rail)
        self.assertIn('closeJourneyOverlay', rail)
        self.assertIn('renderPlaybookFlowchart', rail)
        self.assertIn('renderPlaybookOverlay', rail)
        self.assertIn('fitPlaybookToViewport', rail)
        self.assertIn('applyPlaybookZoom', rail)
        self.assertIn('handlePlaybookViewportWheel', rail)
        self.assertIn('handlePlaybookDoubleClick', rail)
        self.assertIn('PLAYBOOK_DOUBLE_CLICK_FACTOR = 1.6', rail)
        self.assertIn('centerOnAnchor: true', rail)
        self.assertIn("addEventListener('dblclick', handlePlaybookDoubleClick)", rail)
        self.assertIn('beginPlaybookPan', rail)
        self.assertIn('PLAYBOOK_ZOOM_MIN = 0.1', rail)
        self.assertIn('PLAYBOOK_ZOOM_MAX = 2', rail)
        self.assertIn("playbookZoomMode = 'fit'", rail)
        self.assertIn("playbookViewport.scrollLeft", rail)
        self.assertIn("playbookViewport.scrollTop", rail)
        self.assertIn("addEventListener('wheel', handlePlaybookViewportWheel, { passive: false })", rail)
        self.assertIn('new window.ResizeObserver', rail)
        self.assertNotIn('syncOverlayRuntimeSidebar', rail)
        self.assertIn('updateReviewProfilePill', rail)
        self.assertIn('syncPlaybookCompletedThrough', rail)
        self.assertIn('completeGraphSummarizeStep', rail)
        self.assertIn('playbookCompletedThrough = -1', rail)
        self.assertIn('All paths', rail)
        self.assertIn('appendProcessNodeTitle', rail)
        self.assertIn('edgeDrawOrder', rail)
        from investigation_progress import PLAYBOOK_VIEWBOX  # noqa: WPS433

        self.assertIn(f"const FLOW_VIEWBOX = {json.dumps(PLAYBOOK_VIEWBOX)};", rail)
        self.assertIn('appendPlaybookDefs', rail)
        self.assertIn('nodeGradTrunk', rail)
        self.assertIn('nodeGradOperational', rail)
        self.assertIn('nodeGradMetadata', rail)
        self.assertIn('nodeGradSecurity', rail)
        self.assertIn('nodeGradPending', rail)
        self.assertIn('id="glow"', rail)
        self.assertIn('id="greenGlow"', rail)
        self.assertIn('id="amberGlow"', rail)
        self.assertNotIn('playbook-flow-done-badge', rail)
        self.assertNotIn('appendNodeStatusChrome', rail)
        self.assertIn('updatePlaybookHeaderStatus', rail)
        self.assertIn("playbookRunCompleted = true", rail)
        self.assertIn('PLAYBOOK_EDGES', rail)
        self.assertIn('PLAYBOOK_FLOW', rail)
        self.assertIn('PLAYBOOK_LAYOUT', rail)
        self.assertIn('PLAYBOOK_NODE_TIPS', rail)
        self.assertIn('bindPlaybookNodeTooltips', rail)
        self.assertIn('playbook-node-tooltip', html)
        self.assertIn('playbook-node-tooltip', overlay_styles)
        self.assertIn('PLAYBOOK_ORDER', rail)
        self.assertIn('buildPlaybookFlowchart', rail)
        self.assertIn('appendPlaybookLegend', rail)
        self.assertIn('appendPlaybookFramework', rail)
        self.assertIn('renderPlaybookPhaseTimes', rail)
        self.assertIn("phaseSkipped ? 'skipped'", rail)
        self.assertIn('journeyStageSeconds', rail)
        self.assertIn('PLAYBOOK_TIMING_SOURCE', rail)
        self.assertIn('value.toFixed(3)', rail)
        self.assertIn('presentKeys', rail)
        self.assertIn('finalSeconds > 0 || stageTimingsSec[key] == null', rail)
        self.assertIn('delete stageTimingsSec[key]', rail)
        self.assertIn('recordStageComplete', rail)
        self.assertIn('activateJourneyNode', rail)
        self.assertIn('completedNodes.has(key)', rail)
        self.assertIn('eventPhase', rail)
        self.assertNotIn('playbookTimingsSec', rail)
        self.assertNotIn('playbookStartAt', rail)
        self.assertIn('PLAYBOOK_ICONS', rail)
        self.assertIn('playbookIconPath', rail)
        self.assertIn("'Core flow'", rail)
        self.assertIn('trimPathEnd', rail)
        self.assertIn('bindPlaybookJourneyHoverSync', rail)
        self.assertIn('edgeLabelWidth', rail)
        self.assertIn("'Edge label'", rail)
        self.assertIn('playbook-flow-legend-section', overlay_styles)
        self.assertIn('playbook-flow-legend-edge-bg', overlay_styles)
        self.assertIn("setAttribute('rx', '16')", rail)
        self.assertIn('resolveWriterPathFromResult', rail)
        self.assertIn('applyWriterPathFromResult', rail)
        self.assertIn('writer-path-library', rail)
        rail_styles = wus._runtime_rail_stylesheet()
        self.assertIn('min(1500px, calc(100vw - 64px - var(--runtime-rail-width, 248px) - 16px))', rail_styles)
        self.assertIn('@property --runtime-rail-width', rail_styles)
        self.assertIn('transition:--runtime-rail-width .18s ease', rail_styles)
        self.assertNotIn('transition:width .18s ease, min-width .18s ease', rail_styles)
        self.assertIn('xMidYMin meet', rail)
        self.assertIn('z-index:410', rail_styles)
        self.assertNotIn('runtime-playbook-node', html)
        self.assertNotIn('.playbook-flow-icon {', overlay_styles)
        self.assertNotIn("class='playbook-flow-icon'", rail)

    def test_investigation_runtime_rail_shows_ops_link_for_ops_role(self) -> None:
        html = wus._investigation_page_html({"role": "ops"})
        self.assertIn('id="runtime-ops-full-link"', html)
        self.assertIn('View full Ollama Ops', html)

    def test_runtime_ops_summary_endpoint_is_analyst_safe(self) -> None:
        payload = wus.collect_analyst_ops_summary("")
        self.assertIn("connected", payload)
        self.assertIn("connection_state", payload)
        self.assertIn("host", payload)
        self.assertIn("models_loaded", payload)
        self.assertIn("models_loaded_names", payload)
        self.assertIn("gpu_vram_used_gb", payload)
        self.assertIn("gpu_vram_total_gb", payload)
        self.assertIn("gpu_utilization_pct", payload)
        self.assertIn("gpu_metrics_available", payload)
        self.assertIn("cpu_utilization_pct", payload)
        self.assertIn("cpu_metrics_available", payload)
        self.assertIn("compute_target", payload)
        self.assertNotIn("log_source", payload)
        self.assertNotIn("models_installed", payload)

    def test_mcp_layout_exposes_runtime_rail(self) -> None:
        html = wus._mcp_page_body()
        self.assertIn('Analyst Answer', html)
        shell = wus.DOCS_SHELL_HTML.format(
            title="MCP",
            body=html,
            nav=wus._global_nav("mcp"),
            onboarding_user="",
            onboarding_role="analyst",
            onboarding_modal="",
            app_version=wus.APP_VERSION_LABEL,
            runtime_rail_styles=wus._runtime_rail_stylesheet(),
            runtime_rail=wus._runtime_rail_html(),
            runtime_rail_script=wus._runtime_rail_script(show_ops_link=False),
        )
        self.assertIn('class="runtime-rail"', shell)
        self.assertIn('id="runtime-journey"', shell)

    def test_mcp_layout_wires_runtime_rail_journey_during_runs(self) -> None:
        html = wus._mcp_page_body()
        rail = wus._runtime_rail_script(show_ops_link=False)
        self.assertIn('/api/mcp/chat/stream', html)
        self.assertIn('mcpStageHandler', html)
        self.assertIn('finalizeMcpRuntimeRail', html)
        self.assertIn('handleAskStreamStage', html)
        self.assertNotIn('updateRuntimeRailFromProgress', html)
        self.assertIn('completeRuntimeRailJourneyFromWorkflow', rail)
        self.assertIn('hydrateRuntimeRailJourneyTimings', rail)
        self.assertIn('renderJourneyTimes', rail)
        self.assertIn('formatStageSeconds', rail)
        self.assertIn('runtime-journey-step-time', wus._runtime_rail_html())
        self.assertIn('window.consumeAskStream = consumeAskStream', rail)
        self.assertIn('parseSseBuffer', rail)
        self.assertIn("context: 'MCP'", html)

    def test_investigation_run_fallback_wires_stage_handler(self) -> None:
        html = wus._investigation_page_html({"role": "analyst"})
        self.assertIn('handleAskStreamStage', html)
        self.assertNotIn('consumeAskStream(resp, () => {})', html)

    def test_investigation_layout_collapses_advanced_review_sections_by_default(self) -> None:
        html = wus._investigation_page_html({"role": "analyst"})
        self.assertIn('class="flow-shell review-fold"', html)
        self.assertIn('<summary>Model Roles</summary>', html)
        self.assertIn('<summary>Execution Audit</summary>', html)
        self.assertIn('<summary>Advanced Review Trace</summary>', html)
        self.assertIn('Assessment, evidence, and next-step guidance stay above. Open this only when you need audit depth.', html)

    def test_investigation_progress_uses_streaming_and_indeterminate_copy(self) -> None:
        html = wus._investigation_page_html({"role": "analyst"})
        self.assertIn('/api/ask/stream', html)
        self.assertIn('runProgressIndeterminate', html)
        self.assertIn('consumeAskStream', html)
        self.assertIn('Progress follows completed LangGraph stages', html)
        self.assertNotIn('runProgressValue + 0.08', html)
        self.assertNotIn('runProgressValue < 96', html)

    def test_global_nav_renders_icon_rail_with_flyout(self) -> None:
        nav = wus._global_nav("investigation")
        self.assertIn('class="sidebar-rail"', nav)
        self.assertIn('class="rail-logo"', nav)
        self.assertIn('viewBox="0 0 32 32"', nav)
        self.assertNotIn("A.S.", nav)
        self.assertIn('class="rail-item active"', nav)
        self.assertIn('rail-item-flyout', nav)
        self.assertIn('class="rail-flyout"', nav)
        self.assertIn('LangGraph Graph', nav)
        self.assertNotIn('class="topnav"', nav)

    def test_mcp_layout_exposes_mode_banner_summary_and_diagnostics_split(self) -> None:
        html = wus._mcp_page_body()
        self.assertIn('id="mcp-mode-banner"', html)
        self.assertIn('class="mcp-composer-bottom"', html)
        self.assertNotIn('class="mcp-query-top"', html)
        self.assertIn('class="mcp-tab-nav-shell"', html)
        self.assertIn('class="mcp-tab-nav"', html)
        self.assertIn('class="mcp-tab-overflow"', html)
        self.assertIn('data-mcp-tab="answer"', html)
        self.assertIn('data-mcp-tab="spl"', html)
        self.assertIn('data-mcp-tab="results"', html)
        self.assertIn('data-mcp-tab="planning"', html)
        self.assertIn('data-mcp-tab="diagnostics"', html)
        self.assertIn('class="mcp-tab-panel"', html)
        self.assertIn('data-mcp-panel="answer"', html)
        self.assertIn('id="mcp-run-strip"', html)
        self.assertIn('data-run-step="planning"', html)
        self.assertIn('switchMcpTab', html)
        self.assertIn('updateMcpRunStrip', html)
        self.assertIn('id="mcp-user-bubble"', html)
        self.assertIn('Analyst Answer', html)
        self.assertIn('mcp-summary-title', html)
        self.assertIn('mcp-spark-icon', html)
        self.assertIn('id="mcp-answer-time"', html)
        self.assertIn('pipeline=llm_assisted', html)
        self.assertIn('Planning Hints | Likely Data Sources', html)
        self.assertIn('Conversation Transcript', html)
        self.assertIn('Diagnostics', html)
        self.assertIn('id="mcp-results"', html)
        self.assertIn('SPL Query', html)
        self.assertIn('id="mcp-spl-copy"', html)
        self.assertIn('id="mcp-download-csv"', html)
        self.assertIn('mcp-run-btn', html)
        self.assertIn('id="mcp-question"', html)
        self.assertIn(wus.MCP_DEFAULT_QUESTION, html)
        self.assertIn('MCP_DEFAULT_QUESTION', html)
        self.assertIn('showUserBubble(MCP_DEFAULT_QUESTION)', html)
        self.assertIn('id="mcp-send"', html)
        self.assertIn('id="mcp-stop"', html)
        self.assertIn('id="mcp-writer"', html)
        self.assertIn('id="mcp-runtime"', html)
        self.assertIn('id="mcp-rag"', html)
        self.assertIn('id="mcp-json"', html)
        self.assertNotIn('mcp-thread', html)
        self.assertNotIn('mcp-composer-sticky', html)
        self.assertNotIn('mcp-stack', html)
        self.assertIn("rawText.split('\\n')", html)

    def test_mcp_layout_shows_actual_search_time_window(self) -> None:
        """The SPL tab and answer trust-strip must surface the earliest/latest
        time window actually dispatched to Splunk, distinct from the SPL query
        text itself (time bounds are separate MCP tool args, never inline SPL)."""
        html = wus._mcp_page_body()
        self.assertIn('id="mcp-time-window"', html)
        self.assertIn('time=n/a', html)
        self.assertIn('id="mcp-spl-time-row"', html)
        self.assertIn('id="mcp-spl-time-window-value"', html)
        self.assertIn('function resolveMcpTimeWindow', html)
        self.assertIn('function updateMcpTimeWindowUI', html)
        self.assertIn('updateMcpTimeWindowUI(data)', html)
        self.assertIn('id="mcp-save-query-btn"', html)
        self.assertIn('id="mcp-save-query-modal"', html)
        self.assertIn('function openMcpSaveQueryModal', html)
        self.assertIn('function commitMcpSaveQuery', html)
        self.assertNotIn("rawText.split('\n');", html)

    def test_mcp_layout_uses_compact_composer_toggles(self) -> None:
        html = wus._mcp_page_body()
        self.assertIn('id="mcp-pipeline-segment"', html)
        self.assertIn('id="mcp-mode-segment"', html)
        self.assertIn('data-mcp-pipeline="assisted"', html)
        self.assertIn('data-mcp-mode="live"', html)
        self.assertIn('.mcp-segment {', html)
        self.assertIn('display: inline-flex', html)
        self.assertIn('padding: 4px 10px', html)
        self.assertIn('font-size: 11px', html)
        self.assertNotIn('min-height: 38px', html)
        self.assertNotIn('grid-template-columns: repeat(2, minmax(0, 1fr))', html)

    def test_mcp_layout_exposes_stop_button_and_abort_handler(self) -> None:
        html = wus._mcp_page_body()
        self.assertIn('id="mcp-run-chevron"', html)
        self.assertIn('id="mcp-run-menu"', html)
        self.assertIn('mcp-run-menu-wrap', html)
        self.assertIn('id="mcp-stop"', html)
        self.assertIn('Stop run', html)
        self.assertIn('mcp-run-menu-item', html)
        self.assertRegex(html, r'id="mcp-run-menu"[^>]*>[\s\S]*?id="mcp-stop"')
        self.assertNotRegex(html, r'</div>\s*</div>\s*<button id="mcp-stop"')
        self.assertIn('mcp-stop-spinner', html)
        self.assertIn('is-aborting', html)
        self.assertIn('.mcp-stop-btn.is-aborting .mcp-stop-spinner', html)
        self.assertRegex(html, r'\.mcp-stop-spinner\s*\{[^}]*display:\s*none')
        self.assertIn('cursor: pointer', html)
        self.assertIn('background: #0f172a', html)
        self.assertIn('border: 1px solid #1e293b', html)
        self.assertNotIn('.mcp-stop-btn:disabled { opacity: .65; cursor: wait;', html)
        self.assertIn('closeMcpRunMenu', html)
        self.assertIn('toggleMcpRunMenu', html)
        self.assertIn('Running...', html)
        self.assertIn('id="mcp-tab-run-progress"', html)
        self.assertIn('mcpAbortController', html)
        self.assertIn('AbortController', html)
        self.assertIn('AbortError', html)
        self.assertIn('cancelMcpRun', html)
        self.assertIn('syncMcpRunButtons', html)
        self.assertIn('notifyRuntimeRailRunEnd', html)
        self.assertIn('Esc to stop while running', html)

    def test_investigation_layout_exposes_stop_button_and_abort_handler(self) -> None:
        html = wus._investigation_page_html({"role": "analyst"})
        self.assertIn('id="stop-run"', html)
        self.assertIn('invest-stop-spinner', html)
        self.assertIn('is-aborting', html)
        self.assertIn('.invest-stop-btn.is-aborting .invest-stop-spinner', html)
        self.assertNotIn('.invest-stop-btn:disabled {\n      opacity: .65;\n      cursor: wait;', html)
        self.assertIn('runAbortController', html)
        self.assertIn('AbortController', html)
        self.assertIn('AbortError', html)
        self.assertIn('cancelInvestigationRun', html)
        self.assertIn('syncInvestRunButtons', html)
        self.assertIn('invest-stop-btn', html)
        self.assertNotIn('id="cancel-run"', html)

    def test_login_page_uses_centered_modern_shell(self) -> None:
        html = wus.Handler._login_page_body(None)
        self.assertIn('class="login-shell"', html)
        self.assertIn('class="login-mark"', html)
        self.assertIn('viewBox="0 0 32 32"', html)
        self.assertNotIn("A.S", html)
        self.assertIn('class="login-btn"', html)
        self.assertIn('name="remember"', html)
        self.assertIn('class="login-remember-input"', html)
        self.assertIn('class="login-toggle-track"', html)
        self.assertIn('class="login-toggle-knob"', html)
        self.assertIn('class="login-remember-label"', html)
        self.assertIn("Remain logged in", html)
        self.assertIn("input:not([type=checkbox])", html)
        self.assertIn("label.login-remember", html)
        self.assertIn("overflow:hidden", html)
        self.assertNotIn("accent-color", html)
        self.assertNotIn("login-remember-switch", html)
        self.assertIn('body:has(.login-shell) .app-shell', html)
        self.assertIn('#38bdf8', html)
        self.assertIn('#0f172a', html)

    def test_configure_page_exposes_session_status_loader(self) -> None:
        html = wus._configure_page_body_rendered()
        self.assertIn('id="cfg-session-status"', html)
        self.assertIn("/api/session/status", html)
        self.assertIn("cfgLoadSessionStatus", html)

    def test_authenticated_pages_include_sidebar_rail(self) -> None:
        pages = [
            ("configure", wus._configure_page_body_rendered(), "control"),
            ("mcp", wus._mcp_page_body(), "mcp"),
            ("docs", wus._docs_index_body(), "control"),
            ("ollama", wus._ollama_ops_page_body(), "control"),
            ("learning", wus._learning_page_body(), "control"),
            ("environment", wus._environment_page_body(), "environment"),
        ]
        for label, body, nav_active in pages:
            shell = wus.DOCS_SHELL_HTML.format(
                title=label,
                body=body,
                nav=wus._global_nav(nav_active),
                onboarding_user="analyst",
                onboarding_role="analyst",
                onboarding_modal="",
                app_version=wus.APP_VERSION_LABEL,
                runtime_rail_styles=wus._runtime_rail_stylesheet(),
                runtime_rail=wus._runtime_rail_html(),
                runtime_rail_script=wus._runtime_rail_script(show_ops_link=False),
            )
            with self.subTest(page=label):
                self.assertIn('class="sidebar-rail"', shell)
                self.assertIn('border-right:1px solid #1e293b', shell)
                self.assertIn('--accent:#38bdf8', shell)

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

    def test_investigation_stage_sse_payload_includes_phase_and_duration(self) -> None:
        payload = wus._investigation_stage_sse_payload(
            "planner",
            24,
            "Planning investigation approach...",
            "Planning",
            source="llm_assisted",
            phase="complete",
            duration_ms=160000,
        )
        self.assertEqual(payload["node"], "planner")
        self.assertEqual(payload["phase"], "complete")
        self.assertEqual(payload["duration_ms"], 160000)
        self.assertEqual(payload["status"], "complete")


class WebUiSessionBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self._old_ui_env_path = wus.UI_ENV_PATH
        self._old_sessions = dict(wus.SESSIONS)
        wus.UI_ENV_PATH = Path(self._tmpdir.name) / "ui.env"
        wus.SESSIONS.clear()

    def tearDown(self) -> None:
        wus.UI_ENV_PATH = self._old_ui_env_path
        wus.SESSIONS.clear()
        wus.SESSIONS.update(self._old_sessions)
        self._tmpdir.cleanup()

    def test_default_session_timeout_is_sixty_minutes(self) -> None:
        self.assertEqual(wus._session_timeout_minutes(), 60)
        self.assertEqual(wus._session_timeout_seconds(), 3600)

    def test_sliding_expiration_extends_active_session(self) -> None:
        token = wus._create_session("analyst1", "analyst", remember=False)
        with wus.SESSIONS_LOCK:
            original_expires = int(wus.SESSIONS[token]["expires"])
        time.sleep(1)
        session = wus._get_session(token, touch=True)
        self.assertIsNotNone(session)
        with wus.SESSIONS_LOCK:
            refreshed_expires = int(wus.SESSIONS[token]["expires"])
        self.assertGreater(refreshed_expires, original_expires)

    def test_remember_session_uses_longer_timeout(self) -> None:
        with mock.patch.object(wus, "get_soc_ui_session_remember_timeout_min", return_value="120"):
            self.assertEqual(wus._session_timeout_minutes(remember=True), 120)

    def test_session_status_payload_includes_expiry_fields(self) -> None:
        token = wus._create_session("ops1", "ops", remember=True)
        session = wus._get_session(token)
        self.assertIsNotNone(session)
        payload = wus._session_status_payload(session or {})
        self.assertEqual(payload["username"], "ops1")
        self.assertTrue(payload["remember"])
        self.assertGreater(payload["expires_in_seconds"], 0)


if __name__ == "__main__":
    unittest.main()
