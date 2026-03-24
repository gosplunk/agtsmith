#!/usr/bin/env python3
"""Local web UI for the SOC lab with docs portal and architecture view."""

from __future__ import annotations

import argparse
import base64
import html
import hashlib
import hmac
import json
import os
import queue
import re
import secrets
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from http.cookies import SimpleCookie
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

from langgraph_agentic_soc import run_agentic_investigation
from langgraph_multi_model_soc import describe_multi_model_graph, run_multi_model_soc
from minimal_question_to_answer import run_splunk_query_args
from ollama_log_stream import (
    RemoteLogSourceRegistry,
    StreamParams,
    format_sse,
    get_remote_health_url,
    redact_secrets,
    role_allowed,
)
from environment_profile import suggest_domains_for_question
from runtime_config import (
    UI_ENV_PATH,
    display_path,
    get_edge_llm_enabled,
    get_edge_llm_host,
    get_edge_llm_model,
    get_edge_llm_role,
    get_edge_llm_timeout_sec,
    get_ollama_host,
    get_splunk_base_url,
    get_splunk_mcp_url,
    parse_env_file,
    write_env_file,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOCS_ROOT = PROJECT_ROOT / "docs"
ARTIFACTS_ROOT = PROJECT_ROOT / "artifacts"
ENV_PROFILE_PATH = ARTIFACTS_ROOT / "environment" / "environment_profile_latest.json"
ENV_PROFILE_BOOTSTRAP_LOCK = ARTIFACTS_ROOT / "environment" / ".bootstrap.lock"
ENV_PROFILE_REFRESH_LOCK = ARTIFACTS_ROOT / "environment" / ".refresh.lock"
ENV_PROFILE_REFRESH_LOG = ARTIFACTS_ROOT / "environment" / "env_profile_refresh_web.log"
ENV_PROFILE_REFRESH_STATE = ARTIFACTS_ROOT / "environment" / "env_profile_refresh_status.json"
SPL_SKILLPACK_PATH = ARTIFACTS_ROOT / "knowledge" / "spl_skillpack_latest.json"
PERSONALIZATION_LOCK = ARTIFACTS_ROOT / "knowledge" / ".personalization.lock"
PERSONALIZATION_LOG = ARTIFACTS_ROOT / "knowledge" / "personalization_web.log"
PERSONALIZATION_STATE = ARTIFACTS_ROOT / "knowledge" / "personalization_status.json"
AUDIT_ROOT = ARTIFACTS_ROOT / "audit"
QUERY_AUDIT_LOG = AUDIT_ROOT / "query_runs.jsonl"
LOG_SOURCE_REGISTRY = RemoteLogSourceRegistry()
SESSION_COOKIE_NAME = "soc_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
SESSIONS: dict[str, dict[str, Any]] = {}
SESSIONS_LOCK = threading.Lock()
ALLOWED_APP_ROLES = {"admin", "ops", "analyst"}
EXPECTED_MODEL_KEYS = [
    "OLLAMA_MODEL_QUERY_PLANNER",
    "OLLAMA_MODEL_QUERY_WRITER",
    "OLLAMA_MODEL_QUERY_REPAIR",
    "OLLAMA_MODEL_EVIDENCE_REVIEWER",
    "OLLAMA_MODEL_SECURITY_REVIEWER",
    "OLLAMA_MODEL_PEER_REVIEWER",
    "OLLAMA_MODEL_PEER_REVIEWER_2",
    "OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER",
    "OLLAMA_MODEL_FINAL_SUMMARY",
]
DEFAULT_MODEL_ASSIGNMENTS = {
    "OLLAMA_MODEL_QUERY_PLANNER": "hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M",
    "OLLAMA_MODEL_QUERY_WRITER": "deepseek-coder-v2:lite",
    "OLLAMA_MODEL_QUERY_REPAIR": "deepseek-coder-v2:lite",
    "OLLAMA_MODEL_EVIDENCE_REVIEWER": "hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M",
    "OLLAMA_MODEL_SECURITY_REVIEWER": "hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M",
    "OLLAMA_MODEL_PEER_REVIEWER": "hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M",
    "OLLAMA_MODEL_PEER_REVIEWER_2": "hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M",
    "OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER": "hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest",
    "OLLAMA_MODEL_FINAL_SUMMARY": "hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest",
}
EDGE_CONFIG_KEYS = [
    "EDGE_LLM_ENABLED",
    "EDGE_LLM_HOST",
    "EDGE_LLM_MODEL",
    "EDGE_LLM_ROLE",
    "EDGE_LLM_TIMEOUT_SEC",
]
CONFIG_EDITABLE_KEYS = [
    "OLLAMA_HOST",
    "SPLUNK_BASE_URL",
    "SPLUNK_MCP_URL",
    "SPLUNK_LAB_BEARER_TOKEN",
    "SOC_UI_AUTH_ENABLED",
    "SOC_UI_AUTH_USERNAME",
    "SOC_UI_AUTH_PASSWORD",
    "SOC_UI_AUTH_ROLE",
    *EDGE_CONFIG_KEYS,
    *EXPECTED_MODEL_KEYS,
]
DEFAULT_UI_PASSWORDS = {"changeme123!", "SplunkLab-Only-ChangeMe!"}
PASSWORD_HASH_PREFIX = "pbkdf2_sha256:"
LEGACY_PASSWORD_HASH_PREFIX = "pbkdf2_sha256$"


def _default_expected_models() -> list[str]:
    ordered: list[str] = []
    for key in EXPECTED_MODEL_KEYS:
        model = str(DEFAULT_MODEL_ASSIGNMENTS.get(key, "")).strip()
        if model and model not in ordered:
            ordered.append(model)
    return ordered


def _autofill_model_assignments(values: dict[str, str], available_models: list[str] | None = None) -> dict[str, str]:
    updated = {str(key): str(value).strip() for key, value in values.items()}
    installed = set(str(model).strip() for model in (available_models or []) if str(model).strip())
    for key in EXPECTED_MODEL_KEYS:
        if updated.get(key, "").strip():
            continue
        default_model = str(DEFAULT_MODEL_ASSIGNMENTS.get(key, "")).strip()
        if default_model and default_model in installed:
            updated[key] = default_model
    return updated


def _global_nav(active: str) -> str:
    items = [
        ("/mcp", "Splunk MCP Chat", "MCP", "mcp"),
        ("/investigation", "Investigation UI", "Investigate", "investigation"),
        ("/artifacts", "Artifact Repository", "Artifacts", "artifacts"),
        ("__control__", "Control Center", "Control", "control"),
        ("/logout", "Logout", "Session", "logout"),
    ]
    if _can_show_environment_page():
        items.insert(2, ("/environment", "Data Domains", "Profile", "environment"))
    links: list[str] = []
    for href, label, kicker, key in items:
        if href == "__control__":
            dropdown_items = [
                ("/architecture", "Architecture", "System flow and trust boundaries"),
                ("/langgraph-graph", "LangGraph Graph", "Canonical workflow, active topology, and run path"),
                ("/docs", "Docs", "Whitepapers, guides, and references"),
                ("/configure", "Configuration", "Endpoints, models, validation"),
                ("/users", "Users", "Local users and audit trail"),
            ]
            item_links = "".join(
                f'<a class="nav-submenu-item" href="{sub_href}">'
                f'<span class="nav-submenu-title">{html.escape(sub_label)}</span>'
                f'<span class="nav-submenu-copy">{html.escape(sub_copy)}</span>'
                "</a>"
                for sub_href, sub_label, sub_copy in dropdown_items
            )
            cls = "nav-item nav-item-dropdown active" if key == active else "nav-item nav-item-dropdown"
            links.append(
                f'<div class="{cls}">'
                f'<a class="nav-trigger" href="/configure">'
                f'<span class="nav-kicker">{html.escape(kicker)}</span>'
                f'<span class="nav-label">{html.escape(label)}</span>'
                "</a>"
                f'<div class="nav-submenu">{item_links}</div>'
                "</div>"
            )
            continue
        cls = "nav-item active" if key == active else "nav-item"
        links.append(
            f'<a class="{cls}" href="{html.escape(href)}">'
            f'<span class="nav-kicker">{html.escape(kicker)}</span>'
            f'<span class="nav-label">{html.escape(label)}</span>'
            "</a>"
        )
    return f'<nav class="topnav">{"".join(links)}</nav>'


def _control_subnav(active: str) -> str:
    items = [
        ("/architecture", "Architecture"),
        ("/langgraph-graph", "LangGraph Graph"),
        ("/docs", "Docs"),
        ("/configure", "Configuration"),
        ("/users", "Users"),
    ]
    links: list[str] = []
    for href, label in items:
        cls = "control-pane-link active" if href == active else "control-pane-link"
        links.append(
            f'<a class="{cls}" href="{href}">'
            f'<span class="control-pane-link-title">{html.escape(label)}</span>'
            "</a>"
        )
    return (
        '<section class="control-pane">'
        '<div class="control-pane-head">'
        '<div class="control-pane-kicker">Control Center</div>'
        '<h2 class="control-pane-title">Navigation</h2>'
        "</div>"
        f'<div class="control-pane-links">{"".join(links)}</div>'
        "</section>"
    )


def _load_json_if_exists(path: Path) -> dict[str, Any] | list[Any] | None:
    try:
        if path.exists() and path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return None


def _latest_matching_file(root: Path, pattern: str) -> Path | None:
    if not root.exists():
        return None
    matches = [item for item in root.rglob(pattern) if item.is_file()]
    if not matches:
        return None
    return max(matches, key=lambda item: item.stat().st_mtime)


def _latest_multi_model_run_payload() -> dict[str, Any] | None:
    latest = _latest_matching_file(ARTIFACTS_ROOT / "runs" / "multi_model", "multi_model_run_*.json")
    payload = _load_json_if_exists(latest) if latest else None
    if isinstance(payload, dict) and latest is not None:
        payload["_artifact_path"] = str(latest.relative_to(PROJECT_ROOT))
    return payload if isinstance(payload, dict) else None


def _latest_langgraph_topology_eval_payload() -> dict[str, Any] | None:
    latest = _latest_matching_file(ARTIFACTS_ROOT / "evals" / "langgraph", "langgraph_topology_eval_latest.json")
    payload = _load_json_if_exists(latest) if latest else None
    if isinstance(payload, dict) and latest is not None:
        payload["_artifact_path"] = str(latest.relative_to(PROJECT_ROOT))
    return payload if isinstance(payload, dict) else None


def _graph_mermaid(
    diagram: dict[str, Any],
    *,
    title: str,
    executed_nodes: set[str] | None = None,
    direction: str = "LR",
    use_subgraphs: bool = False,
    expanded: bool = False,
    subgraph_direction: str = "LR",
) -> str:
    executed_nodes = executed_nodes or set()
    rank_spacing = 54 if expanded else 45
    node_spacing = 30 if expanded else 24
    curve = "catmullRom" if expanded else "linear"
    lines = [
        "%%{init: {\"flowchart\": {\"curve\": \"" + curve + "\", \"nodeSpacing\": " + str(node_spacing) + ", \"rankSpacing\": " + str(rank_spacing) + "}} }%%",
        f"flowchart {direction}",
    ]
    group_labels = {
        "controller": "Controller",
        "primary_inference": "Primary Inference",
        "data_plane": "Data Plane",
    }
    nodes = diagram.get("nodes", [])
    if use_subgraphs:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for node in nodes:
            grouped[str(node.get("group", ""))].append(node)
        group_order = ["controller", "primary_inference", "data_plane"]
        for group in group_order:
            group_nodes = grouped.get(group, [])
            if not group_nodes:
                continue
            lines.append(f"    subgraph {group}[{group_labels.get(group, group.title())}]")
            lines.append(f"      direction {subgraph_direction}")
            for node in group_nodes:
                node_id = str(node.get("id", "")).strip()
                label = html.escape(str(node.get("label", node_id)))
                lines.append(f'      {node_id}["{label}"]')
            lines.append("    end")
    else:
        for node in nodes:
            node_id = str(node.get("id", "")).strip()
            label = html.escape(str(node.get("label", node_id)))
            lines.append(f'    {node_id}["{label}"]')
    for edge in diagram.get("edges", []):
        src = str(edge.get("from", "")).strip()
        dst = str(edge.get("to", "")).strip()
        label = str(edge.get("label", "")).strip()
        kind = str(edge.get("kind", "direct")).strip()
        connector = "-->" if kind == "direct" else "-.->"
        if label:
            lines.append(f"    {src} {connector}|{html.escape(label)}| {dst}")
        else:
            lines.append(f"    {src} {connector} {dst}")
    lines.append("    classDef controller fill:#0c1f34,stroke:#27506c,color:#f5f9ff;")
    lines.append("    classDef primary_inference fill:#0f2d27,stroke:#2b5a52,color:#f5f9ff;")
    lines.append("    classDef data_plane fill:#0a1525,stroke:#27506c,color:#f5f9ff;")
    lines.append("    classDef executed fill:#3b2506,stroke:#fbbf24,color:#fff7d6,stroke-width:3px;")
    lines.append("    classDef ingestStage fill:#0b1d33,stroke:#67b7ff,color:#eef6ff,stroke-width:2px;")
    lines.append("    classDef plannerStage fill:#122742,stroke:#79c3ff,color:#eef6ff,stroke-width:2px;")
    lines.append("    classDef writerStage fill:#103328,stroke:#39d49d,color:#effff8,stroke-width:2px;")
    lines.append("    classDef reviewStage fill:#33270f,stroke:#ffca62,color:#fff7e6,stroke-width:2px;")
    lines.append("    classDef validationStage fill:#3a2217,stroke:#ff9966,color:#fff4ed,stroke-width:2px;")
    lines.append("    classDef executionStage fill:#12263d,stroke:#63b3ff,color:#eef6ff,stroke-width:2px;")
    lines.append("    classDef summaryStage fill:#1d2a3d,stroke:#93b4d8,color:#eef6ff,stroke-width:2px;")
    lines.append("    classDef controllerGroup fill:#081423,stroke:#315a79,color:#cfe8ff;")
    lines.append("    classDef primaryGroup fill:#0a1d1a,stroke:#2f6c60,color:#d5fff0;")
    lines.append("    classDef dataGroup fill:#09111d,stroke:#315a79,color:#dbeafe;")
    groups: dict[str, list[str]] = defaultdict(list)
    for node in nodes:
        groups[str(node.get("group", ""))].append(str(node.get("id", "")).strip())
    for group, node_ids in groups.items():
        if group and node_ids:
            lines.append(f"    class {','.join(node_ids)} {group};")
    if executed_nodes:
        executed_node_ids = [node_id for node_id in executed_nodes if node_id]
        if executed_node_ids:
            lines.append(f"    class {','.join(executed_node_ids)} executed;")
    stage_classes = {
        "ingestStage": ["ingest_question", "guardrail"],
        "plannerStage": ["planner"],
        "writerStage": ["writer"],
        "reviewStage": ["security_review", "peer_review", "peer_review_2", "evidence_review"],
        "validationStage": ["validate_final_plan"],
        "executionStage": ["run_tool"],
        "summaryStage": ["summarize", "finalize"],
    }
    node_ids_present = {str(node.get("id", "")).strip() for node in nodes}
    for cls, ids in stage_classes.items():
        present = [node_id for node_id in ids if node_id in node_ids_present]
        if present:
            lines.append(f"    class {','.join(present)} {cls};")
    if use_subgraphs:
        if groups.get("controller"):
            lines.append("    class controller controllerGroup;")
        if groups.get("primary_inference"):
            lines.append("    class primary_inference primaryGroup;")
        if groups.get("data_plane"):
            lines.append("    class data_plane dataGroup;")
    return '<div class="mermaid">' + "\n".join(lines) + "</div>"


def _latest_stage_overlay() -> tuple[str, set[str]]:
    payload = _latest_multi_model_run_payload()
    if not payload:
        return (
            '<div class="lg-muted">No multi-model run artifact found yet. Run a live investigation or <code>make multi-model-run</code> first.</div>',
            set(),
        )
    result = payload.get("result", {}) if isinstance(payload.get("result", {}), dict) else {}
    stage_logs = result.get("stage_logs", []) if isinstance(result.get("stage_logs", []), list) else []
    stage_map = {
        "guardrail": "guardrail",
        "planner": "planner",
        "writer": "writer",
        "reviewer": "security_review",
        "peer_review_1": "peer_review",
        "peer_review_2": "peer_review_2",
        "validation": "validate_final_plan",
        "execution": "run_tool",
        "evidence_review": "evidence_review",
        "summary": "summarize",
    }
    executed_nodes: set[str] = set()
    cards: list[str] = []
    for entry in stage_logs:
        if not isinstance(entry, dict):
            continue
        stage = str(entry.get("stage", "")).strip()
        mapped = stage_map.get(stage, "")
        if mapped:
            executed_nodes.add(mapped)
        title = str(entry.get("title", stage)).strip() or stage
        duration = int(entry.get("duration_ms", 0) or 0)
        details = entry.get("details", []) if isinstance(entry.get("details", []), list) else []
        cards.append(
            '<div class="lg-run-card">'
            f'<div class="lg-run-head"><span class="lg-run-stage">{html.escape(stage)}</span><span class="lg-run-ms">{duration} ms</span></div>'
            f'<div class="lg-run-title">{html.escape(title)}</div>'
            + ("".join(f'<div class="lg-run-detail">{html.escape(str(item))}</div>' for item in details[:3]))
            + "</div>"
        )
    meta = (
        f'<div class="lg-meta">Latest artifact: <code>{html.escape(str(payload.get("_artifact_path", "")))}</code></div>'
        f'<div class="lg-meta">Intent: <code>{html.escape(str(result.get("intent", "")))}</code> | '
        f'Tool: <code>{html.escape(str(result.get("selected_tool", "")))}</code> | '
        f'Rows: <code>{html.escape(str(result.get("rows_returned", 0)))}</code> | '
        f'Skip peer review: <code>{html.escape(str(result.get("skip_peer_review", False)).lower())}</code></div>'
    )
    body = meta + '<div class="lg-run-grid">' + "".join(cards) + "</div>"
    return body, executed_nodes


def _experiment_summary_block() -> str:
    payload = _latest_langgraph_topology_eval_payload()
    if not payload:
        return '<div class="lg-muted">No topology eval artifact found yet. Run <code>make langgraph-topology-eval</code> to populate experiment rankings.</div>'
    experiments = payload.get("experiments", []) if isinstance(payload.get("experiments", []), list) else []
    rows: list[str] = []
    for item in experiments[:6]:
        if not isinstance(item, dict):
            continue
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(str(item.get('id', '')))}</code></td>"
            f"<td>{float(item.get('avg_score', 0)):.2f}</td>"
            f"<td>{float(item.get('support_rate_pct', 0)):.1f}%</td>"
            f"<td>{float(item.get('intent_match_rate_pct', 0)):.1f}%</td>"
            f"<td>{float(item.get('avg_latency_ms', 0)):.0f}</td>"
            f"<td>{float(item.get('skip_peer_rate_pct', 0)):.1f}%</td>"
            "</tr>"
        )
    return (
        f'<div class="lg-meta">Latest eval artifact: <code>{html.escape(str(payload.get("_artifact_path", "")))}</code></div>'
        '<div class="lg-table-wrap"><table class="lg-table"><thead><tr>'
        '<th>Experiment</th><th>Avg Score</th><th>Support</th><th>Intent Match</th><th>Avg Latency ms</th><th>Skip Peer</th>'
        '</tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _admin_onboarding_modal(user: dict[str, Any] | None) -> str:
    if not isinstance(user, dict):
        return ""
    role = str(user.get("role", "")).strip().lower()
    if role != "admin":
        return ""
    if bool(user.get("admin_onboarding_skip", False)):
        return ""
    return (
        '<div id="smith-welcome-modal" class="welcome-modal-backdrop" aria-hidden="true">'
        '<div class="welcome-modal" role="dialog" aria-modal="true" aria-labelledby="smith-welcome-title">'
        '<div class="welcome-kicker">First Time?</div>'
        '<h2 id="smith-welcome-title" class="welcome-title">Open Configuration now?</h2>'
        '<p class="welcome-copy">If this is your first admin sign-in, head to Configuration to validate endpoints, assign models, and complete the setup flow.</p>'
        '<div class="welcome-actions">'
        '<button id="smith-welcome-go" class="welcome-btn primary" type="button">Yes</button>'
        '<button id="smith-welcome-skip" class="welcome-btn" type="button">Skip</button>'
        '<button id="smith-welcome-snooze" class="welcome-btn" type="button">Snooze Indefinitely</button>'
        "</div>"
        "</div>"
        "</div>"
    )


def _running_in_container() -> bool:
    return Path("/.dockerenv").exists()


def _environment_profile_exists() -> bool:
    return ENV_PROFILE_PATH.exists() and ENV_PROFILE_PATH.is_file()


def _environment_profile_bootstrap_in_progress() -> bool:
    if not ENV_PROFILE_BOOTSTRAP_LOCK.exists():
        return False
    try:
        age = time.time() - ENV_PROFILE_BOOTSTRAP_LOCK.stat().st_mtime
    except Exception:
        return False
    if age > 30 * 60:
        try:
            ENV_PROFILE_BOOTSTRAP_LOCK.unlink()
        except Exception:
            pass
        return False
    return True


def _can_show_environment_page() -> bool:
    if not _running_in_container():
        return True
    return _environment_profile_exists()


def _personalization_in_progress() -> bool:
    if not PERSONALIZATION_LOCK.exists():
        return False
    try:
        age = time.time() - PERSONALIZATION_LOCK.stat().st_mtime
    except Exception:
        return False
    if age > 60 * 60:
        try:
            PERSONALIZATION_LOCK.unlink()
        except Exception:
            pass
        return False
    return True


def _environment_profile_refresh_in_progress() -> bool:
    if not ENV_PROFILE_REFRESH_LOCK.exists():
        return False
    try:
        age = time.time() - ENV_PROFILE_REFRESH_LOCK.stat().st_mtime
    except Exception:
        return False
    if age > 2 * 60 * 60:
        try:
            ENV_PROFILE_REFRESH_LOCK.unlink()
        except Exception:
            pass
        return False
    return True


def _runtime_mode_label() -> str:
    if not _running_in_container():
        return "host_runtime"
    mounts_path = Path("/app/config")
    return "docker_container" if mounts_path.exists() else "container_runtime"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _environment_profile_bootstrap_state() -> str:
    if _environment_profile_exists():
        return "ready"
    if _environment_profile_bootstrap_in_progress():
        return "in_progress"
    return "pending"


def _personalization_status() -> dict[str, Any]:
    state = _read_json(PERSONALIZATION_STATE)
    if state:
        if PERSONALIZATION_LOG.exists():
            try:
                state["log_path"] = display_path(PERSONALIZATION_LOG)
                state["output"] = PERSONALIZATION_LOG.read_text(encoding="utf-8")[-12000:]
            except Exception:
                pass
        if SPL_SKILLPACK_PATH.exists() and "path" not in state:
            state["path"] = display_path(SPL_SKILLPACK_PATH)
        return state
    if _personalization_in_progress():
        return {
            "state": "in_progress",
            "detail": "Personalization build is running.",
            "progress_pct": 5,
            "phase": "starting",
            "output": "",
            "log_path": display_path(PERSONALIZATION_LOG),
        }
    if not _environment_profile_exists():
        return {
            "state": "blocked",
            "detail": "Data Domains must exist before personalization can build environment-aware SPL guidance.",
        }
    if SPL_SKILLPACK_PATH.exists():
        try:
            stat = SPL_SKILLPACK_PATH.stat()
            return {
                "state": "ready",
                "detail": "Environment-aware SPL personalization is available.",
                "path": display_path(SPL_SKILLPACK_PATH),
                "updated_epoch": int(stat.st_mtime),
                "progress_pct": 100,
                "phase": "complete",
            }
        except Exception:
            return {
                "state": "ready",
                "detail": "Environment-aware SPL personalization is available.",
                "path": display_path(SPL_SKILLPACK_PATH),
                "progress_pct": 100,
                "phase": "complete",
            }
    return {
        "state": "pending",
        "detail": "Ready to build environment-aware SPL personalization from the current Data Domains profile.",
        "progress_pct": 0,
        "phase": "idle",
        "output": "",
        "log_path": display_path(PERSONALIZATION_LOG),
    }


def _environment_profile_refresh_status() -> dict[str, Any]:
    state = _read_json(ENV_PROFILE_REFRESH_STATE)
    if state:
        if ENV_PROFILE_REFRESH_LOG.exists():
            try:
                state["log_path"] = display_path(ENV_PROFILE_REFRESH_LOG)
                state["output"] = ENV_PROFILE_REFRESH_LOG.read_text(encoding="utf-8")[-12000:]
            except Exception:
                pass
        return state
    if _environment_profile_refresh_in_progress():
        return {
            "state": "in_progress",
            "progress_pct": 5,
            "detail": "Environment profile refresh is running.",
            "output": "",
            "log_path": display_path(ENV_PROFILE_REFRESH_LOG),
        }
    detail = "Ready to refresh Data Domains and rebuild environment-aware SPL artifacts."
    if not _environment_profile_exists():
        detail = "No Data Domains profile exists yet. Run a refresh after Splunk MCP validates."
    return {
        "state": "pending",
        "progress_pct": 0,
        "detail": detail,
        "output": "",
        "log_path": display_path(ENV_PROFILE_REFRESH_LOG),
    }


def _run_environment_profile_bootstrap() -> None:
    ENV_PROFILE_BOOTSTRAP_LOCK.parent.mkdir(parents=True, exist_ok=True)
    try:
        ENV_PROFILE_BOOTSTRAP_LOCK.write_text(str(int(time.time())), encoding="utf-8")
    except Exception:
        return
    try:
        subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "scripts" / "build_environment_profile.py"), "--snapshot"],
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    finally:
        try:
            ENV_PROFILE_BOOTSTRAP_LOCK.unlink()
        except Exception:
            pass


def _run_personalization_refresh() -> None:
    PERSONALIZATION_LOCK.parent.mkdir(parents=True, exist_ok=True)
    try:
        PERSONALIZATION_LOCK.write_text(str(int(time.time())), encoding="utf-8")
    except Exception:
        return
    try:
        PERSONALIZATION_LOG.write_text("", encoding="utf-8")
    except Exception:
        pass
    _set_personalization_state("in_progress", "Starting environment-aware SPL personalization...", 8, "starting")
    try:
        commands = [
            (
                "[personalization] refresh environment profile\n",
                [sys.executable, str(PROJECT_ROOT / "scripts" / "build_environment_profile.py"), "--snapshot"],
            ),
            (
                "[personalization] build skillpack\n",
                [sys.executable, str(PROJECT_ROOT / "scripts" / "build_spl_skillpack.py")],
            ),
        ]
        for banner, command in commands:
            try:
                with PERSONALIZATION_LOG.open("a", encoding="utf-8") as handle:
                    handle.write(banner)
            except Exception:
                pass
            phase_update = _personalization_progress_for_line(banner)
            if phase_update:
                pct, phase, detail = phase_update
                _set_personalization_state("in_progress", detail, pct, phase)
            proc = subprocess.Popen(
                command,
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            if proc.stdout is not None:
                for raw_line in proc.stdout:
                    try:
                        with PERSONALIZATION_LOG.open("a", encoding="utf-8") as handle:
                            handle.write(raw_line)
                    except Exception:
                        pass
                    phase_update = _personalization_progress_for_line(raw_line)
                    if phase_update:
                        pct, phase, detail = phase_update
                        _set_personalization_state("in_progress", detail, pct, phase)
                proc.stdout.close()
            code = proc.wait()
            if code != 0:
                _set_personalization_state("error", f"Environment-aware SPL personalization failed with exit code {code}.", 100, "failed", returncode=code)
                return
        try:
            with PERSONALIZATION_LOG.open("a", encoding="utf-8") as handle:
                handle.write("[personalization] complete\n")
        except Exception:
            pass
        _set_personalization_state("ready", "Environment-aware SPL personalization completed successfully.", 100, "complete", returncode=0)
    except Exception as exc:
        try:
            with PERSONALIZATION_LOG.open("a", encoding="utf-8") as handle:
                handle.write(f"\n[personalization] exception: {exc}\n")
        except Exception:
            pass
        _set_personalization_state("error", f"Environment-aware SPL personalization failed: {exc}", 100, "failed")
    finally:
        try:
            PERSONALIZATION_LOCK.unlink()
        except Exception:
            pass


def _set_env_refresh_state(state: str, detail: str, progress_pct: int, phase: str, returncode: int | None = None) -> None:
    payload: dict[str, Any] = {
        "state": state,
        "detail": detail,
        "progress_pct": max(0, min(100, int(progress_pct))),
        "phase": phase,
        "updated_epoch": int(time.time()),
    }
    if returncode is not None:
        payload["returncode"] = int(returncode)
    _write_json(ENV_PROFILE_REFRESH_STATE, payload)


def _set_personalization_state(state: str, detail: str, progress_pct: int, phase: str, returncode: int | None = None) -> None:
    payload: dict[str, Any] = {
        "state": state,
        "detail": detail,
        "progress_pct": max(0, min(100, int(progress_pct))),
        "phase": phase,
        "updated_epoch": int(time.time()),
    }
    if SPL_SKILLPACK_PATH.exists():
        payload["path"] = display_path(SPL_SKILLPACK_PATH)
    if returncode is not None:
        payload["returncode"] = int(returncode)
    _write_json(PERSONALIZATION_STATE, payload)


def _phase_progress_for_line(line: str) -> tuple[int, str, str] | None:
    text = line.strip()
    if not text:
        return None
    if "[env-profile-build]" in text:
        return (24, "env_profile_build", text)
    if "build_environment_profile.py" in text:
        return (34, "env_profile_build", text)
    if "[env-profile-check]" in text:
        return (60, "env_profile_check", text)
    if "check_environment_profile_freshness.py" in text:
        return (70, "env_profile_check", text)
    if "[spl-skillpack-refresh]" in text:
        return (82, "spl_skillpack_refresh", text)
    if "build_spl_skillpack.py" in text:
        return (90, "spl_skillpack_refresh", text)
    if "[env-profile-refresh] complete" in text:
        return (100, "complete", "Environment profile refresh completed.")
    return None


def _personalization_progress_for_line(line: str) -> tuple[int, str, str] | None:
    text = line.strip()
    if not text:
        return None
    if "build_environment_profile.py" in text or "[personalization] refresh environment profile" in text:
        return (28, "env_profile_build", "Refreshing environment profile for personalization.")
    if "build_spl_skillpack.py" in text or "[personalization] build skillpack" in text:
        return (76, "spl_skillpack_refresh", "Rebuilding environment-aware SPL skillpack.")
    if "[personalization] complete" in text:
        return (100, "complete", "Environment-aware SPL personalization completed.")
    return None


def _run_environment_profile_refresh() -> None:
    ENV_PROFILE_REFRESH_LOCK.parent.mkdir(parents=True, exist_ok=True)
    try:
        ENV_PROFILE_REFRESH_LOCK.write_text(str(int(time.time())), encoding="utf-8")
    except Exception:
        return
    try:
        ENV_PROFILE_REFRESH_LOG.write_text("", encoding="utf-8")
    except Exception:
        pass
    _set_env_refresh_state("in_progress", "Starting Data Domains refresh...", 6, "starting")
    try:
        proc = subprocess.Popen(
            ["make", "env-profile-refresh"],
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        if proc.stdout is not None:
            for raw_line in proc.stdout:
                try:
                    with ENV_PROFILE_REFRESH_LOG.open("a", encoding="utf-8") as handle:
                        handle.write(raw_line)
                except Exception:
                    pass
                phase_update = _phase_progress_for_line(raw_line)
                if phase_update:
                    pct, phase, detail = phase_update
                    _set_env_refresh_state("in_progress", detail, pct, phase)
            proc.stdout.close()
        code = proc.wait()
        if code == 0:
            _set_env_refresh_state("ready", "Environment profile refresh completed successfully.", 100, "complete", returncode=0)
            if SPL_SKILLPACK_PATH.exists():
                _set_personalization_state(
                    "ready",
                    "Environment-aware SPL personalization is current from the latest Data Domains refresh.",
                    100,
                    "complete",
                    returncode=0,
                )
        else:
            _set_env_refresh_state("error", f"Environment profile refresh failed with exit code {code}.", 100, "failed", returncode=code)
    except Exception as exc:
        try:
            with ENV_PROFILE_REFRESH_LOG.open("a", encoding="utf-8") as handle:
                handle.write(f"\n[web-ui-refresh] exception: {exc}\n")
        except Exception:
            pass
        _set_env_refresh_state("error", f"Environment profile refresh failed: {exc}", 100, "failed")
    finally:
        try:
            ENV_PROFILE_REFRESH_LOCK.unlink()
        except Exception:
            pass


def _maybe_trigger_environment_profile_bootstrap(validation: dict[str, Any]) -> str:
    if _environment_profile_exists():
        return "ready"
    checks = validation.get("checks", []) if isinstance(validation, dict) else []
    mcp_ok = any(
        isinstance(check, dict)
        and str(check.get("name", "")).strip() == "splunk_mcp"
        and str(check.get("status", "")).strip() == "ok"
        for check in checks
    )
    if not mcp_ok:
        return "pending"
    if _environment_profile_bootstrap_in_progress():
        return "in_progress"
    threading.Thread(target=_run_environment_profile_bootstrap, daemon=True).start()
    return "in_progress"


def _config_snapshot() -> dict[str, Any]:
    _lines, file_values = parse_env_file(UI_ENV_PATH)
    values = {key: file_values.get(key, os.getenv(key, "")).strip() for key in CONFIG_EDITABLE_KEYS}
    if not values.get("OLLAMA_HOST"):
        values["OLLAMA_HOST"] = get_ollama_host()
    if not values.get("SPLUNK_BASE_URL"):
        values["SPLUNK_BASE_URL"] = get_splunk_base_url()
    if not values.get("SPLUNK_MCP_URL"):
        values["SPLUNK_MCP_URL"] = get_splunk_mcp_url()
    if not values.get("EDGE_LLM_ENABLED"):
        values["EDGE_LLM_ENABLED"] = "1" if get_edge_llm_enabled() else "0"
    if not values.get("EDGE_LLM_HOST"):
        values["EDGE_LLM_HOST"] = get_edge_llm_host()
    if not values.get("EDGE_LLM_MODEL"):
        values["EDGE_LLM_MODEL"] = get_edge_llm_model()
    if not values.get("EDGE_LLM_ROLE"):
        values["EDGE_LLM_ROLE"] = get_edge_llm_role()
    if not values.get("EDGE_LLM_TIMEOUT_SEC"):
        values["EDGE_LLM_TIMEOUT_SEC"] = get_edge_llm_timeout_sec()
    expected_models = _default_expected_models()
    models = [values.get(key, "") for key in EXPECTED_MODEL_KEYS if values.get(key, "").strip()]
    unique_models: list[str] = []
    for model in models:
        if model not in unique_models:
            unique_models.append(model)
    token = values.get("SPLUNK_LAB_BEARER_TOKEN", "")
    edge_enabled = values.get("EDGE_LLM_ENABLED", "0") == "1"
    edge_host = values.get("EDGE_LLM_HOST", "").strip().rstrip("/")
    edge_model = values.get("EDGE_LLM_MODEL", "").strip()
    splunk_mcp_config = {
        "mcpServers": {
            "splunk-mcp-server": {
                "command": "npx",
                "args": [
                    "-y",
                    "mcp-remote",
                    values.get("SPLUNK_MCP_URL", ""),
                    "--header",
                    f"Authorization: Bearer {token}",
                ],
            }
        }
    }
    config_display = display_path(UI_ENV_PATH)
    return {
        "runtime_mode": _runtime_mode_label(),
        "config_path": config_display,
        "environment_profile_status": _environment_profile_bootstrap_state(),
        "environment_profile_refresh": _environment_profile_refresh_status(),
        "personalization": _personalization_status(),
        "values": values,
        "expected_models": expected_models,
        "ollama_pull_commands": [f"ollama pull {model}" for model in expected_models],
        "assigned_model_pull_commands": [f"ollama pull {model}" for model in unique_models],
        "ollama_available_models": _discover_ollama_models(values.get("OLLAMA_HOST", get_ollama_host())),
        "edge_ollama_available_models": _discover_ollama_models(edge_host) if edge_enabled and edge_host else [],
        "splunk_mcp_config_json": json.dumps(splunk_mcp_config, indent=2),
        "host_restart_command": "make dev",
        "docker_wrapper_restart_command": "make docker-down && AGTSMITH_UI_PORT=8788 make docker-up",
        "docker_deploy_restart_command": "make docker-deploy-down && AGTSMITH_DEPLOY_PORT=8789 make docker-deploy-up",
        "setup_guide_path": "runbooks/initial_setup.md",
        "connectivity_checks": {
            "ollama_tags": f"curl {values.get('OLLAMA_HOST', get_ollama_host())}/api/tags",
            "edge_ollama_tags": f"curl {edge_host}/api/tags" if edge_enabled and edge_host else "",
            "splunk_mcp": (
                "curl -k -i -H "
                f"\"Authorization: Bearer {token}\" "
                f"{values.get('SPLUNK_MCP_URL', get_splunk_mcp_url())}"
            ),
        },
        "edge_helper": {
            "enabled": edge_enabled,
            "host": edge_host,
            "model": edge_model,
            "role": values.get("EDGE_LLM_ROLE", "").strip(),
            "timeout_sec": values.get("EDGE_LLM_TIMEOUT_SEC", "").strip(),
            "pull_command": f"ollama pull {edge_model}" if edge_enabled and edge_model else "",
        },
    }


def _http_json(url: str, headers: dict[str, str] | None = None, timeout: float = 8.0) -> tuple[int, Any]:
    req = urllib.request.Request(url, headers=headers or {})
    context = ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        return int(getattr(resp, "status", 200)), json.loads(raw) if raw.strip() else {}


def _discover_ollama_models(ollama_host: str) -> list[str]:
    host = str(ollama_host or "").strip().rstrip("/")
    if not host:
        return []
    try:
        _status, payload = _http_json(f"{host}/api/tags")
    except Exception:
        return []
    models = payload.get("models", []) if isinstance(payload, dict) else []
    names: list[str] = []
    for item in models:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if name:
            names.append(name)
    return names


def _validate_runtime_config(values: dict[str, str]) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    summary = {"ok": 0, "warn": 0, "error": 0}
    available_models: list[str] = []
    edge_available_models: list[str] = []
    expected_models = _default_expected_models()

    def add_result(name: str, status: str, detail: str, extra: dict[str, Any] | None = None) -> None:
        summary[status] += 1
        entry = {"name": name, "status": status, "detail": detail}
        if extra:
            entry.update(extra)
        results.append(entry)

    ollama_host = str(values.get("OLLAMA_HOST", "")).strip().rstrip("/")
    try:
        code, payload = _http_json(f"{ollama_host}/api/tags")
        models = payload.get("models", []) if isinstance(payload, dict) else []
        installed = sorted(
            str(item.get("name", "")).strip() for item in models if isinstance(item, dict) and str(item.get("name", "")).strip()
        )
        available_models = installed
        add_result("ollama_api", "ok", f"Ollama reachable ({code}); discovered {len(installed)} model(s).", {"models": installed})
        expected = list(expected_models)
        missing = [model for model in expected if model not in installed]
        if missing:
            add_result("ollama_expected_models", "warn", "Some expected models are not installed on the Ollama host.", {"missing_models": missing})
        else:
            add_result("ollama_expected_models", "ok", "All expected models are installed on the Ollama host.")
    except Exception as exc:
        add_result("ollama_api", "error", f"Could not reach Ollama API: {type(exc).__name__}: {exc}")

    missing_assignments = [key for key in EXPECTED_MODEL_KEYS if not str(values.get(key, "")).strip()]
    if missing_assignments:
        add_result(
            "model_assignments",
            "error",
            "One or more runtime roles do not have an assigned model. Save Configuration after validation to auto-fill supported defaults, or assign models manually.",
            {"missing_assignments": missing_assignments},
        )
    else:
        add_result("model_assignments", "ok", "All runtime roles currently have assigned models.")

    edge_enabled = str(values.get("EDGE_LLM_ENABLED", "0")).strip() == "1"
    edge_host = str(values.get("EDGE_LLM_HOST", "")).strip().rstrip("/")
    edge_model = str(values.get("EDGE_LLM_MODEL", "")).strip()
    if edge_enabled:
        if not edge_host:
            add_result("edge_helper", "error", "Edge helper is enabled but EDGE_LLM_HOST is empty.")
        elif not edge_model:
            add_result("edge_helper", "error", "Edge helper is enabled but EDGE_LLM_MODEL is empty.")
        else:
            try:
                code, payload = _http_json(f"{edge_host}/api/tags")
                models = payload.get("models", []) if isinstance(payload, dict) else []
                installed = sorted(
                    str(item.get("name", "")).strip()
                    for item in models
                    if isinstance(item, dict) and str(item.get("name", "")).strip()
                )
                edge_available_models = installed
                if edge_model in installed:
                    add_result(
                        "edge_helper",
                        "ok",
                        f"Edge helper reachable ({code}); model '{edge_model}' is installed.",
                        {"models": installed},
                    )
                else:
                    add_result(
                        "edge_helper",
                        "warn",
                        f"Edge helper reachable ({code}) but the assigned model '{edge_model}' is not installed.",
                        {"models": installed, "missing_models": [edge_model]},
                    )
            except Exception as exc:
                add_result("edge_helper", "error", f"Could not reach edge helper API: {type(exc).__name__}: {exc}")
    else:
        add_result("edge_helper", "ok", "Edge helper is disabled by operator; the primary inference host handles all planning and writing stages.")

    splunk_base = str(values.get("SPLUNK_BASE_URL", "")).strip().rstrip("/")
    if splunk_base:
        try:
            req = urllib.request.Request(splunk_base, method="GET")
            context = ssl._create_unverified_context()
            with urllib.request.urlopen(req, timeout=8.0, context=context) as resp:
                add_result("splunk_base", "ok", f"Splunk base URL reachable ({getattr(resp, 'status', 200)}).")
        except urllib.error.HTTPError as exc:
            add_result("splunk_base", "ok", f"Splunk base URL reachable and returned HTTP {exc.code}.")
        except Exception as exc:
            add_result("splunk_base", "error", f"Could not reach Splunk base URL: {type(exc).__name__}: {exc}")

    splunk_mcp = str(values.get("SPLUNK_MCP_URL", "")).strip()
    token = str(values.get("SPLUNK_LAB_BEARER_TOKEN", "")).strip()
    if splunk_mcp:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            req = urllib.request.Request(splunk_mcp, headers=headers, method="GET")
            context = ssl._create_unverified_context()
            with urllib.request.urlopen(req, timeout=8.0, context=context) as resp:
                add_result("splunk_mcp", "ok", f"Splunk MCP reachable ({getattr(resp, 'status', 200)}).")
        except urllib.error.HTTPError as exc:
            if exc.code == 405:
                add_result("splunk_mcp", "ok", "Splunk MCP endpoint is reachable and returned HTTP 405, which is expected for a non-MCP GET probe.")
            elif exc.code in {401, 403}:
                add_result("splunk_mcp", "warn", f"Splunk MCP reached but auth failed with HTTP {exc.code}. Check bearer token.")
            else:
                add_result("splunk_mcp", "warn", f"Splunk MCP reached but returned HTTP {exc.code}.")
        except Exception as exc:
            add_result("splunk_mcp", "error", f"Could not reach Splunk MCP endpoint: {type(exc).__name__}: {exc}")

    env_state = _environment_profile_bootstrap_state()
    runtime_label = "container runtime" if _running_in_container() else "host runtime"
    if env_state == "ready":
        add_result("environment_profile", "ok", f"Data Domains profile is available for the {runtime_label}.")
    elif env_state == "in_progress":
        add_result("environment_profile", "warn", "Initial Data Domains build is running after successful Splunk MCP validation.")
    else:
        add_result("environment_profile", "warn", "Data Domains will be initialized after Splunk MCP validates successfully.")

    return {
        "summary": summary,
        "checks": results,
        "expected_models": expected_models,
        "ollama_available_models": available_models,
        "edge_ollama_available_models": edge_available_models,
    }


def _auth_enabled() -> bool:
    value = str(os.getenv("SOC_UI_AUTH_ENABLED", "1")).strip().lower()
    return value not in {"0", "false", "no", "off"}


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return PASSWORD_HASH_PREFIX + base64.b64encode(salt + digest).decode("ascii")


def _password_matches(stored: str, candidate: str) -> bool:
    if not stored:
        return False
    if stored.startswith(PASSWORD_HASH_PREFIX) or stored.startswith(LEGACY_PASSWORD_HASH_PREFIX):
        prefix = PASSWORD_HASH_PREFIX if stored.startswith(PASSWORD_HASH_PREFIX) else LEGACY_PASSWORD_HASH_PREFIX
        payload = stored[len(prefix) :]
        try:
            raw = base64.b64decode(payload.encode("ascii"))
        except Exception:
            return False
        if len(raw) < 48:
            return False
        salt = raw[:16]
        expected = raw[16:]
        actual = hashlib.pbkdf2_hmac("sha256", candidate.encode("utf-8"), salt, 200_000)
        return hmac.compare_digest(expected, actual)
    return hmac.compare_digest(stored, candidate)


def _auth_users_env_value(users: dict[str, dict[str, str]]) -> str:
    payload: list[dict[str, str]] = []
    for username in sorted(users.keys()):
        item = users.get(username, {})
        password = str(item.get("password", "")).strip()
        role = str(item.get("role", "analyst")).strip().lower()
        if not username or not password:
            continue
        if role not in ALLOWED_APP_ROLES:
            role = "analyst"
        payload.append({"username": username, "password": password, "role": role})
    return json.dumps(payload, separators=(",", ":"))


def _persist_auth_users(users: dict[str, dict[str, str]]) -> None:
    env_value = _auth_users_env_value(users)
    write_env_file(
        {
            "SOC_UI_AUTH_USERS_JSON": env_value,
            "SOC_UI_AUTH_ENABLED": "1",
            "SOC_UI_AUTH_INITIALIZED": "1",
        },
        UI_ENV_PATH,
    )
    os.environ["SOC_UI_AUTH_USERS_JSON"] = env_value
    os.environ["SOC_UI_AUTH_ENABLED"] = "1"
    os.environ["SOC_UI_AUTH_INITIALIZED"] = "1"


def _auth_users_for_ui() -> list[dict[str, str]]:
    users = _load_auth_users()
    rows: list[dict[str, str]] = []
    for username in sorted(users.keys()):
        item = users.get(username, {})
        rows.append(
            {
                "username": username,
                "role": str(item.get("role", "analyst")).strip().lower() or "analyst",
                "password_kind": "hashed" if str(item.get("password", "")).startswith(PASSWORD_HASH_PREFIX) else "legacy_plaintext",
            }
        )
    return rows


def _users_snapshot() -> dict[str, Any]:
    return {
        "auth_users": _auth_users_for_ui(),
    }


def _append_query_audit(entry: dict[str, Any]) -> None:
    AUDIT_ROOT.mkdir(parents=True, exist_ok=True)
    with QUERY_AUDIT_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, separators=(",", ":")) + "\n")


def _recent_query_audit(limit: int = 40) -> list[dict[str, Any]]:
    if not QUERY_AUDIT_LOG.exists():
        return []
    try:
        lines = QUERY_AUDIT_LOG.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    items: list[dict[str, Any]] = []
    for raw in reversed(lines[-limit:]):
        try:
            parsed = json.loads(raw)
        except Exception:
            continue
        if isinstance(parsed, dict):
            items.append(parsed)
    return items


def _first_run_setup_required() -> bool:
    _lines, file_values = parse_env_file(UI_ENV_PATH)
    initialized = str(os.getenv("SOC_UI_AUTH_INITIALIZED", file_values.get("SOC_UI_AUTH_INITIALIZED", ""))).strip().lower()
    if initialized in {"1", "true", "yes", "on"}:
        return False
    users_env = str(os.getenv("SOC_UI_AUTH_USERS_JSON", file_values.get("SOC_UI_AUTH_USERS_JSON", ""))).strip()
    if users_env:
        return False
    password = str(os.getenv("SOC_UI_AUTH_PASSWORD", file_values.get("SOC_UI_AUTH_PASSWORD", ""))).strip()
    username = str(os.getenv("SOC_UI_AUTH_USERNAME", file_values.get("SOC_UI_AUTH_USERNAME", ""))).strip()
    if not username or not password:
        return True
    return password in DEFAULT_UI_PASSWORDS


def _load_auth_users() -> dict[str, dict[str, str]]:
    _lines, file_values = parse_env_file(UI_ENV_PATH)
    users_env = str(os.getenv("SOC_UI_AUTH_USERS_JSON", file_values.get("SOC_UI_AUTH_USERS_JSON", ""))).strip()
    users: dict[str, dict[str, str]] = {}

    if users_env:
        try:
            parsed = json.loads(users_env)
            if isinstance(parsed, list):
                for item in parsed:
                    if not isinstance(item, dict):
                        continue
                    username = str(item.get("username", "")).strip()
                    password = str(item.get("password", "")).strip()
                    role = str(item.get("role", "analyst")).strip().lower()
                    if username and password:
                        if role not in ALLOWED_APP_ROLES:
                            role = "analyst"
                        users[username] = {"password": password, "role": role}
            elif isinstance(parsed, dict):
                for username, item in parsed.items():
                    if not isinstance(item, dict):
                        continue
                    password = str(item.get("password", "")).strip()
                    role = str(item.get("role", "analyst")).strip().lower()
                    if username and password:
                        if role not in ALLOWED_APP_ROLES:
                            role = "analyst"
                        users[str(username)] = {"password": password, "role": role}
        except Exception:
            users = {}

    if users:
        return users

    username = str(os.getenv("SOC_UI_AUTH_USERNAME", file_values.get("SOC_UI_AUTH_USERNAME", "analyst"))).strip()
    password = str(os.getenv("SOC_UI_AUTH_PASSWORD", file_values.get("SOC_UI_AUTH_PASSWORD", "changeme123!"))).strip()
    role = str(os.getenv("SOC_UI_AUTH_ROLE", file_values.get("SOC_UI_AUTH_ROLE", "ops"))).strip().lower()
    if role not in ALLOWED_APP_ROLES:
        role = "analyst"
    if username and password:
        users[username] = {"password": password, "role": role}
    return users


def _create_session(username: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with SESSIONS_LOCK:
        SESSIONS[token] = {
            "username": username,
            "role": role,
            "created": now,
            "expires": now + SESSION_TTL_SECONDS,
            "admin_onboarding_skip": False,
        }
    return token


def _get_session(token: str) -> dict[str, Any] | None:
    if not token:
        return None
    now = int(time.time())
    with SESSIONS_LOCK:
        session = SESSIONS.get(token)
        if not session:
            return None
        expires = int(session.get("expires", 0))
        if expires <= now:
            SESSIONS.pop(token, None)
            return None
        return dict(session)


def _delete_session(token: str) -> None:
    if not token:
        return
    with SESSIONS_LOCK:
        SESSIONS.pop(token, None)


def _set_session_admin_onboarding_skip(token: str, skip: bool) -> bool:
    if not token:
        return False
    with SESSIONS_LOCK:
        session = SESSIONS.get(token)
        if not session:
            return False
        session["admin_onboarding_skip"] = bool(skip)
    return True


FAVICON_SVG = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>
<defs>
  <linearGradient id='bg' x1='0' y1='0' x2='1' y2='1'>
    <stop offset='0%' stop-color='#ffffff'/>
    <stop offset='100%' stop-color='#eef2f7'/>
  </linearGradient>
  <linearGradient id='lens' x1='0' y1='0' x2='1' y2='1'>
    <stop offset='0%' stop-color='#020617'/>
    <stop offset='100%' stop-color='#0f172a'/>
  </linearGradient>
  <filter id='glow' x='-20%' y='-20%' width='140%' height='140%'>
    <feGaussianBlur stdDeviation='1.4' result='b'/>
    <feMerge>
      <feMergeNode in='b'/>
      <feMergeNode in='SourceGraphic'/>
    </feMerge>
  </filter>
</defs>
<rect x='2' y='2' width='60' height='60' rx='14' fill='url(#bg)' stroke='#334155' stroke-width='2.4'/>
<path d='M9 24c8-9 38-9 46 0' stroke='#0f172a' stroke-width='3.2' fill='none' stroke-linecap='round'/>
<rect x='10' y='23' width='19' height='14' rx='4' fill='url(#lens)' stroke='#020617' stroke-width='1.8'/>
<rect x='35' y='23' width='19' height='14' rx='4' fill='url(#lens)' stroke='#020617' stroke-width='1.8'/>
<rect x='28' y='28' width='8' height='4' rx='1.5' fill='#111827'/>
<path d='M13 27h13M38 27h13' stroke='#475569' stroke-width='1.2' opacity='0.5'/>
<path d='M14 41h36' stroke='#475569' stroke-width='1.8' opacity='0.9' stroke-linecap='round'/>
<path d='M18 18l6 4M46 18l-6 4' stroke='#1e293b' stroke-width='1.4' opacity='0.9' stroke-linecap='round'/>
</svg>
"""


APP_HTML = """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>A.G.E.N.T. Smith</title>
  <link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg?v=agtsmith1\" />
  <link rel=\"icon\" href=\"/favicon.ico?v=agtsmith1\" />
  <style>
    :root {
      --bg:#0f172a; --card:#111827; --card2:#0b1220; --muted:#9ca3af; --fg:#e5e7eb;
      --accent:#22c55e; --warn:#f59e0b; --link:#93c5fd; --line:#1f2937; --bad:#ef4444; --ok:#10b981;
    }
    html {
      min-height:100%;
      background: linear-gradient(140deg,#0b1220 0%,#111827 65%,#0a1f16 100%);
      background-repeat:no-repeat;
      background-size:cover;
    }
    body {
      margin:0;
      min-height:100vh;
      font-family: "Trebuchet MS", "Segoe UI", "Helvetica Neue", Helvetica, sans-serif;
      background: linear-gradient(140deg,#0b1220,#111827 65%,#0a1f16);
      background-repeat:no-repeat;
      background-size:cover;
      color:var(--fg);
    }
    .wrap { max-width: 1220px; min-height:calc(100vh - 48px); margin: 24px auto; padding: 0 16px 24px; box-sizing:border-box; }
    .topnav {
      display:flex;
      flex-wrap:nowrap;
      gap:4px;
      margin-bottom:18px;
      justify-content:flex-start;
      align-items:stretch;
      padding:6px;
      border:1px solid rgba(34,66,92,.44);
      border-radius:22px;
      background:linear-gradient(180deg, rgba(7,18,31,.82), rgba(5,12,23,.72));
      box-shadow:0 18px 34px rgba(0,0,0,.18), inset 0 1px 0 rgba(255,255,255,.03);
      backdrop-filter:blur(16px);
    }
    .nav-item {
      position:relative;
      display:flex;
      flex-direction:column;
      justify-content:center;
      gap:2px;
      min-width:0;
      flex:1 1 0;
      text-decoration:none;
      border:1px solid transparent;
      border-radius:16px;
      padding:8px 9px 9px;
      background:linear-gradient(180deg, rgba(255,255,255,.015), rgba(255,255,255,.008));
      color:#dce9f8;
      box-shadow:inset 0 1px 0 rgba(255,255,255,.018);
      transition:transform .16s ease, border-color .16s ease, box-shadow .16s ease, background .16s ease, color .16s ease;
      overflow:hidden;
    }
    .nav-item-dropdown { overflow:visible; }
    .nav-trigger {
      display:flex;
      flex-direction:column;
      justify-content:center;
      gap:2px;
      min-width:0;
      text-decoration:none;
      color:inherit;
    }
    .nav-item::after{
      content:"";
      position:absolute;
      left:12px;
      right:12px;
      bottom:0;
      height:2px;
      border-radius:999px;
      background:linear-gradient(90deg, rgba(96,165,250,.82), rgba(45,212,191,.82));
      opacity:0;
      transform:scaleX(.5);
      transition:opacity .16s ease, transform .16s ease;
    }
    .nav-item:hover {
      border-color:rgba(81,127,163,.46);
      background:linear-gradient(180deg, rgba(18,35,53,.74), rgba(9,21,34,.66));
      transform:translateY(-1px);
      box-shadow:0 10px 18px rgba(2,6,23,.16), inset 0 1px 0 rgba(255,255,255,.03);
      color:#f8fbff;
    }
    .nav-item:hover::after{
      opacity:.58;
      transform:scaleX(1);
    }
    .nav-item.active {
      border-color:rgba(61,105,136,.5);
      background:linear-gradient(180deg, rgba(17,37,57,.92), rgba(10,24,39,.9));
      color:#ecfdf5;
      box-shadow:0 12px 22px rgba(2,6,23,.18), inset 0 1px 0 rgba(255,255,255,.04);
    }
    .nav-item.active::after{
      opacity:1;
      transform:scaleX(1);
    }
    .nav-kicker { font-size:9px; color:#7ea2c1; text-transform:uppercase; letter-spacing:.12em; font-weight:800; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .nav-item.active .nav-kicker { color:#8fd3ff; }
    .nav-label { font-size:13px; font-weight:900; line-height:1.15; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .nav-submenu {
      position:absolute;
      top:calc(100% + 10px);
      left:0;
      min-width:320px;
      display:grid;
      gap:0;
      padding:8px;
      border:1px solid rgba(46,82,110,.8);
      border-radius:16px;
      background:linear-gradient(180deg, rgba(10,22,36,.98), rgba(6,14,24,.96));
      box-shadow:0 18px 34px rgba(0,0,0,.32), inset 0 1px 0 rgba(255,255,255,.03);
      opacity:0;
      visibility:hidden;
      transform:translateY(6px);
      transition:opacity .14s ease, transform .14s ease, visibility .14s ease;
      z-index:40;
    }
    .nav-item-dropdown:hover .nav-submenu,
    .nav-item-dropdown:focus-within .nav-submenu {
      opacity:1;
      visibility:visible;
      transform:translateY(0);
    }
    .nav-submenu-item {
      display:grid;
      gap:3px;
      padding:10px 12px;
      border-radius:10px;
      text-decoration:none;
      color:#e5eef8;
      transition:background .14s ease, transform .14s ease;
    }
    .nav-submenu-item:hover {
      background:linear-gradient(180deg, rgba(18,37,57,.92), rgba(10,24,39,.88));
      transform:translateX(1px);
    }
    .nav-submenu-title {
      font-size:13px;
      font-weight:900;
      line-height:1.2;
      color:#eff6ff;
    }
    .nav-submenu-copy {
      font-size:12px;
      line-height:1.4;
      color:#9fb4cc;
    }
    .stack { display:grid; grid-template-columns: 1fr; gap:14px; align-items:start; }
    .card {
      background: rgba(17,24,39,.93);
      border:1px solid var(--line);
      border-radius: 14px;
      padding: 16px;
      box-shadow: 0 12px 30px rgba(0,0,0,.30);
    }
    .hero-head {
      display:grid;
      grid-template-columns: minmax(0, .95fr) minmax(320px, 1.05fr);
      gap:16px;
      align-items:start;
      margin-bottom:8px;
    }
    .hero-title-block { min-width:0; }
    .hero-summary {
      min-width:0;
      padding:10px 14px;
      border:1px solid #24364a;
      border-radius:12px;
      background:linear-gradient(180deg, rgba(10,22,37,.88), rgba(9,18,31,.82));
      color:#d6e3f1;
      line-height:1.55;
      font-size:13px;
    }
    .card-head { display:flex; align-items:center; justify-content:space-between; gap:10px; }
    h1 { margin: 0 0 8px; font-size: 24px; letter-spacing:.2px; }
    h2 { margin: 0 0 8px; font-size: 20px; letter-spacing:.2px; }
    h3 { margin: 14px 0 8px; }
    .muted { color: var(--muted); font-size: 13px; }
    .hint {
      display:inline-flex;
      align-items:center;
      justify-content:center;
      width:16px;
      height:16px;
      border-radius:999px;
      border:1px solid #36516b;
      color:#b9e6ff;
      font-size:11px;
      cursor:help;
      margin-left:6px;
      position:relative;
      top:-1px;
    }
    .hint:hover .hint-pop, .hint:focus-within .hint-pop { display:block; }
    .hint-pop {
      display:none;
      position:absolute;
      top:20px;
      left:-8px;
      width:280px;
      z-index:20;
      background:#07111f;
      border:1px solid #294560;
      border-radius:8px;
      padding:8px;
      color:#dbeafe;
      font-size:12px;
      line-height:1.35;
      box-shadow:0 10px 18px rgba(0,0,0,.35);
    }
    label { display:block; margin: 12px 0 6px; font-size: 13px; color:#d1d5db; }
    textarea, input, select {
      width:100%; box-sizing:border-box; background:var(--card2); color:var(--fg);
      border:1px solid #374151; border-radius:10px; padding:10px;
      font-family: "Trebuchet MS", "Segoe UI", "Helvetica Neue", Helvetica, sans-serif;
      font-size:14px;
    }
    textarea { min-height: 100px; }
    .row { display:grid; grid-template-columns: 1fr 160px 180px 220px; gap:10px; }
    .row-ops { display:none; }
    .ops-field { min-width: 0; }
    .ops-field.wide { grid-column: span 2; }
    .label-row {
      display:flex;
      align-items:center;
      gap:6px;
      flex-wrap:wrap;
    }
    .ops-actions { display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }
    .ops-actions button { margin-top:0; }
    button {
      margin-top: 14px;
      background:linear-gradient(135deg,#22c55e,#14b86a);
      color:#03210d;
      border:1px solid rgba(134,239,172,.22);
      border-radius:14px;
      font-weight:800;
      padding:11px 16px;
      cursor:pointer;
      font-family: "Trebuchet MS", "Segoe UI", "Helvetica Neue", Helvetica, sans-serif;
      letter-spacing:.01em;
      box-shadow:0 10px 22px rgba(20,184,106,.24), inset 0 1px 0 rgba(255,255,255,.18);
      transition:transform .18s ease, box-shadow .18s ease, filter .18s ease, border-color .18s ease;
    }
    button:hover {
      transform:translateY(-1px);
      filter:brightness(1.03);
      box-shadow:0 14px 28px rgba(20,184,106,.30), inset 0 1px 0 rgba(255,255,255,.2);
    }
    .btn-secondary {
      background:linear-gradient(180deg,#16324a,#102435);
      color:#dbeafe;
      border-color:#315a79;
      box-shadow:0 10px 20px rgba(8,23,37,.26), inset 0 1px 0 rgba(255,255,255,.05);
    }
    .btn-secondary:hover {
      box-shadow:0 14px 28px rgba(8,23,37,.34), inset 0 1px 0 rgba(255,255,255,.06);
    }
    .btn-danger { background:#7f1d1d; color:#fee2e2; }
    button:disabled { opacity:.6; cursor:wait; }
    .run-progress-wrap {
      margin-top:10px;
      border:1px solid #2a4056;
      border-radius:10px;
      background:#07111f;
      padding:8px;
    }
    .run-progress-meta {
      display:flex;
      justify-content:space-between;
      gap:8px;
      align-items:center;
      font-size:12px;
      color:#c7d8eb;
      margin-bottom:6px;
    }
    .run-progress-track {
      width:100%;
      height:10px;
      border-radius:999px;
      border:1px solid #1f2937;
      background:#0b2130;
      overflow:hidden;
    }
    .run-progress-bar {
      height:100%;
      width:0%;
      border-radius:999px;
      background:linear-gradient(90deg,#22c55e,#10b981);
      transition:width .2s ease;
    }
    pre {
      white-space: pre-wrap; background:#020617; border:1px solid var(--line);
      border-radius:10px; padding:12px; overflow:auto; line-height:1.4;
      font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
      font-size:13px;
    }
    #ops-log-output { height: 460px; overflow:auto; }
    .warn { color: var(--warn); }
    .badge {
      display:inline-block; border-radius:999px; padding:4px 10px; border:1px solid #223245;
      background:#0b2130; color:#bde6ff; font-size:12px; margin-left:8px;
    }
    .domain-hints {
      margin-top:8px;
      background:#07111f;
      border:1px solid #27415a;
      border-radius:10px;
      padding:8px;
    }
    .domain-hints summary {
      cursor:pointer;
      outline:none;
      list-style:none;
    }
    .domain-hints summary::-webkit-details-marker { display:none; }
    .domain-hints summary::after {
      content:"Show";
      float:right;
      color:#9fb4cc;
      font-size:12px;
      font-weight:700;
    }
    .domain-hints[open] summary::after { content:"Hide"; }
    .domain-hints .hint-title {
      color:#c7d8eb;
      font-size:12px;
      font-weight:700;
      margin-bottom:0;
    }
    .domain-list {
      display:flex;
      flex-direction:column;
      gap:6px;
    }
    .domain-item {
      border:1px solid #25435f;
      background:#0a1b2d;
      border-radius:8px;
      padding:6px 8px;
      font-size:12px;
      line-height:1.4;
    }
    .domain-item .idx {
      color:#93c5fd;
      font-weight:700;
      font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
    }
    .domain-item .meta {
      color:#bcd2e8;
      margin-top:2px;
      overflow-wrap:anywhere;
    }
    .badge.ok { border-color:#14532d; background:#052e1f; color:#a7f3d0; }
    .badge.bad { border-color:#7f1d1d; background:#2a0d0d; color:#fecaca; }
    .tdir-card {
      background:#07111f;
      border:1px solid #23384f;
      border-radius:10px;
      padding:10px;
      margin-bottom:8px;
    }
    .tdir-head {
      display:flex;
      flex-wrap:wrap;
      gap:8px;
      align-items:center;
      margin-bottom:8px;
    }
    .pill {
      display:inline-block;
      border-radius:999px;
      padding:3px 10px;
      border:1px solid #2a4056;
      background:#0b2130;
      color:#dbeafe;
      font-size:12px;
      line-height:1.2;
      font-weight:700;
    }
    .pill-sev-info { border-color:#1e40af; background:#0f1f4a; color:#bfdbfe; }
    .pill-sev-low { border-color:#166534; background:#052e16; color:#bbf7d0; }
    .pill-sev-medium { border-color:#92400e; background:#3b1d08; color:#fde68a; }
    .pill-sev-high { border-color:#b91c1c; background:#3f1212; color:#fecaca; }
    .pill-risk-low { border-color:#1d4ed8; background:#0f1f4a; color:#bfdbfe; }
    .pill-risk-medium { border-color:#a16207; background:#3b2a08; color:#fde68a; }
    .pill-risk-high { border-color:#b91c1c; background:#3f1212; color:#fecaca; }
    .tdir-meta {
      color:#a7b4c5;
      font-size:12px;
      line-height:1.35;
    }
    .tdir-body {
      display:grid;
      gap:12px;
      margin-top:10px;
    }
    .tdir-section {
      border:1px solid #23384f;
      background:#091525;
      border-radius:12px;
      padding:12px;
    }
    .tdir-section.takeaway {
      border-color:#16a34a;
      background:linear-gradient(180deg, #0d1f17 0%, #0a1611 100%);
      box-shadow:0 0 0 1px rgba(34,197,94,0.18), 0 16px 36px rgba(0,0,0,0.28);
    }
    .tdir-kicker {
      font-size:11px;
      letter-spacing:0.12em;
      text-transform:uppercase;
      color:#86efac;
      font-weight:800;
      margin-bottom:6px;
    }
    .tdir-title {
      color:#f8fafc;
      font-size:18px;
      line-height:1.2;
      font-weight:800;
      margin-bottom:8px;
    }
    .tdir-takeaway-copy {
      color:#dcfce7;
      font-size:14px;
      line-height:1.55;
      margin-bottom:10px;
    }
    .tdir-response-note {
      color:#cbd5e1;
      font-size:12px;
      line-height:1.45;
      padding-top:8px;
      border-top:1px solid rgba(148,163,184,0.2);
    }
    .summary-box {
      white-space:pre-wrap;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size:14px;
      line-height:1.7;
      color:#e5eefc;
      background:#0a1422;
      border:1px solid #23384f;
      border-radius:12px;
      padding:14px 16px;
    }
    .summary-box strong {
      color:#ffffff;
      font-weight:800;
    }
    .summary-box .summary-lead {
      color:#ffffff;
      font-weight:800;
    }
    .tdir-label {
      color:#8fb6d9;
      font-size:11px;
      letter-spacing:0.08em;
      text-transform:uppercase;
      font-weight:800;
      margin-bottom:8px;
    }
    .tdir-hypothesis {
      color:#dbeafe;
      font-size:14px;
      line-height:1.5;
    }
    .tdir-phase-grid {
      display:flex;
      flex-wrap:wrap;
      gap:8px;
    }
    .phase-pill {
      display:flex;
      align-items:center;
      gap:8px;
      border-radius:999px;
      padding:7px 12px;
      border:1px solid #29445f;
      background:#0c1d2d;
      min-width:150px;
    }
    .phase-pill .phase-name {
      font-size:12px;
      font-weight:800;
      letter-spacing:0.04em;
      text-transform:uppercase;
      color:#e2e8f0;
    }
    .phase-pill .phase-state {
      font-size:12px;
      color:#d6e4f5;
      font-weight:700;
    }
    .phase-pill.detect { border-color:#1d4ed8; background:#0b1731; }
    .phase-pill.triage { border-color:#15803d; background:#061a12; }
    .phase-pill.investigate { border-color:#b45309; background:#221105; }
    .phase-pill.respond { border-color:#dc2626; background:#2a0b0b; }
    .phase-pill.recover { border-color:#7c3aed; background:#160a2d; }
    .phase-pill.soar_automation { border-color:#0f766e; background:#081f23; }
    .phase-pill.complete .phase-state { color:#bbf7d0; }
    .phase-pill.planned .phase-state { color:#fde68a; }
    .phase-pill.not_enabled_yet .phase-state { color:#93c5fd; }
    .phase-pill.awaiting_human_approval .phase-state { color:#fca5a5; }
    .tdir-pivot-list {
      display:grid;
      gap:8px;
      margin:0;
      padding:0;
      list-style:none;
    }
    .tdir-pivot-item {
      border:1px solid rgba(74,222,128,0.28);
      background:rgba(34,197,94,0.08);
      border-radius:10px;
      padding:10px 12px;
      color:#f0fdf4;
      font-size:14px;
      line-height:1.5;
      font-weight:600;
    }
    .tdir-pivot-item.priority {
      border-color:#22c55e;
      background:linear-gradient(180deg, rgba(34,197,94,0.18) 0%, rgba(34,197,94,0.08) 100%);
      color:#ffffff;
      box-shadow:0 0 0 1px rgba(34,197,94,0.18);
    }
    .persona-grid {
      display:grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap:8px;
      margin-bottom:8px;
    }
    .persona {
      border:1px solid #27415a;
      background:#07111f;
      border-radius:10px;
      padding:8px;
    }
    .persona .p-head {
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:8px;
      margin-bottom:4px;
    }
    .persona .p-name {
      font-weight:700;
      color:#dbeafe;
      font-size:13px;
    }
    .persona.planner { border-color:#1d4ed8; background:#0b1731; }
    .persona.reviewer { border-color:#15803d; background:#061a12; }
    .persona.judge { border-color:#b45309; background:#221105; }
    .persona.judge2 { border-color:#db2777; background:#2a0b1c; }
    .persona.policy { border-color:#7c3aed; background:#1a0a2e; }
    .persona .p-role {
      color:#9fb4cc;
      font-size:12px;
      margin-bottom:4px;
    }
    .persona .p-detail {
      color:#cdd8e5;
      font-size:12px;
      line-height:1.35;
      white-space:pre-wrap;
    }
    .persona .p-model {
      color:#8fb7ff;
      font-size:11px;
      overflow-wrap:anywhere;
    }
    .persona.planner .p-model { color:#93c5fd; }
    .persona.reviewer .p-model { color:#86efac; }
    .persona.judge .p-model { color:#fcd34d; }
    .persona.judge2 .p-model { color:#f9a8d4; }
    .persona.policy .p-model { color:#d8b4fe; }
    .spl-card {
      border:1px solid #294560;
      background:#061423;
      border-radius:10px;
      padding:8px;
      margin-bottom:8px;
    }
    .section-head {
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
    }
    .spl-title {
      font-weight:700;
      font-size:13px;
      color:#dbeafe;
      margin-bottom:6px;
    }
    .decision-log {
      white-space: pre-wrap;
      background:#020617;
      border:1px solid var(--line);
      border-radius:10px;
      padding:12px;
      overflow:auto;
      line-height:1.45;
      font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
      font-size:13px;
    }
    .role-line { margin-bottom:4px; }
    .role-line strong { font-weight:800; }
    .role-line.planner strong { color:#93c5fd; }
    .role-line.reviewer strong { color:#86efac; }
    .role-line.judge strong { color:#fcd34d; }
    .role-line.judge2 strong { color:#f9a8d4; }
    .role-line.policy strong { color:#d8b4fe; }
    .decision-subhead {
      margin:10px 0 6px;
      color:#9fb4cc;
      font-weight:700;
    }
    .advanced-shell {
      margin-top:14px;
      border:1px solid #27415a;
      border-radius:12px;
      background:#061423;
      padding:10px 12px;
    }
    .advanced-shell summary {
      cursor:pointer;
      font-weight:800;
      color:#dbeafe;
      outline:none;
    }
    .advanced-body {
      margin-top:12px;
      display:grid;
      gap:14px;
    }
    .advanced-panel {
      border:1px solid #22384f;
      border-radius:10px;
      background:#081729;
      padding:10px;
    }
    .advanced-subhead {
      margin:0 0 8px;
      font-size:13px;
      font-weight:800;
      color:#dbeafe;
      letter-spacing:.2px;
    }
    .flow-shell {
      margin-top:0;
      border:1px solid #27415a;
      border-radius:10px;
      background:#061423;
      padding:8px 10px;
    }
    .flow-shell summary {
      cursor:pointer;
      font-weight:700;
      color:#dbeafe;
      outline:none;
    }
    .flow-track {
      margin-top:10px;
      display:flex;
      gap:8px;
      align-items:stretch;
      flex-wrap:wrap;
    }
    .flow-node {
      min-width:150px;
      flex:1 1 150px;
      border-radius:10px;
      border:1px solid #2a4056;
      background:#0b2130;
      padding:8px;
    }
    .flow-node .n-title {
      font-weight:800;
      font-size:12px;
      color:#e5e7eb;
      margin-bottom:4px;
      letter-spacing:.2px;
    }
    .flow-node .n-status {
      font-size:12px;
      color:#cbd5e1;
      margin-bottom:4px;
    }
    .flow-node .n-time {
      font-size:12px;
      color:#93c5fd;
      font-weight:700;
    }
    .flow-arrow {
      align-self:center;
      color:#7dd3fc;
      font-weight:800;
      font-size:14px;
      padding:0 2px;
    }
    .flow-node.complete { border-color:#166534; background:#052e16; }
    .flow-node.in_progress { border-color:#92400e; background:#3b1d08; }
    .flow-node.awaiting_human_approval { border-color:#7c3aed; background:#2a1148; }
    .flow-node.planned { border-color:#1d4ed8; background:#0f1f4a; }
    .flow-node.not_enabled_yet { border-color:#475569; background:#0f172a; }
    .flow-meta { margin-top:8px; color:#9fb4cc; font-size:12px; }
    .continue-shell {
      margin-top:14px;
      padding:14px;
      border:1px solid #244360;
      border-radius:12px;
      background:linear-gradient(180deg,#0d1a2d,#091423);
    }
    .continue-title {
      margin:0 0 8px;
      font-size:16px;
      color:#e2e8f0;
    }
    .continue-copy {
      margin:0 0 10px;
      color:#9fb4cc;
      font-size:13px;
      line-height:1.5;
      white-space:pre-wrap;
    }
    .continue-actions {
      display:flex;
      gap:10px;
      align-items:center;
      flex-wrap:wrap;
    }
    .continue-pill {
      display:inline-flex;
      align-items:center;
      gap:6px;
      padding:5px 10px;
      border-radius:999px;
      border:1px solid #2a4d6b;
      background:#0a2034;
      color:#cbe4ff;
      font-size:12px;
      font-weight:700;
    }
    @media (max-width: 900px) { .persona-grid { grid-template-columns: 1fr; } }
    @media (max-width: 900px) { .hero-head { grid-template-columns: 1fr; } }
    @media (max-width: 1240px) { .stack { grid-template-columns: 1fr; } }
    @media (max-width: 1100px) { .ops-field.wide { grid-column: span 1; } }
    @media (max-width: 900px) { .row { grid-template-columns: 1fr 1fr; } }
    @media (max-width: 560px) { .row, .row-ops { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class=\"wrap\">
    <nav class=\"topnav\">
      <a class=\"nav-item\" href=\"/mcp\"><span class=\"nav-kicker\">MCP</span><span class=\"nav-label\">Splunk MCP Chat</span></a>
      <a class=\"nav-item active\" href=\"/investigation\"><span class=\"nav-kicker\">Investigate</span><span class=\"nav-label\">Investigation UI</span></a>
      <a class=\"nav-item\" href=\"/environment\"><span class=\"nav-kicker\">Profile</span><span class=\"nav-label\">Data Domains</span></a>
      <a class=\"nav-item\" href=\"/artifacts\"><span class=\"nav-kicker\">Artifacts</span><span class=\"nav-label\">Artifact Repository</span></a>
      <div class=\"nav-item nav-item-dropdown\">
        <a class=\"nav-trigger\" href=\"/configure\"><span class=\"nav-kicker\">Control</span><span class=\"nav-label\">Control Center</span></a>
        <div class=\"nav-submenu\">
          <a class=\"nav-submenu-item\" href=\"/architecture\"><span class=\"nav-submenu-title\">Architecture</span><span class=\"nav-submenu-copy\">System flow and trust boundaries</span></a>
          <a class=\"nav-submenu-item\" href=\"/docs\"><span class=\"nav-submenu-title\">Docs</span><span class=\"nav-submenu-copy\">Whitepapers, guides, and references</span></a>
          <a class=\"nav-submenu-item\" href=\"/configure\"><span class=\"nav-submenu-title\">Configuration</span><span class=\"nav-submenu-copy\">Endpoints, models, validation</span></a>
          <a class=\"nav-submenu-item\" href=\"/users\"><span class=\"nav-submenu-title\">Users</span><span class=\"nav-submenu-copy\">Local users and audit trail</span></a>
        </div>
      </div>
      <a class=\"nav-item\" href=\"/logout\"><span class=\"nav-kicker\">Session</span><span class=\"nav-label\">Logout</span></a>
    </nav>

    <div class=\"stack\" id=\"invest-layout\">
      <div class=\"card\" id=\"analyst-card\">
        <div class=\"hero-head\">
          <div class=\"hero-title-block\">
            <h1>A.G.E.N.T. Smith</h1>
            <div class=\"muted\">A Splunk TDI(R) Agentic SOC Copilot</div>
          </div>
          <div class=\"hero-summary\">A.G.E.N.T. Smith is a Splunk-centric analyst augmentation platform that uses networked tasker roles, deterministic guardrails, and evidence-first workflow control to support detection, triage, and investigation.</div>
        </div>
        <label class=\"label-row\">Question
          <span class=\"hint\" tabindex=\"0\">?
            <span class=\"hint-pop\">Natural-language investigation request. Keep it read-only (search/analyze/explain) for this lab flow.</span>
          </span>
        </label>
        <textarea id=\"question\">Show failed login activity in the last 24 hours</textarea>
        <details class=\"domain-hints\">
          <summary class=\"hint-title\">Likely Data Domains (pre-investigation hint)</summary>
          <div id=\"domain-hints\" class=\"domain-list\">
            <div class=\"muted\">Type a question to see likely index/sourcetype targets.</div>
          </div>
        </details>
        <div class=\"row\">
          <div>
            <label class=\"label-row\">Session ID (optional)
              <span class=\"hint\" tabindex=\"0\">?
                <span class=\"hint-pop\">Analyst session grouping key for artifacts and run history, e.g. `night_shift_a`.</span>
              </span>
            </label>
            <input id=\"session\" placeholder=\"analyst_shift_a\" />
          </div>
          <div>
            <label class=\"label-row\">Max Steps
              <span class=\"hint\" tabindex=\"0\">?
                <span class=\"hint-pop\">For Agentic Loop only: upper bound on total inner-graph steps per round. Separate loop controls allow one automatic deeper-investigation round, then require analyst approval for anything deeper.</span>
              </span>
            </label>
            <input id=\"maxsteps\" type=\"number\" min=\"1\" max=\"8\" value=\"3\" />
          </div>
          <div>
            <label class=\"label-row\">Write Artifact
              <span class=\"hint\" tabindex=\"0\">?
                <span class=\"hint-pop\">When enabled, writes JSON run artifacts under `artifacts/runs/*`.</span>
              </span>
            </label>
            <select id=\"artifact\"><option value=\"1\">Yes</option><option value=\"0\">No</option></select>
          </div>
          <div>
            <label class=\"label-row\">Pipeline
              <span class=\"hint\" tabindex=\"0\">?
                <span class=\"hint-pop\">
                  <strong>Multi-Model Reviewer</strong>: planner, SPL writer, and security reviewer on every run; peer reviewer 1 and 2 only when the reviewer contests or revises the writer output.<br/><br/>
                  <strong>Agentic Loop</strong>: bounded multi-step investigation with one automatic deeper pass, then analyst approval for any further continuation.
                </span>
              </span>
            </label>
            <select id=\"pipeline\">
              <option value=\"multi_model\">Multi-Model Reviewer</option>
              <option value=\"agentic\">Agentic Loop</option>
            </select>
          </div>
        </div>
        <p id=\"pipeline-help\" class=\"muted\"></p>
        <button id=\"run\" title=\"Execute selected investigation pipeline with current settings\">Run Investigation</button>
        <div id=\"run-progress-wrap\" class=\"run-progress-wrap\" style=\"display:none;\">
          <div class=\"run-progress-meta\">
            <span id=\"run-progress-label\">Preparing investigation...</span>
            <span id=\"run-progress-pct\">0%</span>
          </div>
          <div class=\"run-progress-track\">
            <div id=\"run-progress-bar\" class=\"run-progress-bar\"></div>
          </div>
        </div>
        <p id=\"status\" class=\"muted\"></p>
        <h3>Summary <span class=\"hint\" tabindex=\"0\">?<span class=\"hint-pop\">Final analyst-facing narrative generated from guarded, read-only workflow results.</span></span></h3>
        <div id=\"summary\" class=\"summary-box\"></div>
        <div class=\"spl-card\">
          <div class=\"spl-title\">Splunk SPL Executed <span class=\"hint\" tabindex=\"0\">?<span class=\"hint-pop\">Always displays the exact SPL used by the selected execution plan.</span></span></div>
          <pre id=\"spl-details\"></pre>
          <div><a id=\"spl-link\" href=\"#\" target=\"_blank\" rel=\"noopener noreferrer\" style=\"display:none; color:#93c5fd; text-decoration:none; font-size:13px;\">View in Splunk</a></div>
          <pre id=\"spl-query\"></pre>
          <div class=\"spl-title\" style=\"margin-top:8px;\">SPL Results (sample)</div>
          <pre id=\"spl-results\"></pre>
        </div>
        <h3>TDIR Case <span class=\"hint\" tabindex=\"0\">?<span class=\"hint-pop\">Detect/Triage/Investigate/Respond/Recover framing generated from the run output. Investigate can show `awaiting_human_approval` after the first automatic deeper round completes and another bounded pivot is available.</span></span></h3>
        <div id=\"tdir-card\" class=\"tdir-card\" style=\"display:none;\">
          <div id=\"tdir-head\" class=\"tdir-head\"></div>
          <div id=\"tdir-meta\" class=\"tdir-meta\"></div>
        </div>
        <div id=\"tdir-case\" class=\"tdir-body\"></div>
        <h3>Model Decisions <span class=\"hint\" tabindex=\"0\">?<span class=\"hint-pop\">Shows each model persona output and final adjudication for transparent review.</span></span></h3>
        <div id=\"model-personas\" class=\"persona-grid\"></div>
        <details class=\"advanced-shell\">
          <summary>Show Advanced Details</summary>
          <div class=\"advanced-body\">
            <div class=\"advanced-panel\">
              <div class=\"advanced-subhead\">Detailed Model Trace</div>
              <div id=\"model-decisions\" class=\"decision-log\"></div>
            </div>
            <div class=\"advanced-panel\">
              <div class=\"advanced-subhead\">Workflow Journey (TDI/R)</div>
              <div id=\"workflow-track\" class=\"flow-track\"></div>
              <div id=\"workflow-meta\" class=\"flow-meta\"></div>
            </div>
            <div class=\"advanced-panel\">
              <div class=\"advanced-subhead\">Investigation Narrative Trace</div>
              <pre id=\"journey\"></pre>
            </div>
            <div id=\"continue-shell\" class=\"continue-shell\" style=\"display:none;\">
              <div class=\"continue-title\">Deeper Investigation Control <span class=\"hint\" tabindex=\"0\">?<span class=\"hint-pop\">Shows the bounded continuation state: one automatic deeper-investigation round is allowed when justified, then further continuation requires analyst approval. Duplicate pivots and low-confidence follow-ups are blocked.</span></span></div>
              <div id=\"continue-copy\" class=\"continue-copy\"></div>
              <div class=\"continue-actions\">
                <span id=\"continue-pill\" class=\"continue-pill\"></span>
                <button id=\"continue-btn\" class=\"btn-secondary\" style=\"display:none; margin-top:0;\">Run Deeper Investigation</button>
              </div>
            </div>
            <div class=\"advanced-panel\">
              <div class=\"section-head\">
                <div class=\"advanced-subhead\">Result JSON</div>
                <button id=\"toggle-json\" class=\"btn-secondary\" style=\"margin-top:0;\">Show JSON</button>
              </div>
              <pre id=\"output\" style=\"display:none;\"></pre>
            </div>
          </div>
        </details>
      </div>
    </div>
  </div>
  <script>
    const $ = (id) => document.getElementById(id);
    const runBtn = $('run');
    const continueBtn = $('continue-btn');
    let runProgressTimer = null;
    let runProgressValue = 0;
    let lastAskResult = null;
    let pendingContinuationState = null;

    const esc = (v) => String(v ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');

    function fmtValue(v) {
      if (v === null || v === undefined) return '';
      if (Array.isArray(v)) {
        return v.map((item) => {
          if (item && typeof item === 'object') {
            try { return JSON.stringify(item); } catch (_e) { return String(item); }
          }
          return String(item ?? '');
        }).join('; ');
      }
      if (typeof v === 'object') {
        try { return JSON.stringify(v); } catch (_e) { return String(v); }
      }
      return String(v);
    }

    function compactValue(v) {
      if (v === null || v === undefined) return '';
      if (Array.isArray(v)) {
        return v.map((item) => compactValue(item)).filter(Boolean).slice(0, 2).join(' | ');
      }
      if (typeof v === 'object') {
        const action = String(v.action || '').trim();
        const description = String(v.description || '').trim();
        const indicator = String(v.indicator || '').trim();
        const reason = String(v.reason || '').trim();
        if (description) return action ? `${action}: ${description}` : description;
        if (indicator) return indicator;
        if (reason) return reason;
        try { return JSON.stringify(v); } catch (_e) { return String(v); }
      }
      return String(v);
    }

    function updatePipelineHelp() {
      const v = $('pipeline')?.value || 'multi_model';
      if (v === 'agentic') {
        $('pipeline-help').textContent =
          'Agentic Loop: allows one automatic deeper-investigation pass, then requires analyst approval for any further continuation.';
      } else {
        $('pipeline-help').textContent =
          'Multi-Model Reviewer: planner -> SPL writer -> security reviewer -> optional peer review -> deterministic gate -> tool execution.';
      }
    }

    function renderModelDecisions(result) {
      if (!result || typeof result !== 'object') {
        $('model-personas').innerHTML = '';
        $('spl-details').textContent = '';
        $('spl-query').textContent = '';
        $('spl-results').textContent = '';
        $('model-decisions').innerHTML = '';
        return;
      }

      const workflow = Array.isArray(result.model_workflow) ? result.model_workflow : [];
      const workflowStagesPresent = new Set(
        workflow
          .map((step) => String((step && step.stage) || '').trim())
          .filter(Boolean)
      );
      const writer = result.query_writer_output || result.planner?.output || {};
      const reviewer = result.security_reviewer_output || result.security_reviewer?.output || {};
      const peer = result.peer_reviewer_decision || result.peer_reviewer?.output || {};
      const peer2 = result.peer_reviewer_2_decision || result.peer_reviewer_2?.output || {};
      const evidenceReviewer = result.evidence_reviewer_output || result.evidence_reviewer?.output || {};
      const continuationReviewer = result.continuation_reviewer_output || result.continuation_reviewer?.output || {};
      const hasContinuationReviewerData = Boolean(
        continuationReviewer &&
        typeof continuationReviewer === 'object' &&
        (
          continuationReviewer.should_continue !== undefined ||
          String(continuationReviewer.why || '').trim() ||
          String(continuationReviewer.next_best_question || '').trim() ||
          String(continuationReviewer.next_best_spl_or_tool || '').trim() ||
          continuationReviewer.confidence !== undefined ||
          String(continuationReviewer.expected_value_of_next_step || '').trim()
        )
      );
      const adjudication = result.final_adjudication || {};
      const repair = result.query_repair || {};

      const detailLines = [];
      const roleClassMap = {
        query_writer: 'planner',
        planner: 'planner',
        security_reviewer: 'reviewer',
        reviewer: 'reviewer',
        evidence_reviewer: 'reviewer',
        continuation_reviewer: 'reviewer',
        peer_reviewer: 'judge',
        peer_reviewer_1: 'judge',
        peer_reviewer_2: 'judge2',
        controller: 'policy',
        final_summary: 'policy',
        summary: 'policy',
        policy: 'policy'
      };
      const roleNameMap = {
        query_writer: 'SPL Writer',
        planner: 'Planner',
        security_reviewer: 'Security Reviewer',
        reviewer: 'Security Reviewer',
        evidence_reviewer: 'Evidence Reviewer',
        continuation_reviewer: 'Continuation Reviewer',
        peer_reviewer: 'Peer Reviewer 1',
        peer_reviewer_1: 'Peer Reviewer 1',
        peer_reviewer_2: 'Peer Reviewer 2',
        controller: 'Controller',
        final_summary: 'Summary',
        summary: 'Summary',
        policy: 'Policy'
      };
      const preferredRoleOrder = [
        'planner',
        'query_writer',
        'security_reviewer',
        'peer_reviewer',
        'peer_reviewer_1',
        'peer_reviewer_2',
        'evidence_reviewer',
        'continuation_reviewer',
        'controller',
        'final_summary',
        'summary',
      ];
      const roleTimingKeyMap = {
        query_writer: 'writer',
        planner: 'planner',
        security_reviewer: 'security_review',
        reviewer: 'security_review',
        peer_reviewer: 'peer_review_1',
        peer_reviewer_1: 'peer_review_1',
        peer_reviewer_2: 'peer_review_2',
        evidence_reviewer: 'evidence_review',
        continuation_reviewer: 'continuation_review',
        final_summary: 'summarize',
        summary: 'summarize',
      };
      const nodeTimings = (result && typeof result.node_timings_ms === 'object' && result.node_timings_ms) ? result.node_timings_ms : {};
      const workflowNormalized = [];
      for (const stage of preferredRoleOrder) {
        const hit = workflow.find((step) => String((step && step.stage) || '').trim() === stage);
        if (hit) workflowNormalized.push(hit);
      }
      for (const step of workflow) {
        const stage = String((step && step.stage) || '').trim();
        if (!stage) continue;
        if (!preferredRoleOrder.includes(stage)) workflowNormalized.push(step);
      }
      if (!workflowStagesPresent.has('evidence_reviewer') && (result.evidence_reviewer || result.evidence_reviewer_output)) {
        workflowNormalized.push({
          stage: 'evidence_reviewer',
          model: result.evidence_reviewer?.model || '',
          responsibility: 'Assesses evidence quality from executed query results.',
        });
      }
      if (!workflowStagesPresent.has('continuation_reviewer') && (result.continuation_reviewer || result.continuation_reviewer_output)) {
        workflowNormalized.push({
          stage: 'continuation_reviewer',
          model: result.continuation_reviewer?.model || '',
          responsibility: 'Decides if the investigation should continue and proposes the next best pivot.',
        });
      }
      const workflowHtml = [];
      for (const step of workflowNormalized) {
        const stage = String(step.stage || '');
        const model = String(step.model || '');
        const responsibility = String(step.responsibility || '');
        const roleClass = roleClassMap[stage] || 'policy';
        const roleLabel = roleNameMap[stage] || stage || 'Role';
        const respText = responsibility ? ` - ${responsibility}` : '';
        const timingKey = roleTimingKeyMap[stage];
        const timingValue = timingKey ? nodeTimings[timingKey] : null;
        const timingText = timingValue !== null && timingValue !== undefined ? ` (duration=${fmtMs(timingValue)})` : '';
        workflowHtml.push(
          `<div class="role-line ${esc(roleClass)}"><strong>${esc(roleLabel)}:</strong> ${esc(model)}${esc(respText)}${esc(timingText)}</div>`
        );
      }

      detailLines.push(`query_writer selected_tool=${writer.selected_tool || ''} intent=${writer.intent || ''} confidence=${writer.confidence ?? ''}`);
      detailLines.push(`planner intent=${result.planner?.output?.intent || ''} strategy=${result.search_strategy_summary || ''} confidence=${result.planner?.output?.confidence ?? ''}`);
      detailLines.push(`security_reviewer approved=${reviewer.approved ?? ''} confidence=${reviewer.confidence ?? ''} revised_tool=${reviewer.revised_selected_tool || ''}`);
      detailLines.push(`peer_reviewer_1 winner=${peer.winner || ''} confidence=${peer.confidence ?? ''}`);
      detailLines.push(`peer_reviewer_2 winner=${peer2.winner || ''} confidence=${peer2.confidence ?? ''} agrees_with_peer1=${peer2.agrees_with_peer1 ?? ''}`);
      detailLines.push(`evidence_reviewer confidence=${fmtValue(evidenceReviewer.confidence)} quality=${fmtValue(evidenceReviewer.evidence_quality)} recommendation=${fmtValue(evidenceReviewer.recommendation)}`);
      if (hasContinuationReviewerData) {
        detailLines.push(`continuation_reviewer should_continue=${fmtValue(continuationReviewer.should_continue)} confidence=${fmtValue(continuationReviewer.confidence)} next_best_question=${fmtValue(continuationReviewer.next_best_question)}`);
      }
      const hasRepairDetails = Boolean(
        repair && typeof repair === 'object' && (
          repair.ok === true ||
          String(repair.repair_reason || '').trim() ||
          String(repair.validation_reason || '').trim() ||
          String(repair.model || '').trim()
        )
      );
      if (hasRepairDetails) {
        detailLines.push(`query_repair applied=${repair.ok ?? false} model=${repair.model || ''} reason=${repair.repair_reason || ''}`);
      }
      detailLines.push(`final_adjudication tool=${adjudication.selected_tool || ''} intent=${adjudication.selected_intent || ''} validation=${adjudication.validation_ok ?? ''} reason=${adjudication.validation_reason || ''}`);

      const personas = [
        {
          cls: 'planner',
          name: 'Planner',
          role: 'Builds the structured search plan before SPL generation.',
          model: result.planner?.model || '',
          detail: `tool=${result.planner?.output?.selected_tool || ''}\nintent=${result.planner?.output?.intent || ''}\nconfidence=${result.planner?.output?.confidence ?? ''}`,
          badge: 'Planner'
        },
        {
          cls: 'planner',
          name: 'SPL Writer',
          role: 'Turns the plan into bounded read-only SPL.',
          model: result.writer?.model || '',
          detail: `tool=${writer.selected_tool || ''}\nintent=${writer.intent || ''}\nconfidence=${writer.confidence ?? ''}`,
          badge: 'Writer'
        },
        {
          cls: 'reviewer',
          name: 'Security Reviewer',
          role: 'Critiques quality and safety.',
          model: result.security_reviewer?.model || '',
          detail: `approved=${reviewer.approved ?? ''}\nconfidence=${reviewer.confidence ?? ''}\nrevised_tool=${reviewer.revised_selected_tool || ''}`,
          badge: 'Reviewer'
        },
        {
          cls: 'judge',
          name: 'Peer Reviewer 1',
          role: 'Adjudicates writer vs reviewer winner.',
          model: result.peer_reviewer?.model || '',
          detail: `winner=${peer.winner || ''}\nconfidence=${peer.confidence ?? ''}`,
          badge: 'Judge-1'
        },
        {
          cls: 'judge2',
          name: 'Peer Reviewer 2',
          role: 'Validates or overrides peer reviewer 1.',
          model: result.peer_reviewer_2?.model || '',
          detail: `winner=${peer2.winner || ''}\nconfidence=${peer2.confidence ?? ''}\nagrees_with_peer1=${peer2.agrees_with_peer1 ?? ''}`,
          badge: 'Judge-2'
        },
        {
          cls: 'reviewer',
          name: 'Evidence Reviewer',
          role: 'Assesses evidence quality from executed query results.',
          model: result.evidence_reviewer?.model || '',
          detail: `confidence=${fmtValue(evidenceReviewer.confidence)}\nquality=${fmtValue(evidenceReviewer.evidence_quality)}\nrecommendation=${compactValue(evidenceReviewer.recommendation)}`,
          badge: 'Evidence'
        },
        {
          cls: 'policy',
          name: 'Final Adjudication',
          role: 'Deterministic gate + selected execution plan.',
          model: '',
          detail: `tool=${adjudication.selected_tool || result.selected_tool || ''}\nintent=${adjudication.selected_intent || result.intent || ''}\nvalidation=${adjudication.validation_ok ?? ''}`,
          badge: 'Policy'
        }
      ];
      if (hasRepairDetails) {
        personas.splice(4, 0, {
          cls: 'policy',
          name: 'Query Repair',
          role: 'One-pass repair when environment validation fails.',
          model: repair.model || '',
          detail: `applied=${repair.ok ?? false}\nreason=${repair.repair_reason || ''}\nvalidation=${repair.validation_reason || ''}`,
          badge: 'Repair'
        });
      }
      if (hasContinuationReviewerData) {
        personas.splice(hasRepairDetails ? 6 : 5, 0, {
          cls: 'reviewer',
          name: 'Continuation Reviewer',
          role: 'Decides whether to continue the investigation and what pivot adds the most value.',
          model: result.continuation_reviewer?.model || '',
          detail: `should_continue=${fmtValue(continuationReviewer.should_continue)}\nconfidence=${fmtValue(continuationReviewer.confidence)}\nwhy=${compactValue(continuationReviewer.why)}\nnext_question=${compactValue(continuationReviewer.next_best_question)}`,
          badge: 'Continue'
        });
      }
      $('model-personas').innerHTML = personas.map((p) =>
        `<div class="persona ${esc(p.cls)}">
          <div class="p-head"><span class="p-name">${esc(p.name)}</span><span class="pill">${esc(p.badge)}</span></div>
          <div class="p-role">${esc(p.role)}</div>
          <div class="p-model">${esc(p.model)}</div>
          <div class="p-detail">${esc(p.detail)}</div>
        </div>`
      ).join('');

      const splLink = $('spl-link');

      let spl = '';
      let splDetails = 'writer_model=unknown\\nrun_time_ms=unknown\\nsource=unavailable';
      const splRuns = Array.isArray(result?.selected_spl_details) ? result.selected_spl_details : [];
      if (splRuns.length) {
        const latest = splRuns[splRuns.length - 1] || {};
        splDetails = [
          `writer_model=${String(latest.writer_model || 'unknown')}`,
          `run_time_ms=${String(latest.execution_ms ?? 'unknown')}`,
          `rows_returned=${String(latest.rows_returned ?? 'unknown')}`,
          `reason=${String(latest.reason || '')}`,
          'source=deterministic_run_telemetry',
        ].join('\\n');
      }
      if (result?.query_args?.query) spl = String(result.query_args.query);
      else if (result?.final_adjudication?.selected_args?.query) spl = String(result.final_adjudication.selected_args.query);
      else if (result?.evidence?.query_or_args?.query) spl = String(result.evidence.query_or_args.query);
      else if (Array.isArray(result?.trajectory)) {
        for (let i = result.trajectory.length - 1; i >= 0; i -= 1) {
          const q = result.trajectory[i]?.args?.query;
          if (q) { spl = String(q); break; }
        }
      }
      if (!spl) {
        const tool = String(result?.selected_tool || result?.final_adjudication?.selected_tool || '');
        spl = `(No splunk_run_query in this path) selected_tool=${tool || 'n/a'}`;
      }
      if (!splRuns.length && result?.query_args?.query) {
        const writer =
          String(result?.query_writer?.model || result?.planner?.model || result?.query_writer_model || 'unknown');
        splDetails = [
          `writer_model=${writer}`,
          'run_time_ms=unknown',
          'rows_returned=unknown',
          'source=single_step_result',
        ].join('\\n');
      }
      $('spl-details').textContent = splDetails;
      $('spl-query').textContent = spl;
      const previewRowsRaw = Array.isArray(result?.spl_results_preview) ? result.spl_results_preview : [];
      const previewRows = previewRowsRaw.filter((row) => row && typeof row === 'object').slice(0, 50);
      const latestSplRun = splRuns.length ? (splRuns[splRuns.length - 1] || {}) : {};
      const latestRowsReturned = latestSplRun.rows_returned;
      $('spl-results').textContent = previewRows.length
        ? JSON.stringify(previewRows, null, 2)
        : (
          latestRowsReturned === 0
            ? '(This SPL returned 0 rows for the selected time range and filters)'
            : '(No SPL result rows were captured for this run)'
        );
      if (spl && !spl.startsWith('(No splunk_run_query')) {
        const earliest =
          String(
            result?.query_args?.earliest_time ||
            result?.final_adjudication?.selected_args?.earliest_time ||
            result?.evidence?.time_window?.earliest_time ||
            '-24h@h'
          );
        const latest =
          String(
            result?.query_args?.latest_time ||
            result?.final_adjudication?.selected_args?.latest_time ||
            result?.evidence?.time_window?.latest_time ||
            'now'
          );
        const splunkBase = 'http://174.175.242.244:8042/en-US/app/search/search';
        const params = new URLSearchParams({
          q: spl,
          'display.page.search.mode': 'smart',
          'dispatch.sample_ratio': '1',
          workload_pool: '',
          earliest,
          latest,
          'display.page.search.tab': 'statistics',
          'display.general.type': 'statistics',
        });
        splLink.href = `${splunkBase}?${params.toString()}`;
        splLink.style.display = 'inline';
      } else {
        splLink.href = '#';
        splLink.style.display = 'none';
      }
      const detailHtml = esc(detailLines.join('\\n')).replaceAll('\\n', '<br>');
      $('model-decisions').innerHTML =
        `${workflowHtml.length ? `<div class="decision-subhead">Pipeline Roles</div>${workflowHtml.join('')}` : ''}` +
        `${detailHtml ? `<div class="decision-subhead">Key Outputs</div>${detailHtml}` : ''}`;
    }

    function renderInvestigationJourney(result) {
      if (!result || typeof result !== 'object') {
        $('journey').textContent = '';
        return;
      }
      const tdir = result.tdir_case || {};
      const phase = tdir.phase_status || {};
      const pivots = Array.isArray(tdir.recommended_next_pivots) ? tdir.recommended_next_pivots : [];
      const continuation = tdir.continuation_review || result.continuation_reviewer_output || {};
      const loop = tdir.loop_control || result.loop_control || {};
      const decisionLog = Array.isArray(result.decision_log) ? result.decision_log : [];
      const tool = result.selected_tool || tdir.selected_tool || 'n/a';
      const rows = result.rows_returned ?? tdir.rows_returned ?? 'n/a';
      const intent = result.intent || tdir.intent || 'n/a';

      const lines = [];
      lines.push(`1) Detect`);
      lines.push(`- Question accepted and classified as intent: ${intent}`);
      lines.push(`- Guardrails/policy outcome: ${result.supported === false ? 'blocked' : 'supported'}${result.guardrail_reason ? ` (${result.guardrail_reason})` : ''}`);
      lines.push('');
      lines.push(`2) Triage`);
      lines.push(`- Tool path selected: ${tool}`);
      lines.push(`- Query evidence returned rows: ${rows}`);
      lines.push(`- Triage status: ${phase.triage || 'in_progress'}`);
      lines.push('');
      lines.push(`3) Investigate`);
      lines.push(`- Investigation status: ${phase.investigate || 'in_progress'}`);
      lines.push(`- Analyst hypothesis: ${tdir.incident_hypothesis || result.summary || 'No hypothesis provided.'}`);
      lines.push(`- Continuation reviewer: should_continue=${fmtValue(continuation.should_continue)} confidence=${fmtValue(continuation.confidence)}`);
      if (loop.human_approval_required) lines.push(`- Loop control: waiting for analyst approval before another deeper investigation round.`);
      else if (loop.auto_followup_executed) lines.push(`- Loop control: one bounded deeper-investigation round already executed automatically.`);
      else if (loop.stop_reason) lines.push(`- Loop control: ${loop.stop_reason}`);
      if (continuation.why) lines.push(`- Why: ${continuation.why}`);
      if (continuation.next_best_question) lines.push(`- Next best question: ${continuation.next_best_question}`);
      if (continuation.next_best_spl_or_tool) lines.push(`- Next best SPL/tool: ${continuation.next_best_spl_or_tool}`);
      if (pivots.length) {
        lines.push(`- Suggested pivots:`);
        for (const p of pivots.slice(0, 5)) lines.push(`  - ${p}`);
      }
      lines.push('');
      lines.push(`Future: Respond (R)`);
      lines.push(`- Not automated yet in this lab. Future R phase will apply approved containment/response playbooks and SOAR actions.`);
      if (decisionLog.length) {
        lines.push('');
        lines.push('Decision trail (condensed)');
        for (const d of decisionLog.slice(0, 8)) {
          const node = d.node || 'node';
          const reason = d.reason || d.decision || d.selected_tool || '';
          lines.push(`- ${node}: ${reason}`);
        }
      }
      $('journey').textContent = lines.join('\\n');
    }

    function fmtMs(ms) {
      const n = Number(ms || 0);
      if (!Number.isFinite(n) || n <= 0) return 'n/a';
      if (n < 1000) return `${Math.round(n)} ms`;
      return `${(n / 1000).toFixed(2)} s`;
    }

    function renderSummaryText(text) {
      let raw = String(text || '').trim();
      if (!raw.trim()) return '';
      raw = raw.replace(/^Here's a concise summary of the query results in plain English:\\s*/i, '');
      raw = raw.replace(/^Based on the query result:\\s*/i, '');
      raw = raw.replace(/^\\*\\s*What was queried:/i, 'What was queried:');
      let html = esc(raw);
      html = html.replace(/\\*\\*(.+?)\\*\\*/g, '<strong>$1</strong>');
      html = html.replace(/^\\*\\s+/gm, '&#8226; ');
      html = html.replace(
        /(Top findings(?: from the query results)?(?: show that)?)/gi,
        '<span class="summary-lead">$1</span>'
      );
      return html.replace(/\\n/g, '<br>');
    }

    function renderWorkflowTimeline(result) {
      const track = $('workflow-track');
      const meta = $('workflow-meta');
      if (!track || !meta) return;
      track.innerHTML = '';
      meta.textContent = '';
      if (!result || typeof result !== 'object') return;

      const tdir = result?.tdir_case || {};
      const phase = tdir?.phase_status || {};
      const timings = result?.stage_timings_ms || {};
      const nodes = [
        { key: 'detect', label: 'Detect' },
        { key: 'triage', label: 'Triage' },
        { key: 'investigate', label: 'Investigate' },
        { key: 'respond', label: 'Respond' },
        { key: 'recover', label: 'Recover' },
      ];

      const html = [];
      nodes.forEach((node, idx) => {
        const status = String(phase[node.key] || 'planned');
        const ms = timings[node.key];
        html.push(
          `<div class="flow-node ${esc(status)}">` +
          `<div class="n-title">${esc(node.label)}</div>` +
          `<div class="n-status">status=${esc(status)}</div>` +
          `<div class="n-time">duration=${esc(fmtMs(ms))}</div>` +
          `</div>`
        );
        if (idx < nodes.length - 1) html.push('<div class="flow-arrow">&rarr;</div>');
      });
      track.innerHTML = html.join('');

      const total = fmtMs(timings.total);
      const pipeline = String(result.pipeline || tdir.pipeline || 'unknown');
      const roleTimingLabels = [
        ['query_writer', 'planner'],
        ['security_reviewer', 'security_review'],
        ['peer_reviewer_1', 'peer_review_1'],
        ['peer_reviewer_2', 'peer_review_2'],
        ['evidence_reviewer', 'evidence_review'],
        ['continuation_reviewer', 'continuation_review'],
        ['summary', 'summarize'],
      ];
      const roleJourney = roleTimingLabels
        .filter((entry) => entry[1] in timings || entry[1] in (result.node_timings_ms || {}))
        .map((entry) => {
          const stage = entry[0];
          const key = entry[1];
          const ms = (result.node_timings_ms || {})[key];
          return `${stage}=${fmtMs(ms)}`;
        })
        .join(' | ');
      meta.textContent = roleJourney
        ? `pipeline=${pipeline} total=${total}\nroles: ${roleJourney}`
        : `pipeline=${pipeline} total=${total}`;
    }

    async function refreshDomainHints() {
      const q = ($('question')?.value || '').trim();
      const shell = $('domain-hints');
      if (!shell) return;
      if (!q) {
        shell.innerHTML = '<div class="muted">Type a question to see likely index/sourcetype targets.</div>';
        return;
      }
      try {
        const resp = await fetch(`/api/environment/hint?question=${encodeURIComponent(q)}`);
        const data = await resp.json();
        const hints = Array.isArray(data?.hints) ? data.hints : [];
        if (!resp.ok) {
          shell.innerHTML = `<div class="muted">hint error: ${esc(data?.error || `http_${resp.status}`)}</div>`;
          return;
        }
        if (!hints.length) {
          shell.innerHTML = '<div class="muted">No strong domain hints found yet; investigation can still run.</div>';
          return;
        }
        shell.innerHTML = hints.map((h) => {
          const idx = String(h.index || '');
          const score = String(h.score ?? '');
          const sts = Array.isArray(h.sourcetypes) ? h.sourcetypes : [];
          const reasons = Array.isArray(h.reasons) ? h.reasons : [];
          return (
            `<div class="domain-item">` +
            `<div><span class="idx">index=${esc(idx)}</span> <span class="badge">score=${esc(score)}</span></div>` +
            `<div class="meta">sourcetypes: ${esc(sts.join(', '))}</div>` +
            `<div class="meta">why: ${esc(reasons.join('; ') || 'keyword/domain match')}</div>` +
            `</div>`
          );
        }).join('');
      } catch (err) {
        shell.innerHTML = `<div class="muted">hint fetch failed: ${esc(String(err))}</div>`;
      }
    }

    function renderTDIRCase(result) {
      const tdir = result?.tdir_case;
      if (!tdir || typeof tdir !== 'object') {
        $('tdir-card').style.display = 'none';
        $('tdir-case').innerHTML = '';
        return;
      }
      const sev = String(tdir.severity || '').toLowerCase();
      const risk = Number(tdir.risk_score || 0);
      let sevClass = 'pill-sev-info';
      if (sev === 'high') sevClass = 'pill-sev-high';
      else if (sev === 'medium') sevClass = 'pill-sev-medium';
      else if (sev === 'low') sevClass = 'pill-sev-low';

      let riskClass = 'pill-risk-low';
      let riskBand = 'low';
      if (risk >= 70) { riskClass = 'pill-risk-high'; riskBand = 'high'; }
      else if (risk >= 40) { riskClass = 'pill-risk-medium'; riskBand = 'medium'; }

      $('tdir-head').innerHTML =
        `<span class="pill ${sevClass}">Severity: ${sev || 'n/a'}</span>` +
        `<span class="pill ${riskClass}">Risk: ${risk} (${riskBand})</span>` +
        `<span class="pill">Pipeline: ${tdir.pipeline || 'n/a'}</span>`;
      $('tdir-meta').textContent =
        `Intent=${tdir.intent || ''} | Tool=${tdir.selected_tool || ''} | Rows=${tdir.rows_returned ?? ''}`;
      $('tdir-card').style.display = 'block';
      const phase = tdir.phase_status || {};
      const phaseOrder = ['detect', 'triage', 'investigate', 'respond', 'recover', 'soar_automation'];
      const phaseHtml = phaseOrder.map((key) => {
        const state = String(phase[key] ?? 'planned');
        return (
          `<div class="phase-pill ${esc(key)} ${esc(state)}">` +
          `<span class="phase-name">${esc(key.replaceAll('_', ' '))}</span>` +
          `<span class="phase-state">${esc(state.replaceAll('_', ' '))}</span>` +
          `</div>`
        );
      }).join('');
      const pivots = Array.isArray(tdir.recommended_next_pivots) ? tdir.recommended_next_pivots : [];
      const pivotHtml = pivots.length
        ? pivots.map((p) => {
            const text = String(p || '').trim();
            const priority = text.toLowerCase().startsWith('priority ');
            return `<li class="tdir-pivot-item${priority ? ' priority' : ''}">${esc(text)}</li>`;
          }).join('')
        : '<li class="tdir-pivot-item">No recommended next pivots were produced for this run.</li>';
      const hypothesis = String(tdir.incident_hypothesis || '').trim() || 'No explicit hypothesis was generated.';
      const responseNote = String(tdir.response_note || '').trim();
      $('tdir-case').innerHTML =
        `<div class="tdir-section">` +
        `<div class="tdir-label">Current Assessment</div>` +
        `<div class="tdir-hypothesis">${esc(hypothesis)}</div>` +
        `</div>` +
        `<div class="tdir-section">` +
        `<div class="tdir-label">Phase Status</div>` +
        `<div class="tdir-phase-grid">${phaseHtml}</div>` +
        `</div>` +
        `<div class="tdir-section takeaway">` +
        `<div class="tdir-kicker">Real Takeaway</div>` +
        `<div class="tdir-title">Recommended Next Pivots</div>` +
        `<div class="tdir-takeaway-copy">The most useful next moves for this investigation are below. These are the highest-value pivots produced from the current evidence, not generic follow-up ideas.</div>` +
        `<ul class="tdir-pivot-list">${pivotHtml}</ul>` +
        (responseNote ? `<div class="tdir-response-note">${esc(responseNote)}</div>` : '') +
        `</div>`;
    }

    function clearContinuationControls() {
      lastAskResult = null;
      pendingContinuationState = null;
      $('continue-shell').style.display = 'none';
      $('continue-copy').textContent = '';
      $('continue-pill').textContent = '';
      $('continue-btn').style.display = 'none';
    }

    function renderContinuationControls(result) {
      const shell = $('continue-shell');
      const copy = $('continue-copy');
      const pill = $('continue-pill');
      if (!shell || !copy || !pill) return;
      const loop = result?.loop_control;
      if (!loop || typeof loop !== 'object' || String(result?.pipeline || '') !== 'agentic_loop') {
        clearContinuationControls();
        return;
      }
      const lines = [];
      lines.push(`depth ${loop.current_depth + 1} of ${loop.max_depth}`);
      lines.push(`auto_used=${loop.auto_continue_used}/${loop.auto_continue_limit}`);
      if (loop.recommended_followup_question) lines.push(`next_question=${loop.recommended_followup_question}`);
      if (loop.recommended_followup_tool) lines.push(`next_tool=${loop.recommended_followup_tool}`);
      if (loop.auto_followup_executed) {
        lines.push(`Auto follow-up already executed in this run.`);
      }
      if (loop.human_approval_required) {
        lines.push(`Further investigation now requires explicit analyst approval.`);
        pendingContinuationState = loop.continuation_request || null;
        $('continue-btn').style.display = 'inline-block';
      } else {
        pendingContinuationState = null;
        $('continue-btn').style.display = 'none';
      }
      if (loop.stop_reason) lines.push(`control=${loop.stop_reason}`);
      pill.textContent = loop.human_approval_required ? 'Awaiting Human Approval' : 'Loop Control Active';
      copy.textContent = lines.join('\\n');
      shell.style.display = 'block';
    }

    async function executeInvestigation(options = {}) {
      function setRunProgress(value, label='') {
        runProgressValue = Math.max(0, Math.min(100, Number(value || 0)));
        $('run-progress-wrap').style.display = 'block';
        $('run-progress-bar').style.width = `${runProgressValue}%`;
        $('run-progress-pct').textContent = `${Math.round(runProgressValue)}%`;
        if (label) $('run-progress-label').textContent = label;
      }

      function startRunProgress() {
        if (runProgressTimer) clearInterval(runProgressTimer);
        setRunProgress(2, 'Starting investigation...');
        runProgressTimer = setInterval(() => {
          if (runProgressValue < 40) {
            setRunProgress(runProgressValue + 2.8, 'Planning and validating query...');
            return;
          }
          if (runProgressValue < 75) {
            setRunProgress(runProgressValue + 1.2, 'Running Splunk tools...');
            return;
          }
          if (runProgressValue < 92) {
            setRunProgress(runProgressValue + 0.45, 'Summarizing investigation evidence...');
          }
        }, 350);
      }

      function stopRunProgress(finalOk) {
        if (runProgressTimer) {
          clearInterval(runProgressTimer);
          runProgressTimer = null;
        }
        setRunProgress(100, finalOk ? 'Investigation complete.' : 'Investigation failed.');
        setTimeout(() => {
          $('run-progress-wrap').style.display = 'none';
        }, 700);
      }

      runBtn.disabled = true;
      $('status').textContent = 'Running...';
      startRunProgress();
      $('summary').innerHTML = '';
      $('model-personas').innerHTML = '';
      $('spl-details').textContent = '';
      $('spl-link').style.display = 'none';
      $('spl-query').textContent = '';
      $('spl-results').textContent = '';
      $('model-decisions').innerHTML = '';
      $('workflow-track').innerHTML = '';
      $('workflow-meta').textContent = '';
      $('tdir-card').style.display = 'none';
      $('tdir-case').textContent = '';
      $('journey').textContent = '';
      $('output').textContent = '';
      clearContinuationControls();
      try {
        const payload = {
          question: options.question || $('question').value,
          session_id: $('session').value,
          max_steps: Number($('maxsteps').value || 3),
          write_artifact: $('artifact').value === '1',
          pipeline: $('pipeline').value,
          approved_deeper_investigation: Boolean(options.approved_deeper_investigation),
          continuation_state: options.continuation_state || null,
        };
        const resp = await fetch('/api/ask', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify(payload)
        });
        setRunProgress(94, 'Finalizing investigation output...');
        const data = await resp.json();
        if (!resp.ok) {
          $('status').innerHTML = '<span class="warn">Error</span>';
          renderInvestigationJourney(data.result || data || {});
          renderWorkflowTimeline(data.result || data || {});
          $('output').textContent = JSON.stringify(data, null, 2);
          renderContinuationControls(data.result || {});
          stopRunProgress(false);
        } else {
          lastAskResult = data.result || {};
          $('status').textContent = 'Complete';
          $('summary').innerHTML = renderSummaryText(data.result?.summary || '');
          renderModelDecisions(data.result || {});
          renderTDIRCase(data.result || {});
          renderInvestigationJourney(data.result || {});
          renderWorkflowTimeline(data.result || {});
          renderContinuationControls(data.result || {});
          $('output').textContent = JSON.stringify(data, null, 2);
          stopRunProgress(true);
        }
      } catch (e) {
        $('status').innerHTML = '<span class="warn">Request failed</span>';
        $('journey').textContent = 'Unable to build investigation journey because the request failed before a structured result was returned.';
        $('output').textContent = String(e);
        stopRunProgress(false);
      } finally {
        runBtn.disabled = false;
      }
    }

    runBtn.onclick = async () => {
      await executeInvestigation({});
    };
    continueBtn.onclick = async () => {
      if (!pendingContinuationState) return;
      await executeInvestigation({
        question: (lastAskResult && (lastAskResult.root_question || lastAskResult.question)) || $('question').value,
        approved_deeper_investigation: true,
        continuation_state: pendingContinuationState,
      });
    };
    $('pipeline').addEventListener('change', updatePipelineHelp);
    updatePipelineHelp();
    let hintTimer = null;
    $('question').addEventListener('input', () => {
      if (hintTimer) clearTimeout(hintTimer);
      hintTimer = setTimeout(refreshDomainHints, 220);
    });
    refreshDomainHints();
    $('toggle-json').onclick = () => {
      const out = $('output');
      const btn = $('toggle-json');
      const showing = out.style.display !== 'none';
      out.style.display = showing ? 'none' : 'block';
      btn.textContent = showing ? 'Show JSON' : 'Hide JSON';
    };
  </script>
</body>
</html>
"""


DOCS_SHELL_HTML = """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{title}</title>
  <link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg?v=agtsmith1\" />
  <link rel=\"icon\" href=\"/favicon.ico?v=agtsmith1\" />
  <style>
    :root {{
      --bg:#0f172a; --card:#111827; --card2:#0b1220; --muted:#9ca3af; --fg:#e5e7eb;
      --line:#1f2937; --link:#93c5fd; --accent:#22c55e;
    }}
    html {{
      min-height:100%;
      background: linear-gradient(140deg,#0b1220 0%,#111827 65%,#0a1f16 100%);
      background-repeat:no-repeat;
      background-size:cover;
    }}
    body {{
      margin:0;
      min-height:100vh;
      font-family: "Trebuchet MS", "Segoe UI", "Helvetica Neue", Helvetica, sans-serif;
      background: linear-gradient(140deg,#0b1220,#111827 65%,#0a1f16);
      background-repeat:no-repeat;
      background-size:cover;
      color:var(--fg);
    }}
    .wrap {{ max-width: 1360px; min-height:calc(100vh - 28px); margin: 14px auto; padding: 0 14px 20px; box-sizing:border-box; }}
    .topnav {{
      display:flex;
      flex-wrap:nowrap;
      gap:4px;
      margin-bottom:16px;
      justify-content:flex-start;
      align-items:stretch;
      padding:6px;
      border:1px solid rgba(34,66,92,.44);
      border-radius:22px;
      background:linear-gradient(180deg, rgba(7,18,31,.82), rgba(5,12,23,.72));
      box-shadow:0 18px 34px rgba(0,0,0,.18), inset 0 1px 0 rgba(255,255,255,.03);
      backdrop-filter:blur(16px);
    }}
    .nav-item {{
      position:relative;
      display:flex;
      flex-direction:column;
      justify-content:center;
      gap:2px;
      min-width:0;
      flex:1 1 0;
      text-decoration:none;
      border:1px solid transparent;
      border-radius:16px;
      padding:8px 9px 9px;
      background:linear-gradient(180deg, rgba(255,255,255,.015), rgba(255,255,255,.008));
      color:#dce9f8;
      box-shadow:inset 0 1px 0 rgba(255,255,255,.018);
      transition:transform .16s ease, border-color .16s ease, box-shadow .16s ease, background .16s ease, color .16s ease;
      overflow:hidden;
    }}
    .nav-item-dropdown {{ overflow:visible; }}
    .nav-trigger {{
      display:flex;
      flex-direction:column;
      justify-content:center;
      gap:2px;
      min-width:0;
      text-decoration:none;
      color:inherit;
    }}
    .nav-item::after{{ content:""; position:absolute; left:12px; right:12px; bottom:0; height:2px; border-radius:999px; background:linear-gradient(90deg, rgba(96,165,250,.82), rgba(45,212,191,.82)); opacity:0; transform:scaleX(.5); transition:opacity .16s ease, transform .16s ease; }}
    .nav-item:hover {{ border-color:rgba(81,127,163,.46); background:linear-gradient(180deg, rgba(18,35,53,.74), rgba(9,21,34,.66)); transform:translateY(-1px); box-shadow:0 10px 18px rgba(2,6,23,.16), inset 0 1px 0 rgba(255,255,255,.03); color:#f8fbff; }}
    .nav-item:hover::after{{ opacity:.58; transform:scaleX(1); }}
    .nav-item.active {{ border-color:rgba(61,105,136,.5); background:linear-gradient(180deg, rgba(17,37,57,.92), rgba(10,24,39,.9)); color:#ecfdf5; box-shadow:0 12px 22px rgba(2,6,23,.18), inset 0 1px 0 rgba(255,255,255,.04); }}
    .nav-item.active::after{{ opacity:1; transform:scaleX(1); }}
    .nav-kicker {{ font-size:9px; color:#7ea2c1; text-transform:uppercase; letter-spacing:.12em; font-weight:800; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
    .nav-item.active .nav-kicker {{ color:#8fd3ff; }}
    .nav-label {{ font-size:13px; font-weight:900; line-height:1.15; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
    .nav-submenu {{
      position:absolute;
      top:calc(100% + 10px);
      left:0;
      min-width:320px;
      display:grid;
      gap:0;
      padding:8px;
      border:1px solid rgba(46,82,110,.8);
      border-radius:16px;
      background:linear-gradient(180deg, rgba(10,22,36,.98), rgba(6,14,24,.96));
      box-shadow:0 18px 34px rgba(0,0,0,.32), inset 0 1px 0 rgba(255,255,255,.03);
      opacity:0;
      visibility:hidden;
      transform:translateY(6px);
      transition:opacity .14s ease, transform .14s ease, visibility .14s ease;
      z-index:40;
    }}
    .nav-item-dropdown:hover .nav-submenu,
    .nav-item-dropdown:focus-within .nav-submenu {{
      opacity:1;
      visibility:visible;
      transform:translateY(0);
    }}
    .nav-submenu-item {{
      display:grid;
      gap:3px;
      padding:10px 12px;
      border-radius:10px;
      text-decoration:none;
      color:#e5eef8;
      transition:background .14s ease, transform .14s ease;
    }}
    .nav-submenu-item:hover {{
      background:linear-gradient(180deg, rgba(18,37,57,.92), rgba(10,24,39,.88));
      transform:translateX(1px);
    }}
    .nav-submenu-title {{
      font-size:13px;
      font-weight:900;
      line-height:1.2;
      color:#eff6ff;
    }}
    .nav-submenu-copy {{
      font-size:12px;
      line-height:1.4;
      color:#9fb4cc;
    }}
    .layout {{ display:grid; grid-template-columns: 320px minmax(0, 1fr); gap:0; align-items:start; }}
    .card {{
      background: linear-gradient(180deg, rgba(17,24,39,.96), rgba(13,20,34,.96));
      border:1px solid #213246;
      border-radius: 12px;
      padding: 16px;
      box-shadow: 0 8px 20px rgba(0,0,0,.20);
    }}
    .docs-sidebar {{
      position: sticky;
      top: 10px;
      padding: 12px 14px 18px 0;
      border-right: 1px solid #1c3145;
      margin-right: 18px;
      align-self:start;
    }}
    .docs-main {{
      min-width: 0;
      background: linear-gradient(180deg, rgba(17,24,39,.96), rgba(13,20,34,.96));
      border:1px solid #213246;
      border-radius: 12px;
      padding: 18px;
      box-shadow: 0 8px 20px rgba(0,0,0,.20);
    }}
    .docs-main details {{
      margin:14px 0 18px;
      border:1px solid #355772;
      border-radius:16px;
      background:linear-gradient(180deg, rgba(7,23,38,.96), rgba(8,28,41,.92));
      overflow:hidden;
      box-shadow:0 12px 24px rgba(0,0,0,.16);
    }}
    .docs-main details > summary {{
      position:relative;
      cursor:pointer;
      list-style:none;
      padding:14px 18px 14px 48px;
      color:#ecfeff;
      font-weight:900;
      line-height:1.45;
      background:linear-gradient(135deg, rgba(6,78,59,.88), rgba(8,47,73,.94));
      border-bottom:1px solid rgba(70,116,144,.28);
    }}
    .docs-main details > summary::-webkit-details-marker {{ display:none; }}
    .docs-main details > summary::before {{
      content:"+";
      position:absolute;
      left:16px;
      top:50%;
      transform:translateY(-50%);
      width:20px;
      height:20px;
      display:grid;
      place-items:center;
      border-radius:999px;
      background:rgba(236,254,255,.14);
      color:#f0fdfa;
      font-size:15px;
      font-weight:900;
      border:1px solid rgba(236,254,255,.18);
    }}
    .docs-main details[open] > summary::before {{ content:"−"; }}
    .docs-main details > :not(summary) {{
      margin-left:18px;
      margin-right:18px;
    }}
    .docs-main details > p:last-child,
    .docs-main details > ul:last-child,
    .docs-main details > ol:last-child,
    .docs-main details > pre:last-child,
    .docs-main details > h3:last-child {{
      margin-bottom:18px;
    }}
    .docs-rail-title {{
      margin:0 0 6px;
      font-size:22px;
      color:#eef4fb;
    }}
    .docs-rail-sub {{
      margin:0 0 12px;
      color:#8ea4ba;
      font-size:13px;
      line-height:1.5;
    }}
    h1 {{ margin:0 0 8px; font-size:24px; }}
    h2 {{ margin:14px 0 8px; font-size:18px; }}
    h3 {{ margin:12px 0 7px; font-size:16px; }}
    p {{ line-height:1.6; margin: 8px 0; }}
    .muted {{ color: var(--muted); font-size:13px; }}
    ul, ol {{ margin:8px 0 10px; padding-left: 22px; line-height:1.55; }}
    li {{ margin:4px 0; }}
    a {{ color:var(--link); }}
    pre {{
      white-space: pre-wrap;
      background:#020617;
      border:1px solid var(--line);
      border-radius:10px;
      padding:12px;
      overflow:auto;
      line-height:1.45;
      font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
      font-size:13px;
    }}
    .mermaid {{
      background:#020617;
      border:1px solid var(--line);
      border-radius:12px;
      padding:12px;
      overflow:auto;
      margin:10px 0 14px;
    }}
    code {{
      background:var(--card2);
      border:1px solid var(--line);
      border-radius:4px;
      padding:1px 4px;
      font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
      font-size: 90%;
    }}
    .doc-link {{
      display:block;
      padding:7px 10px;
      border-radius:8px;
      text-decoration:none;
      color:var(--fg);
      border:1px solid transparent;
      font-size:13px;
    }}
    .doc-link:hover {{ background:#0d1d32; border-color:#2f4a68; }}
    .doc-link.active {{ background:#0f2a3d; border-color:#3c7aa3; color:#dbeafe; }}
    .doc-link-title {{
      display:block;
      font-weight:700;
      color:#e5eef8;
      margin-bottom:2px;
    }}
    .doc-link-meta {{
      display:block;
      color:#8ea4ba;
      font-size:11.5px;
      line-height:1.35;
    }}
    .doc-group {{
      margin-top:10px;
      border:0;
      border-radius:0;
      background:transparent;
      overflow:visible;
    }}
    .doc-group[open] {{ background:transparent; }}
    .section-title {{
      margin:0;
      padding:8px 0;
      color:#c8d1dc;
      font-size:12px;
      text-transform:uppercase;
      letter-spacing:.7px;
      font-weight:700;
      list-style:none;
      cursor:pointer;
      border-bottom:0;
      background:transparent;
    }}
    .doc-group summary::-webkit-details-marker {{ display:none; }}
    .section-title::after {{
      content: "▾";
      float:right;
      color:#7ea6c9;
      font-size:12px;
      transform: translateY(1px);
    }}
    .doc-group:not([open]) .section-title::after {{ content: "▸"; }}
    .section-links {{
      padding:2px 0 4px 10px;
      margin-left:6px;
      border-left:1px solid #22384d;
    }}
    .search {{
      width:100%; box-sizing:border-box; margin:8px 0 10px; background:var(--card2);
      color:var(--fg); border:1px solid #374151; border-radius:8px; padding:9px;
      font-size:14px;
    }}
    .doc-brand-title {{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:12px;
      margin-bottom:8px;
    }}
    .doc-brand-icon {{
      width:28px;
      height:28px;
      border-radius:7px;
      border:1px solid #27415a;
      background:#07111f;
      flex:0 0 auto;
    }}
    .hero {{ display:grid; grid-template-columns: 1fr 1fr; gap:12px; }}
    .guide-grid {{ display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap:12px; margin-top:12px; }}
    .guide-card {{
      background:#0b1626;
      border:1px solid #24384f;
      border-radius:12px;
      padding:14px;
    }}
    .guide-card h2 {{
      margin:0 0 6px;
      font-size:17px;
      color:#e5eef8;
    }}
    .guide-card p {{
      margin:0 0 10px;
      color:#9cb0c4;
      font-size:13px;
      line-height:1.55;
    }}
    .guide-links {{
      display:flex;
      flex-direction:column;
      gap:8px;
    }}
    .guide-link {{
      display:block;
      text-decoration:none;
      border:1px solid #294560;
      background:#0d1c2d;
      border-radius:10px;
      padding:10px 11px;
      color:#dbeafe;
    }}
    .guide-link:hover {{ border-color:#5ea6d6; background:#102338; }}
    .guide-link strong {{
      display:block;
      margin-bottom:3px;
      font-size:13px;
    }}
    .guide-link span {{
      display:block;
      color:#9bb1c6;
      font-size:12px;
      line-height:1.4;
    }}
    .badge {{ display:inline-block; border:1px solid #2e4658; background:#0a2330; border-radius:999px; padding:4px 10px; font-size:12px; color:#b9e6ff; }}
    .statline {{ display:flex; gap:10px; flex-wrap:wrap; margin:8px 0 10px; }}
    .env-list {{ display:flex; flex-direction:column; gap:10px; margin-top:10px; }}
    .env-card {{
      background: var(--card2);
      border:1px solid var(--line);
      border-radius:10px;
      padding:0;
      min-width:0;
    }}
    .env-card summary {{
      cursor:pointer;
      list-style:none;
      padding:10px 12px;
      border-radius:10px;
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:10px;
      background:#0a1b2d;
    }}
    .env-card summary::-webkit-details-marker {{ display:none; }}
    .env-card .env-body {{ padding:10px 12px; border-top:1px solid #213246; }}
    .env-sublist {{ display:flex; flex-direction:column; gap:8px; }}
    .env-subcard {{
      background: linear-gradient(180deg, rgba(8,22,38,0.92), rgba(6,17,30,0.92));
      border:1px solid #213246;
      border-radius:10px;
      overflow:hidden;
    }}
    .env-subcard summary {{
      cursor:pointer;
      list-style:none;
      padding:10px 12px;
      display:flex;
      justify-content:space-between;
      align-items:flex-start;
      gap:10px;
      background:#0a1626;
    }}
    .env-subcard summary::-webkit-details-marker {{ display:none; }}
    .env-subbody {{ padding:10px 12px; border-top:1px solid #213246; overflow-x:auto; }}
    .env-submeta {{ display:flex; flex-wrap:wrap; gap:8px; align-items:center; }}
    .env-preview {{ color:#b7cadb; font-size:12px; line-height:1.45; margin-top:4px; }}
    .env-title {{
      font-weight:700;
      color:#dbeafe;
      font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
      overflow-wrap:anywhere;
    }}
    .mono {{
      font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
      overflow-wrap:anywhere;
    }}
    .kv {{ margin:5px 0; line-height:1.45; }}
    .env-table {{
      width:100%;
      border-collapse:collapse;
      margin-top:8px;
      font-size:13px;
      min-width:980px;
      table-layout:auto;
    }}
    .env-table th, .env-table td {{
      border:1px solid #213246;
      padding:6px 8px;
      text-align:left;
      vertical-align:top;
    }}
    .env-table th {{ background:#091726; color:#bfdbfe; }}
    .env-table th:first-child, .env-table td:first-child {{ white-space:nowrap; width:180px; }}
    .env-table th:nth-child(3), .env-table td:nth-child(3),
    .env-table th:nth-child(4), .env-table td:nth-child(4) {{ white-space:nowrap; width:92px; }}
    .svg-wrap {{
      overflow:auto;
      border:1px solid var(--line);
      border-radius:10px;
      background:
        radial-gradient(circle at top left, rgba(34,197,94,.08), transparent 32%),
        radial-gradient(circle at bottom right, rgba(59,130,246,.12), transparent 34%),
        linear-gradient(180deg, #030712, #07111f);
      padding:16px;
    }}
    .arch-hero {{
      display:block;
      margin-bottom:14px;
    }}
    .arch-hero-card {{
      min-width:0;
      border:1px solid #24384f;
      border-radius:16px;
      padding:16px 18px;
      background:linear-gradient(180deg, rgba(8,21,37,.96), rgba(7,17,31,.92));
      box-shadow:0 16px 34px rgba(0,0,0,.26);
    }}
    .arch-kicker {{
      margin:0 0 8px;
      color:#7dd3fc;
      text-transform:uppercase;
      letter-spacing:.9px;
      font-size:11px;
      font-weight:700;
    }}
    .arch-hero h2 {{
      margin:0 0 8px;
      font-size:30px;
      line-height:1.1;
      color:#f8fbff;
    }}
    .arch-hero p {{
      margin:0;
      color:#b8c7d9;
      line-height:1.75;
      font-size:14px;
    }}
    .arch-hero-lead {{
      max-width:1040px;
    }}
    .arch-visio {{
      margin-bottom:14px;
      border:1px solid #22384d;
      border-radius:18px;
      background:linear-gradient(180deg, rgba(8,21,37,.96), rgba(7,17,31,.92));
      box-shadow:0 14px 28px rgba(0,0,0,.22);
      overflow:auto;
      padding:10px;
    }}
    .arch-visio-svg {{
      display:block;
      width:100%;
      min-width:1080px;
      height:auto;
    }}
    .arch-visio-caption {{
      margin:8px 4px 0;
      color:#8fb0cb;
      font-size:12px;
      line-height:1.55;
    }}
    .arch-endpoint-grid {{
      display:grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap:10px;
      align-items:stretch;
    }}
    .arch-endpoint-card {{
      min-width:0;
      border-radius:18px;
      padding:16px;
      border:1px solid #234159;
      background:linear-gradient(180deg, rgba(11,22,38,.96), rgba(7,17,31,.92));
      box-shadow:0 14px 28px rgba(0,0,0,.22);
      position:relative;
      overflow:hidden;
    }}
    .arch-endpoint-card::before {{
      content:"";
      position:absolute;
      inset:0 0 auto 0;
      height:4px;
      background:linear-gradient(90deg, #22c55e, #38bdf8);
    }}
    .arch-endpoint-topline {{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      margin-bottom:8px;
    }}
    .arch-endpoint-card h3 {{
      margin:0;
      color:#f5f9ff;
      font-size:18px;
      line-height:1.2;
    }}
    .arch-endpoint-kicker {{
      margin:0 0 10px;
      color:#8fd8ff;
      font-size:11px;
      text-transform:uppercase;
      letter-spacing:.8px;
      font-weight:700;
    }}
    .arch-endpoint-copy {{
      margin:0;
      color:#bfd0df;
      font-size:12px;
      line-height:1.6;
    }}
    .arch-endpoint-meta {{
      margin-top:10px;
      padding-top:10px;
      border-top:1px solid rgba(36,64,88,.8);
      color:#8fb0cb;
      font-size:11px;
      line-height:1.45;
    }}
    .arch-step-badge {{
      display:inline-flex;
      align-items:center;
      justify-content:center;
      min-width:28px;
      height:28px;
      padding:0 8px;
      border-radius:999px;
      border:1px solid #2e506e;
      background:#0a1626;
      color:#dbeafe;
      font-size:11px;
      font-weight:800;
      flex:0 0 auto;
    }}
    .arch-connection-band {{
      display:grid;
      grid-template-columns: repeat(13, minmax(0, 1fr));
      gap:8px;
      align-items:center;
      margin:12px 0;
    }}
    .arch-connection-link {{
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:40px;
      border-radius:999px;
      border:1px solid #24435d;
      background:linear-gradient(180deg, rgba(8,21,37,.94), rgba(7,17,31,.88));
      color:#7dd3fc;
      font-size:12px;
      font-weight:800;
      text-transform:uppercase;
      letter-spacing:.06em;
      text-align:center;
      padding:0 6px;
    }}
    .arch-connection-link.arrow {{
      font-size:22px;
      font-weight:900;
      letter-spacing:0;
      color:#a5f3fc;
      text-shadow:0 0 18px rgba(125,211,252,.2);
    }}
    .arch-handoff-grid {{
      display:grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap:10px;
      margin-top:12px;
    }}
    .arch-handoff-card {{
      border:1px solid #22384d;
      border-radius:14px;
      padding:12px 13px;
      background:linear-gradient(180deg, rgba(11,22,38,.96), rgba(7,17,31,.9));
      color:#ccdae7;
      font-size:12px;
      line-height:1.55;
    }}
    .arch-handoff-card strong {{
      display:block;
      margin-bottom:6px;
      color:#f5f9ff;
      font-size:12px;
      text-transform:uppercase;
      letter-spacing:.6px;
    }}
    .arch-map {{
      display:grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap:14px;
      align-items:stretch;
    }}
    .arch-box {{
      min-width:0;
      border-radius:18px;
      padding:16px 18px;
      background:linear-gradient(180deg, rgba(15,23,42,.98), rgba(11,18,32,.94));
      border:1px solid #244058;
      box-shadow:0 16px 32px rgba(0,0,0,.28);
      position:relative;
      overflow:hidden;
    }}
    .arch-box::before {{
      content:"";
      position:absolute;
      inset:0 0 auto 0;
      height:4px;
      background:linear-gradient(90deg, #22c55e, #38bdf8);
    }}
    .arch-box.secondary {{
      border-color:#254866;
      background:linear-gradient(180deg, rgba(11,18,32,.98), rgba(8,17,31,.94));
    }}
    .arch-box.tertiary {{
      border-color:#244862;
      background:linear-gradient(180deg, rgba(10,22,38,.98), rgba(7,17,31,.94));
    }}
    .arch-box h3 {{
      margin:0 0 12px;
      font-size:18px;
      color:#f2f7fd;
      position:relative;
    }}
    .arch-box ul {{
      margin:0;
      padding-left:18px;
    }}
    .arch-box li {{
      margin:8px 0;
      color:#d7e0ea;
      line-height:1.55;
    }}
    .arch-note {{
      margin-top:14px;
      padding:10px 12px 0;
      border-top:1px solid #243245;
      color:#a7b8c9;
      font-size:12px;
      line-height:1.5;
    }}
    .arch-box-label {{
      display:inline-flex;
      align-items:center;
      border-radius:999px;
      border:1px solid #27415a;
      background:#081525;
      color:#8fd8ff;
      padding:4px 9px;
      font-size:11px;
      text-transform:uppercase;
      letter-spacing:.7px;
      margin-bottom:10px;
      font-weight:700;
    }}
    .arch-subgrid {{
      display:grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap:12px;
      align-items:stretch;
      margin-top:12px;
    }}
    .arch-tier {{
      margin-bottom:12px;
    }}
    .arch-tier-label {{
      display:flex;
      align-items:center;
      gap:10px;
      margin:0 0 10px;
      color:#9fc2dd;
      font-size:11px;
      text-transform:uppercase;
      letter-spacing:.8px;
      font-weight:700;
    }}
    .arch-tier-label::after {{
      content:"";
      height:1px;
      flex:1 1 auto;
      background:linear-gradient(90deg, rgba(56,189,248,.7), rgba(34,197,94,.18));
    }}
    .arch-flow-ribbon {{
      display:grid;
      grid-template-columns: minmax(0, 1fr) 34px minmax(0, 1fr) 34px minmax(0, 1fr) 34px minmax(0, 1fr) 34px minmax(0, 1fr);
      gap:12px;
      align-items:stretch;
      margin-top:14px;
      padding:12px 14px;
      border:1px solid #22384d;
      border-radius:14px;
      background:linear-gradient(180deg, rgba(8,21,37,.94), rgba(7,17,31,.88));
    }}
    .arch-flow-step {{
      display:flex;
      flex-direction:column;
      justify-content:space-between;
      min-height:108px;
      padding:12px;
      border-radius:14px;
      border:1px solid #2a4661;
      background:linear-gradient(180deg, #0b1728, #08111f);
      color:#deecfb;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.03);
    }}
    .arch-flow-step-title {{
      font-size:13px;
      font-weight:800;
      line-height:1.35;
      color:#f2f8ff;
      margin-bottom:8px;
    }}
    .arch-flow-step-copy {{
      font-size:12px;
      line-height:1.5;
      color:#b5c7d8;
    }}
    .arch-flow-step-tag {{
      align-self:flex-start;
      margin-top:10px;
      border-radius:999px;
      border:1px solid #27415a;
      background:#081525;
      color:#8fd8ff;
      padding:4px 8px;
      font-size:10px;
      text-transform:uppercase;
      letter-spacing:.7px;
      font-weight:700;
    }}
    .arch-flow-arrow-node {{
      display:flex;
      align-items:center;
      justify-content:center;
      align-self:center;
      min-height:42px;
      border-radius:999px;
      border:1px solid #24435d;
      background:linear-gradient(180deg, rgba(8,21,37,.94), rgba(7,17,31,.88));
      color:#7dd3fc;
      font-size:18px;
      font-weight:900;
      box-shadow:0 10px 18px rgba(0,0,0,.18);
    }}
    .arch-loop-strip {{
      display:flex;
      flex-wrap:wrap;
      gap:10px;
      align-items:center;
      margin-top:12px;
      padding:10px 12px;
      border:1px dashed #24435d;
      border-radius:14px;
      background:linear-gradient(180deg, rgba(7,17,31,.88), rgba(5,13,24,.84));
    }}
    .arch-loop-chip {{
      display:inline-flex;
      align-items:center;
      min-height:32px;
      padding:6px 10px;
      border-radius:999px;
      border:1px solid #264560;
      background:#081525;
      color:#deecfb;
      font-size:12px;
      line-height:1.3;
      font-weight:700;
    }}
    .arch-loop-arrow {{
      color:#7dd3fc;
      font-size:17px;
      font-weight:900;
      line-height:1;
    }}
    .arch-interop-grid {{
      display:grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap:12px;
      margin-top:14px;
    }}
    .arch-interop-card {{
      border:1px solid #22384d;
      border-radius:14px;
      padding:12px 13px;
      background:linear-gradient(180deg, rgba(11,22,38,.96), rgba(7,17,31,.9));
    }}
    .arch-interop-title {{
      margin:0 0 8px;
      color:#eef6ff;
      font-size:13px;
      font-weight:800;
      text-transform:uppercase;
      letter-spacing:.6px;
    }}
    .arch-interop-line {{
      margin:6px 0;
      color:#c7d4e2;
      font-size:12px;
      line-height:1.5;
    }}
    .arch-interop-line strong {{
      color:#f4f8fd;
      font-weight:800;
    }}
    .arch-pill-row {{
      display:flex;
      flex-wrap:wrap;
      gap:8px;
      margin-top:12px;
    }}
    .arch-pill {{
      display:inline-flex;
      align-items:center;
      border-radius:999px;
      border:1px solid #2c4660;
      background:linear-gradient(180deg, #091726, #08111f);
      color:#dbeafe;
      padding:4px 10px;
      font-size:12px;
      line-height:1.2;
    }}
    .arch-panels {{ display:grid; grid-template-columns: repeat(3,minmax(0,1fr)); gap:12px; margin-top:14px; }}
    .arch-panel {{ background:linear-gradient(180deg, rgba(11,18,32,.96), rgba(8,17,31,.92)); border:1px solid #213246; border-radius:14px; padding:14px; }}
    .arch-panel h3 {{ margin-top:0; margin-bottom:10px; font-size:16px; color:#eff6ff; }}
    .arch-panel p, .arch-panel li {{ color:#c4d1df; }}
    .arch-detail-shell {{
      margin-top:16px;
      border:1px solid #22384d;
      border-radius:14px;
      background:linear-gradient(180deg, rgba(8,21,37,.92), rgba(7,17,31,.88));
      padding:12px 14px;
    }}
    .arch-detail-shell summary {{
      cursor:pointer;
      color:#e8f2fc;
      font-weight:800;
      font-size:14px;
      list-style:none;
    }}
    .arch-detail-shell summary::-webkit-details-marker {{ display:none; }}
    .arch-detail-sub {{
      color:#97adc2;
      font-size:12px;
      margin-top:4px;
      line-height:1.5;
    }}
    .arch-detail-body {{
      margin-top:14px;
    }}
    .guided {{
      margin-top: 14px;
      background: var(--card2);
      border:1px solid var(--line);
      border-radius:10px;
      padding:10px;
    }}
    .guided summary {{
      cursor:pointer;
      font-weight:700;
      color:#dbeafe;
      margin-bottom:8px;
    }}
    .guided .guided-body {{
      margin-top:8px;
    }}
    .step {{
      margin: 10px 0;
      border:1px solid #243245;
      border-radius:8px;
      padding:8px;
      background:#07111f;
    }}
    .step-title {{
      font-weight:700;
      color:#dbeafe;
      margin-bottom:4px;
      font-size:13px;
    }}
    .mini-flow {{
      margin-top:8px;
      display:flex;
      flex-wrap:wrap;
      align-items:center;
      gap:6px;
    }}
    .mini-node {{
      display:inline-block;
      background:#0b2130;
      border:1px solid #1d4f66;
      border-radius:6px;
      color:#dbeafe;
      padding:4px 8px;
      font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
      font-size:11px;
      line-height:1.3;
    }}
    .mini-arrow {{
      color:#93c5fd;
      font-weight:700;
      font-size:14px;
      line-height:1;
    }}
    .welcome-modal-backdrop {{
      position:fixed;
      inset:0;
      display:none;
      align-items:center;
      justify-content:center;
      padding:20px;
      background:rgba(2,6,23,.62);
      backdrop-filter:blur(8px);
      z-index:120;
    }}
    .welcome-modal-backdrop.open {{ display:flex; }}
    .welcome-modal {{
      width:min(540px,94vw);
      border:1px solid #294560;
      border-radius:22px;
      padding:22px;
      background:linear-gradient(165deg,#091727,#07111f 58%,#0b1d17);
      box-shadow:0 28px 60px rgba(0,0,0,.42);
    }}
    .welcome-kicker {{
      display:inline-flex;
      align-items:center;
      gap:8px;
      padding:6px 10px;
      border-radius:999px;
      border:1px solid #294560;
      background:#0b2130;
      color:#bde6ff;
      font-size:12px;
      font-weight:800;
    }}
    .welcome-title {{
      margin:14px 0 8px;
      font-size:28px;
      line-height:1.05;
      letter-spacing:.2px;
      color:#f8fafc;
    }}
    .welcome-copy {{
      margin:0 0 16px;
      color:#a8bfd7;
      font-size:14px;
      line-height:1.65;
    }}
    .welcome-actions {{
      display:flex;
      gap:10px;
      flex-wrap:wrap;
      align-items:center;
    }}
    .welcome-btn {{
      appearance:none;
      border:1px solid #315a79;
      border-radius:14px;
      padding:12px 16px;
      background:linear-gradient(180deg,#16324a,#102435);
      color:#dbeafe;
      font-weight:900;
      cursor:pointer;
      font-size:14px;
    }}
    .welcome-btn.primary {{
      border:0;
      background:linear-gradient(135deg,#22c55e,#16a34a);
      color:#03230f;
    }}
    @media (max-width: 980px) {{
      .layout {{ grid-template-columns: 1fr; gap:14px; }}
      .docs-sidebar {{
        position: relative;
        border-right:0;
        margin-right:0;
        padding-right:0;
      }}
      .hero {{ grid-template-columns: 1fr; }}
      .guide-grid {{ grid-template-columns: 1fr; }}
      .arch-hero {{ grid-template-columns: 1fr; }}
      .arch-summary-grid {{ grid-template-columns: 1fr; }}
      .arch-visio {{ grid-template-columns: 1fr; }}
      .arch-endpoint-grid {{ grid-template-columns: 1fr; }}
      .arch-connection-band {{ grid-template-columns: 1fr; }}
      .arch-handoff-grid {{ grid-template-columns: 1fr; }}
      .arch-map {{ grid-template-columns: 1fr; }}
      .arch-subgrid {{ grid-template-columns: 1fr; }}
      .arch-flow-ribbon {{ grid-template-columns: 1fr; }}
      .arch-flow-arrow-node {{ min-height:28px; }}
      .arch-interop-grid {{ grid-template-columns: 1fr; }}
      .arch-panels {{ grid-template-columns: 1fr; }}
      .env-list {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body data-smith-user="{onboarding_user}" data-smith-role="{onboarding_role}">
  <div class=\"wrap\">
    {nav}
    {body}
  </div>
  {onboarding_modal}
  <script type="module">
    import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
    mermaid.initialize({{ startOnLoad: true, theme: 'dark', securityLevel: 'loose' }});
    window.mermaid = mermaid;
  </script>
  <script>
    (() => {{
      const role = document.body.getAttribute('data-smith-role') || '';
      const username = document.body.getAttribute('data-smith-user') || '';
      const path = window.location.pathname || '';
      if(role !== 'admin' || !username || path === '/configure') {{
        return;
      }}
      const snoozeKey = `smith-admin-config-snooze:${{username}}`;
      const skipKey = `smith-admin-config-skip:${{username}}`;
      if(window.localStorage.getItem(snoozeKey) === '1') {{
        return;
      }}
      if(window.sessionStorage.getItem(skipKey) === '1') {{
        return;
      }}
      const backdrop = document.getElementById('smith-welcome-modal');
      if(!backdrop) {{
        return;
      }}
      const open = () => backdrop.classList.add('open');
      const close = () => backdrop.classList.remove('open');
      window.setTimeout(open, 220);
      const goBtn = document.getElementById('smith-welcome-go');
      const skipBtn = document.getElementById('smith-welcome-skip');
      const snoozeBtn = document.getElementById('smith-welcome-snooze');
      if(goBtn) {{
        goBtn.onclick = () => {{
          close();
          window.location.href = '/configure';
        }};
      }}
      if(skipBtn) {{
        skipBtn.onclick = () => {{
          window.sessionStorage.setItem(skipKey, '1');
          fetch('/api/session/onboarding', {{
            method:'POST',
            headers:{{'Content-Type':'application/json'}},
            body: JSON.stringify({{ action:'skip' }})
          }}).finally(() => close());
        }};
      }}
      if(snoozeBtn) {{
        snoozeBtn.onclick = () => {{
          window.localStorage.setItem(snoozeKey, '1');
          close();
        }};
      }}
      backdrop.addEventListener('click', (event) => {{
        if(event.target === backdrop) {{
          window.sessionStorage.setItem(skipKey, '1');
          close();
        }}
      }});
    }})();
  </script>
</body>
</html>
"""


def _safe_docs_path(path_value: str) -> Path | None:
    if not path_value:
        return None
    resolved = (DOCS_ROOT / path_value).resolve()
    try:
        resolved.relative_to(DOCS_ROOT.resolve())
    except Exception:
        return None
    if not resolved.exists() or not resolved.is_file():
        return None
    return resolved


def _list_docs_files() -> list[str]:
    files: list[str] = []
    if not DOCS_ROOT.exists():
        return files
    for p in DOCS_ROOT.rglob("*"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(DOCS_ROOT))
        if rel.startswith("logs/"):
            continue
        if rel == "build_log.md":
            continue
        if p.suffix.lower() not in {".md", ".json", ".csv", ".txt"}:
            continue
        files.append(rel)
    return sorted(files)


DOC_SECTION_ORDER = [
    "Start Here",
    "Business View",
    "Platform Details",
    "Architecture",
    "Operator Guides",
    "Reference",
]

DOC_LABELS: dict[str, tuple[str, str]] = {
    "whitepapers/project_one_page_white_paper.md": (
        "What A.G.E.N.T. Smith Is",
        "Best first read for leaders and new users.",
    ),
    "project_overview.md": (
        "Documentation Guide",
        "Where to start and where to go next.",
    ),
    "whitepapers/executive_white_paper.md": (
        "Executive Summary",
        "Business value, controls, and readiness framing.",
    ),
    "whitepapers/technical_deep_dive.md": (
        "Technical Deep Dive",
        "Architecture, runtime flow, controls, and planned expansion.",
    ),
    "architecture/system_design.md": (
        "System Design",
        "Current platform shape and planned extensions.",
    ),
    "architecture/network_diagram.md": (
        "Network Diagram",
        "Hosts, trust boundaries, ports, and future components.",
    ),
    "architecture/tdir_core_blueprint.md": (
        "TDIR Blueprint",
        "Current Detect, Triage, and Investigate operating model.",
    ),
    "runbooks/health_check.md": (
        "Health Check",
        "Short post-install health check for an already-configured runtime.",
    ),
    "runbooks/initial_setup.md": (
        "Initial Setup Guide",
        "Step-by-step setup for a new machine and new operator.",
    ),
    "runbooks/demo_walkthrough.md": (
        "Demo Walkthrough",
        "Recommended presentation path for stakeholders.",
    ),
    "runbooks/daily_ops.md": (
        "Daily Operations",
        "Routine checks for the current deployment.",
    ),
    "model_strategy.md": (
        "Model Strategy",
        "Why each model role exists and how they are used.",
    ),
    "splunk_integration.md": (
        "Splunk Integration",
        "How Splunk MCP access and retrieval are wired.",
    ),
    "langgraph_plan.md": (
        "LangGraph Notes",
        "Historical implementation notes and reference context.",
    ),
}


def _doc_label(path: str) -> tuple[str, str]:
    if path in DOC_LABELS:
        return DOC_LABELS[path]
    stem = Path(path).stem.replace("_", " ").replace("-", " ").strip().title()
    return stem, path


def _doc_section(path: str) -> str:
    if path == "whitepapers/project_one_page_white_paper.md":
        return "Start Here"
    if path == "project_overview.md":
        return "Start Here"
    if path == "whitepapers/executive_white_paper.md":
        return "Business View"
    if path == "whitepapers/technical_deep_dive.md":
        return "Platform Details"
    if path in {"model_strategy.md", "splunk_integration.md"}:
        return "Platform Details"
    if path == "langgraph_plan.md":
        return "Reference"
    if path.startswith("architecture/"):
        return "Architecture"
    if path in {
        "runbooks/daily_ops.md",
        "runbooks/demo_walkthrough.md",
        "runbooks/weekly_maintenance.md",
        "runbooks/spl_quality_pass.md",
    }:
        return "Reference"
    if path.startswith("runbooks/"):
        return "Operator Guides"
    if path.startswith("reference/"):
        return "Reference"
    return "Platform Details"


def _group_docs(files: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for f in files:
        grouped[_doc_section(f)].append(f)
    for key in grouped:
        grouped[key] = sorted(grouped[key], key=lambda p: (_doc_label(p)[0].lower(), p.lower()))
    ordered: dict[str, list[str]] = {}
    for section in DOC_SECTION_ORDER:
        if grouped.get(section):
            ordered[section] = grouped[section]
    for section in sorted(grouped.keys()):
        if section not in ordered:
            ordered[section] = grouped[section]
    return ordered


def _render_docs_sidebar(active_path: str = "") -> str:
    files = _list_docs_files()
    grouped = _group_docs(files)
    sections: list[str] = []
    for section, section_files in grouped.items():
        items = []
        for path in section_files:
            active = " active" if path == active_path else ""
            qp = quote(path)
            label, desc = _doc_label(path)
            items.append(
                f'<a class="doc-link{active}" href="/docs/view?path={qp}" '
                f'data-doc-path="{html.escape(path)}" data-doc-label="{html.escape(label)}">'
                f'<span class="doc-link-title">{html.escape(label)}</span>'
                f'<span class="doc-link-meta">{html.escape(desc)}</span>'
                "</a>"
            )
        open_attr = " open" if section != "Reference" else ""
        sections.append(
            f'<details class="doc-group"{open_attr}>'
            f'<summary class="section-title">{html.escape(section)}</summary>'
            f'<div class="section-links">{"".join(items)}</div>'
            "</details>"
        )
    return "\n".join(sections)


def _render_markdown_simple(text: str) -> str:
    lines = text.splitlines()
    out: list[str] = []
    in_code = False
    code_lang = ""
    in_ul = False
    in_ol = False

    def render_inline(value: str) -> str:
        placeholders: dict[str, str] = {}
        token_index = 0

        def stash(rendered: str) -> str:
            nonlocal token_index
            token = f"__INLINE_TOKEN_{token_index}__"
            token_index += 1
            placeholders[token] = rendered
            return token

        def _code_repl(match: re.Match[str]) -> str:
            return stash(f"<code>{html.escape(match.group(1))}</code>")

        def _link_repl(match: re.Match[str]) -> str:
            label = render_inline(match.group(1))
            href = html.escape(match.group(2), quote=True)
            return stash(f'<a href="{href}">{label}</a>')

        value = re.sub(r"`([^`]+)`", _code_repl, value)
        value = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", _link_repl, value)
        rendered = html.escape(value)
        for token, replacement in placeholders.items():
            rendered = rendered.replace(token, replacement)
        return rendered

    def close_lists() -> None:
        nonlocal in_ul, in_ol
        if in_ul:
            out.append("</ul>")
            in_ul = False
        if in_ol:
            out.append("</ol>")
            in_ol = False

    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()

        if stripped.startswith("```"):
            close_lists()
            if not in_code:
                code_lang = stripped[3:].strip().lower()
                if code_lang == "mermaid":
                    out.append('<div class="mermaid">')
                else:
                    out.append("<pre><code>")
                in_code = True
            else:
                if code_lang == "mermaid":
                    out.append("</div>")
                else:
                    out.append("</code></pre>")
                in_code = False
                code_lang = ""
            continue

        if in_code:
            out.append(html.escape(line))
            continue

        if not stripped:
            close_lists()
            out.append("")
            continue

        if (
            stripped.startswith("<details")
            or stripped.startswith("</details")
            or stripped.startswith("<summary")
            or stripped.startswith("</summary")
        ):
            close_lists()
            out.append(stripped)
            continue

        if stripped.startswith("### "):
            close_lists()
            out.append(f"<h3>{render_inline(stripped[4:])}</h3>")
            continue
        if stripped.startswith("## "):
            close_lists()
            out.append(f"<h2>{render_inline(stripped[3:])}</h2>")
            continue
        if stripped.startswith("# "):
            close_lists()
            out.append(f"<h1>{render_inline(stripped[2:])}</h1>")
            continue

        if stripped.startswith("- "):
            if in_ol:
                out.append("</ol>")
                in_ol = False
            if not in_ul:
                out.append("<ul>")
                in_ul = True
            out.append(f"<li>{render_inline(stripped[2:])}</li>")
            continue

        if len(stripped) > 2 and stripped[0].isdigit() and stripped[1] == "." and stripped[2] == " ":
            if in_ul:
                out.append("</ul>")
                in_ul = False
            if not in_ol:
                out.append("<ol>")
                in_ol = True
            out.append(f"<li>{render_inline(stripped[3:])}</li>")
            continue

        close_lists()
        out.append(f"<p>{render_inline(stripped)}</p>")

    close_lists()
    if in_code:
        if code_lang == "mermaid":
            out.append("</div>")
        else:
            out.append("</code></pre>")
    rendered = "\n".join(out)
    rendered = rendered.replace("<pre><code>\n", "<pre><code>")
    rendered = rendered.replace('<div class="mermaid">\n', '<div class="mermaid">')
    return rendered


def _architecture_svg() -> str:
    return """
<div class="arch-tier">
  <div class="arch-tier-label">Primary Runtime</div>
  <div class="arch-map" role="img" aria-label="A.G.E.N.T. Smith architecture map">
    <section class="arch-box">
      <div class="arch-box-label">Orchestration</div>
      <h3>Controller Node (Linux host, for example a Raspberry Pi)</h3>
      <ul>
        <li><code>web_ui_server.py</code> serves the LAN UI on port <code>8787</code>.</li>
        <li>Runs the minimal, multi-model, and agentic investigation flows.</li>
        <li>Applies guardrails, query-policy checks, and deterministic execution gates.</li>
        <li>Handles MCP client calls, evidence packaging, and response assembly.</li>
        <li>Agentic controller logic enforces bounded pivots and completion decisions.</li>
        <li>Docs portal reads <code>docs/</code> directly and publishes the current platform narrative.</li>
      </ul>
      <div class="arch-note">Trust boundary: Splunk tools execute only after deterministic checks pass. Unsafe or non-read-only requests are blocked before execution.</div>
    </section>
    <section class="arch-box secondary">
      <div class="arch-box-label">Reasoning Layer</div>
      <h3>LLM Host (Windows + RTX 3090)</h3>
      <ul>
        <li>Remote Ollama API on <code>:11434</code>.</li>
        <li>Planner interprets the question and produces a structured search plan.</li>
        <li>SPL Writer turns that plan into bounded read-only SPL.</li>
        <li>Security Reviewer critiques quality and safety.</li>
        <li>Peer Reviewer 1 only runs when the reviewer does not cleanly approve the writer output.</li>
        <li>Peer Reviewer 2 verifies or overrides that adjudication when it is needed.</li>
        <li>Evidence Reviewer checks executed rows against the claim set.</li>
        <li>Continuation Reviewer decides whether another bounded pivot is warranted.</li>
        <li>Controller model supports bounded orchestration in the agentic path.</li>
        <li>Final Summary model produces the analyst-facing narrative.</li>
      </ul>
      <div class="arch-pill-row">
        <span class="arch-pill">write</span>
        <span class="arch-pill">review</span>
        <span class="arch-pill">adjudicate</span>
        <span class="arch-pill">verify</span>
        <span class="arch-pill">evidence-check</span>
        <span class="arch-pill">continue?</span>
        <span class="arch-pill">summarize</span>
      </div>
    </section>
    <section class="arch-box tertiary">
      <div class="arch-box-label">Grounding Layer</div>
      <h3>Analyst Data Domains</h3>
      <ul>
        <li>Windows authentication and endpoint-relevant telemetry.</li>
        <li>Linux auth, sudo, and related host activity.</li>
        <li>Apache web activity including <code>access_combined</code>.</li>
        <li>Index, sourcetype, tag, metadata, and known-field inventory used for environment-aware planning.</li>
      </ul>
      <div class="arch-note">All retrieval paths are read-only in the current platform build.</div>
    </section>
  </div>
</div>
<div class="arch-tier" style="margin-top:14px;">
  <div class="arch-tier-label">Interconnectivity</div>
  <div class="arch-flow-ribbon" aria-label="Architecture flow sequence">
    <div class="arch-flow-step">
      <div>
        <div class="arch-flow-step-title">1. Analyst question enters A.G.E.N.T. Smith</div>
        <div class="arch-flow-step-copy">The browser sends the investigation request to the Pi-hosted control plane through the authenticated web UI.</div>
      </div>
      <div class="arch-flow-step-tag">UI to controller</div>
    </div>
    <div class="arch-flow-arrow-node" aria-hidden="true">&rarr;</div>
    <div class="arch-flow-step">
      <div>
        <div class="arch-flow-step-title">2. Controller engages model roles</div>
        <div class="arch-flow-step-copy">The controller sends the question, RAG context, and constraints to the remote reasoning stack for planning and review.</div>
      </div>
      <div class="arch-flow-step-tag">control to reasoning</div>
    </div>
    <div class="arch-flow-arrow-node" aria-hidden="true">&rarr;</div>
    <div class="arch-flow-step">
      <div>
        <div class="arch-flow-step-title">3. Environment context grounds the plan</div>
        <div class="arch-flow-step-copy">Index, sourcetype, tag, metadata, and known-field awareness feed back into the model decision path so SPL is shaped by the real environment.</div>
      </div>
      <div class="arch-flow-step-tag">grounding loop</div>
    </div>
    <div class="arch-flow-arrow-node" aria-hidden="true">&rarr;</div>
    <div class="arch-flow-step">
      <div>
        <div class="arch-flow-step-title">4. Splunk MCP executes bounded retrieval</div>
        <div class="arch-flow-step-copy">After deterministic validation, the controller calls the approved read-only MCP tool against Splunk and gets structured results back.</div>
      </div>
      <div class="arch-flow-step-tag">validated execution</div>
    </div>
    <div class="arch-flow-arrow-node" aria-hidden="true">&rarr;</div>
    <div class="arch-flow-step">
      <div>
        <div class="arch-flow-step-title">5. Evidence returns to UI and storage</div>
        <div class="arch-flow-step-copy">Returned rows are reviewed, continuation is assessed, the summary is rendered to the analyst, and optional artifacts are written for later inspection.</div>
      </div>
      <div class="arch-flow-step-tag">results and persistence</div>
    </div>
  </div>
  <div class="arch-loop-strip" aria-label="Architecture feedback loops">
    <span class="arch-loop-chip">Data Domains</span>
    <span class="arch-loop-arrow" aria-hidden="true">&rarr;</span>
    <span class="arch-loop-chip">Planner and Reviewer Prompts</span>
    <span class="arch-loop-arrow" aria-hidden="true">&rarr;</span>
    <span class="arch-loop-chip">Deterministic Policy Gate</span>
    <span class="arch-loop-arrow" aria-hidden="true">&rarr;</span>
    <span class="arch-loop-chip">Splunk MCP Retrieval</span>
    <span class="arch-loop-arrow" aria-hidden="true">&rarr;</span>
    <span class="arch-loop-chip">Evidence Reviewer</span>
    <span class="arch-loop-arrow" aria-hidden="true">&rarr;</span>
    <span class="arch-loop-chip">Continuation Reviewer</span>
    <span class="arch-loop-arrow" aria-hidden="true">&rarr;</span>
    <span class="arch-loop-chip">Analyst UI and Artifacts</span>
  </div>
  <div class="arch-interop-grid">
    <div class="arch-interop-card">
      <div class="arch-interop-title">Control Path</div>
      <div class="arch-interop-line"><strong>Browser</strong> -> <strong>Pi Controller</strong> for authenticated request handling.</div>
      <div class="arch-interop-line"><strong>Pi Controller</strong> -> <strong>optional edge helper</strong> -> <strong>primary inference host</strong> for staged routing and reasoning roles.</div>
    </div>
    <div class="arch-interop-card">
      <div class="arch-interop-title">Grounding Path</div>
      <div class="arch-interop-line"><strong>Data Domains</strong> -> <strong>Planner/Reviewer prompts</strong> for environment-aware SPL generation using known fields where available.</div>
      <div class="arch-interop-line"><strong>RAG snippets</strong> -> <strong>query repair and critique</strong> for higher-quality searches.</div>
    </div>
    <div class="arch-interop-card">
      <div class="arch-interop-title">Execution Path</div>
      <div class="arch-interop-line"><strong>Validated plan</strong> -> <strong>Splunk MCP</strong> -> <strong>Splunk Platform</strong>.</div>
      <div class="arch-interop-line"><strong>Structured results</strong> -> <strong>evidence reviewer</strong> -> <strong>continuation reviewer</strong> -> <strong>summary model</strong>.</div>
    </div>
    <div class="arch-interop-card">
      <div class="arch-interop-title">Persistence Path</div>
      <div class="arch-interop-line"><strong>Documentation</strong> stays in <code>docs/</code> and feeds the web portal.</div>
      <div class="arch-interop-line"><strong>Runtime outputs</strong> can be written to <code>artifacts/runs/</code> without polluting docs.</div>
    </div>
  </div>
</div>
<div class="arch-tier" style="margin-top:14px;">
  <div class="arch-tier-label">Platform Surfaces</div>
  <div class="arch-subgrid">
    <section class="arch-box secondary">
      <div class="arch-box-label">Retrieval Layer</div>
      <h3>Splunk Server</h3>
      <ul>
        <li>MCP endpoint: <code>:8089/services/mcp</code></li>
        <li>Read-only tools in current use: <code>splunk_run_query</code>, <code>splunk_get_indexes</code>, <code>splunk_get_metadata</code>, <code>splunk_get_info</code></li>
        <li>Queries are executed only after model output clears deterministic validation.</li>
      </ul>
    </section>
    <section class="arch-box">
      <div class="arch-box-label">Persistence Layer</div>
      <h3>Artifacts and Documentation</h3>
      <ul>
        <li>Documentation is maintained under <code>docs/</code> and exposed in the web UI.</li>
        <li>Runtime artifacts are stored separately under <code>artifacts/runs/</code>.</li>
        <li>The architecture page describes implemented behavior first; planned items are documented separately.</li>
      </ul>
    </section>
  </div>
</div>
"""


def _docs_index_body() -> str:
    sidebar = _render_docs_sidebar()
    body = f"""
<div class=\"layout\">
  <aside class=\"docs-sidebar\">
    <h1 class=\"docs-rail-title\">Documentation</h1>
    <p class=\"docs-rail-sub\">Organized for leaders first, operators second, deep reference last.</p>
    <input id=\"doc-filter\" class=\"search\" type=\"text\" placeholder=\"Filter docs by topic or title...\" />
    {sidebar}
  </aside>
  <main class=\"docs-main\">
    <h1>A.G.E.N.T. Smith Documentation</h1>
    <div class=\"hero\">
      <div class=\"card\">
        <h2>Start Here</h2>
        <p>If you are new to A.G.E.N.T. Smith, begin with the business overview and then move into the technical architecture only if you need deeper detail.</p>
        <p><a href=\"/docs\">Open the business overview</a></p>
      </div>
      <div class=\"card\">
        <h2>How To Use This Section</h2>
        <p><span class=\"badge\">Audience-first layout</span></p>
        <p>Business readers should start with overview and roadmap material. Technical readers should then move into architecture, flow, and operator guides.</p>
      </div>
    </div>
    <div class=\"guide-grid\">
      <div class=\"guide-card\">
        <h2>What Is This?</h2>
        <p>Use these if you want the business story, problem statement, current value, and roadmap direction.</p>
        <div class=\"guide-links\">
          <a class=\"guide-link\" href=\"/docs/view?path=whitepapers/project_one_page_white_paper.md\"><strong>What A.G.E.N.T. Smith Is</strong><span>Fastest explanation for non-technical readers.</span></a>
          <a class=\"guide-link\" href=\"/docs/view?path=runbooks/initial_setup.md\"><strong>Initial Setup Guide</strong><span>Step-by-step install and configuration for a new machine.</span></a>
          <a class=\"guide-link\" href=\"/docs/view?path=whitepapers/executive_white_paper.md\"><strong>Executive Summary</strong><span>Value, controls, and readiness framing for leadership.</span></a>
          <a class=\"guide-link\" href=\"/docs/view?path=project_overview.md\"><strong>Documentation Guide</strong><span>Reading order and major entry points.</span></a>
        </div>
      </div>
      <div class=\"guide-card\">
        <h2>How Does It Work?</h2>
        <p>Use these if you need architecture, runtime flow, or current-versus-planned design detail.</p>
        <div class=\"guide-links\">
          <a class=\"guide-link\" href=\"/docs/view?path=whitepapers/technical_deep_dive.md\"><strong>Technical Deep Dive</strong><span>Best technical overview of runtime flow and controls.</span></a>
          <a class=\"guide-link\" href=\"/docs/view?path=architecture/system_design.md\"><strong>System Design</strong><span>Current system shape and planned extensions.</span></a>
          <a class=\"guide-link\" href=\"/architecture\"><strong>Architecture Graph</strong><span>Visual map of components, roles, and trust boundaries.</span></a>
        </div>
      </div>
      <div class=\"guide-card\">
        <h2>What Can It Do Today?</h2>
        <p>Use these if you want the implemented operating model, data domains, and day-to-day workflow entry points.</p>
        <div class=\"guide-links\">
          <a class=\"guide-link\" href=\"/docs/view?path=architecture/tdir_core_blueprint.md\"><strong>TDIR Blueprint</strong><span>Current Detect, Triage, and Investigate capability.</span></a>
          <a class=\"guide-link\" href=\"/environment\"><strong>Data Domains</strong><span>Indexes, sourcetypes, and environment-aware query grounding.</span></a>
          <a class=\"guide-link\" href=\"/investigation\"><strong>Investigation UI</strong><span>Main analyst-facing workflow surface.</span></a>
        </div>
      </div>
      <div class=\"guide-card\">
        <h2>How Do We Operate It?</h2>
        <p>Use these if you are bringing up the platform, running a demo, or managing the current environment.</p>
        <div class=\"guide-links\">
          <a class=\"guide-link\" href=\"/docs/view?path=runbooks/health_check.md\"><strong>Health Check</strong><span>Short post-install validation for an already-configured runtime.</span></a>
          <a class=\"guide-link\" href=\"/docs/view?path=runbooks/demo_walkthrough.md\"><strong>Demo Walkthrough</strong><span>Presentation path for stakeholders.</span></a>
          <a class=\"guide-link\" href=\"/docs/view?path=runbooks/daily_ops.md\"><strong>Daily Operations</strong><span>Routine operational checks.</span></a>
        </div>
      </div>
    </div>
  </main>
</div>
<script>
  const filter = document.getElementById('doc-filter');
  if (filter) {{
    filter.addEventListener('input', () => {{
      const q = filter.value.trim().toLowerCase();
      document.querySelectorAll('.doc-link[data-doc-path]').forEach((el) => {{
        const txt = ((el.getAttribute('data-doc-path') || '') + ' ' + (el.getAttribute('data-doc-label') || '')).toLowerCase();
        el.style.display = txt.includes(q) ? 'block' : 'none';
      }});
    }});
  }}
</script>
"""
    return body


def _docs_view_body(path_value: str) -> str:
    doc_path = _safe_docs_path(path_value)
    sidebar = _render_docs_sidebar(path_value)
    if doc_path is None:
        return f"""
<div class=\"layout\">
  <aside class=\"docs-sidebar\">
    <h1 class=\"docs-rail-title\">Documentation</h1>
    <p class=\"docs-rail-sub\">Browse by topic. The navigation stays visible while reading.</p>
    {sidebar}
  </aside>
  <main class=\"docs-main\">
    <h1>Not Found</h1>
    <p class=\"muted\">Invalid docs path: <code>{html.escape(path_value)}</code></p>
    <p><a href=\"/docs\">Back to Documentation Landing</a></p>
    <p><a href=\"/docs/index\">Open Docs Index</a></p>
  </main>
</div>
"""

    text = doc_path.read_text(encoding="utf-8", errors="replace")
    rel = str(doc_path.relative_to(DOCS_ROOT))
    if doc_path.suffix.lower() == ".md":
        rendered = _render_markdown_simple(text)
    else:
        rendered = f"<pre>{html.escape(text)}</pre>"

    qpath = quote(rel)
    if rel == "whitepapers/project_one_page_white_paper.md":
        rendered = rendered.replace(
            "<h1>A.G.E.N.T. Smith</h1>",
            (
                '<h1 class="doc-brand-title">'
                '<span>A.G.E.N.T. Smith</span>'
                '<img class="doc-brand-icon" src="/favicon.svg?v=agtsmith1" alt="A.G.E.N.T. Smith icon" />'
                "</h1>"
            ),
            1,
        )
    return f"""
<div class=\"layout\">
  <aside class=\"docs-sidebar\">
    <h1 class=\"docs-rail-title\">Documentation</h1>
    <p class=\"docs-rail-sub\">Browse by topic. The navigation stays visible while reading.</p>
    <a class=\"doc-link\" href=\"/docs\">Back to documentation landing</a>
    <a class=\"doc-link\" href=\"/docs/index\">Open docs index</a>
    <a class=\"doc-link\" href=\"/docs/raw?path={qpath}\">Raw view</a>
    {sidebar}
  </aside>
  <main class=\"docs-main\">
    {rendered}
  </main>
</div>
"""


def _favicon_preview_body() -> str:
    return """
<div class=\"card\">
  <h1>A.G.E.N.T. Smith Favicon Preview</h1>
  <p class=\"muted\">Large preview for visual verification.</p>
  <div style=\"display:flex; gap:14px; flex-wrap:wrap; align-items:flex-start;\">
    <div class=\"card\" style=\"max-width:420px;\">
      <h3>320px</h3>
      <img src=\"/favicon.svg?v=agtsmith1\" alt=\"A.G.E.N.T. Smith favicon\" width=\"320\" height=\"320\" style=\"background:#020617; border:1px solid #223245; border-radius:10px;\" />
    </div>
    <div class=\"card\" style=\"max-width:220px;\">
      <h3>128px</h3>
      <img src=\"/favicon.svg?v=agtsmith1\" alt=\"A.G.E.N.T. Smith favicon\" width=\"128\" height=\"128\" style=\"background:#020617; border:1px solid #223245; border-radius:10px;\" />
    </div>
  </div>
  <p><a href=\"/favicon.svg?v=agtsmith1\">Open raw SVG</a></p>
</div>
"""


def _architecture_page_body() -> str:
    return f"""
<div class="card">
  <div class="arch-hero">
    <div class="arch-hero-card">
      <div class="arch-kicker">Architecture</div>
      <h2>A.G.E.N.T. Smith - TLDR</h2>
      <p class="arch-hero-lead">A.G.E.N.T. Smith is a guarded Splunk analyst copilot built to help people investigate faster without giving up control, evidence quality, or transparency. It takes natural-language security questions, uses environment-aware context to improve SPL generation, keeps every retrieval path read-only, shows the analyst what query ran and why, and records operator activity so the workflow remains explainable and reviewable. The project is intentionally focused on practical analyst augmentation rather than blind autonomy: better investigations, better SPL, real-data grounding, and clear guardrails first, with optional edge-assisted routing and a separate offline LangGraph eval loop used to test workflow changes before they become the default runtime.</p>
    </div>
  </div>
  <div class="svg-wrap">
    <div class="arch-tier">
      <div class="arch-tier-label">Connected Device Diagram</div>
      <div class="arch-visio" role="img" aria-label="A.G.E.N.T. Smith connected device diagram">
        <svg class="arch-visio-svg" viewBox="0 0 1500 520" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <defs>
            <linearGradient id="archBoxBlue" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#0c1f34"/>
              <stop offset="100%" stop-color="#0a1525"/>
            </linearGradient>
            <linearGradient id="archBoxGreen" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#0f2d27"/>
              <stop offset="100%" stop-color="#0a1a1d"/>
            </linearGradient>
            <linearGradient id="archBoxAmber" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#3b2506"/>
              <stop offset="100%" stop-color="#181108"/>
            </linearGradient>
            <marker id="archArrow" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto">
              <path d="M0,0 L10,5 L0,10 z" fill="#7dd3fc"/>
            </marker>
            <marker id="archArrowOptional" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto">
              <path d="M0,0 L10,5 L0,10 z" fill="#fbbf24"/>
            </marker>
          </defs>

          <path d="M190 170 L315 170" stroke="#7dd3fc" stroke-width="4" fill="none" marker-end="url(#archArrow)"/>
          <path d="M605 170 L760 170" stroke="#7dd3fc" stroke-width="4" fill="none" marker-end="url(#archArrow)"/>
          <path d="M1100 170 L1260 170" stroke="#7dd3fc" stroke-width="4" fill="none" marker-end="url(#archArrow)"/>

          <path d="M605 170 C675 170 695 57 760 57 L810 57" stroke="#fbbf24" stroke-width="4" stroke-dasharray="10 8" fill="none" marker-end="url(#archArrowOptional)"/>
          <path d="M1085 57 C1180 57 1180 150 1100 170" stroke="#fbbf24" stroke-width="4" stroke-dasharray="10 8" fill="none" marker-end="url(#archArrowOptional)"/>

          <rect x="40" y="110" rx="22" ry="22" width="150" height="120" fill="url(#archBoxBlue)" stroke="#27506c" stroke-width="2"/>
          <rect x="315" y="90" rx="22" ry="22" width="290" height="160" fill="url(#archBoxBlue)" stroke="#27506c" stroke-width="2"/>
          <rect x="760" y="90" rx="22" ry="22" width="340" height="160" fill="url(#archBoxGreen)" stroke="#2b5a52" stroke-width="2"/>
          <rect x="1260" y="90" rx="22" ry="22" width="190" height="160" fill="url(#archBoxBlue)" stroke="#27506c" stroke-width="2"/>
          <rect x="810" y="5" rx="22" ry="22" width="275" height="96" fill="url(#archBoxAmber)" stroke="#7a5a1d" stroke-width="2"/>

          <text x="58" y="138" fill="#8fd8ff" font-size="11" font-weight="700" letter-spacing=".08em">USER DEVICE</text>
          <text x="58" y="168" fill="#f5f9ff" font-size="20" font-weight="800">Analyst</text>
          <text x="58" y="192" fill="#f5f9ff" font-size="20" font-weight="800">Browser</text>
          <text x="58" y="218" fill="#8fb0cb" font-size="12">Authenticated UI</text>

          <text x="338" y="118" fill="#8fd8ff" font-size="12" font-weight="700" letter-spacing=".08em">CONTROL PLANE</text>
          <text x="338" y="150" fill="#f5f9ff" font-size="23" font-weight="800">Linux Controller Host</text>
          <text x="338" y="178" fill="#bfd0df" font-size="12">Web UI, LangGraph, validation,</text>
          <text x="338" y="198" fill="#bfd0df" font-size="12">audit, docs, Splunk MCP client.</text>
          <text x="338" y="226" fill="#8fb0cb" font-size="12">Always present</text>

          <text x="788" y="118" fill="#9bf7cf" font-size="12" font-weight="700" letter-spacing=".08em">PRIMARY INFERENCE</text>
          <text x="788" y="150" fill="#f5f9ff" font-size="24" font-weight="800">Primary Ollama Host</text>
          <text x="788" y="178" fill="#bfd0df" font-size="13">Planner, writer, reviewer, peer review,</text>
          <text x="788" y="198" fill="#bfd0df" font-size="13">evidence, continuation, summary.</text>
          <text x="788" y="226" fill="#8fb0cb" font-size="13">Main model endpoint</text>

          <text x="1278" y="118" fill="#8fd8ff" font-size="12" font-weight="700" letter-spacing=".08em">DATA PLANE</text>
          <text x="1278" y="150" fill="#f5f9ff" font-size="22" font-weight="800">Splunk + MCP</text>
          <text x="1278" y="178" fill="#bfd0df" font-size="13">Read-only retrieval,</text>
          <text x="1278" y="198" fill="#bfd0df" font-size="13">metadata, evidence.</text>
          <text x="1278" y="226" fill="#8fb0cb" font-size="13">Source of truth</text>

          <text x="830" y="31" fill="#fde68a" font-size="12" font-weight="700" letter-spacing=".08em">OPTIONAL EDGE HELPER</text>
          <text x="830" y="57" fill="#f5f9ff" font-size="18" font-weight="800">Small Edge LLM Device</text>
          <text x="830" y="79" fill="#d6c089" font-size="12">Routing, split-query hints,</text>
          <text x="830" y="95" fill="#d6c089" font-size="12">confidence checks</text>

          <text x="228" y="156" fill="#7dd3fc" font-size="12" font-weight="700">HTTP UI</text>
          <text x="645" y="152" fill="#7dd3fc" font-size="12" font-weight="700">Primary model path</text>
          <text x="1152" y="148" fill="#7dd3fc" font-size="11" font-weight="700">Read-only retrieval</text>
          <text x="630" y="52" fill="#fde68a" font-size="12" font-weight="700">Edge helper enabled path</text>

          <rect x="40" y="300" rx="14" ry="14" width="1420" height="170" fill="#091726" stroke="#24435d" stroke-width="1.5"/>
          <text x="64" y="328" fill="#9fc2dd" font-size="12" font-weight="700" letter-spacing=".08em">FLOW NOTES</text>
          <text x="64" y="356" fill="#bfd0df" font-size="13">1. Browser always talks to the controller.</text>
          <text x="64" y="384" fill="#bfd0df" font-size="13">2. LangGraph on the controller coordinates model calls and any</text>
          <text x="82" y="404" fill="#bfd0df" font-size="13">optional edge-helper branch when enabled.</text>
          <text x="64" y="432" fill="#bfd0df" font-size="13">3. Primary inference host remains mandatory for the main reasoning stack.</text>
          <text x="64" y="454" fill="#bfd0df" font-size="13">4. Only the controller can call Splunk MCP, and only after deterministic validation succeeds.</text>
        </svg>
        <div class="arch-visio-caption">The optional edge helper is a separate role from the Linux controller host. It only appears in the request path when explicitly enabled in Configuration; otherwise the controller sends the grounded prompt directly to the primary inference host.</div>
      </div>
    </div>

    <div class="arch-tier" style="margin-top:14px;">
      <div class="arch-tier-label">Endpoints and Connections</div>
      <div class="arch-endpoint-grid" role="img" aria-label="A.G.E.N.T. Smith endpoint interaction map">
        <section class="arch-endpoint-card">
          <div class="arch-endpoint-kicker">Entry Point</div>
          <div class="arch-endpoint-topline">
            <h3>Analyst Browser</h3>
            <span class="arch-step-badge">1</span>
          </div>
          <p class="arch-endpoint-copy">Accept question. The analyst opens the Investigation UI and submits a natural-language request.</p>
          <div class="arch-endpoint-meta">HTTP UI session<br/>Browser -&gt; <code>/api/ask</code></div>
        </section>
        <section class="arch-endpoint-card">
          <div class="arch-endpoint-kicker">Controller</div>
          <div class="arch-endpoint-topline">
            <h3>Linux Controller Host</h3>
            <span class="arch-step-badge">2</span>
          </div>
          <p class="arch-endpoint-copy">Assemble context. The controller receives the request, adds RAG, environment profile, known fields, policy constraints, and decides whether the optional edge hop is active.</p>
          <div class="arch-endpoint-meta">Receives <code>/api/ask</code><br/>Question -&gt; grounded prompt</div>
        </section>
        <section class="arch-endpoint-card">
          <div class="arch-endpoint-kicker">Optional Routing</div>
          <div class="arch-endpoint-topline">
            <h3>Optional Edge Helper</h3>
            <span class="arch-step-badge">3</span>
          </div>
          <p class="arch-endpoint-copy">Only present if enabled. A small edge-hosted model can classify the question, suggest split-query handling, or emit a confidence hint before the main planner runs. If disabled, this hop does not exist.</p>
          <div class="arch-endpoint-meta">Conditional endpoint<br/>Controller -&gt; edge helper when enabled</div>
        </section>
        <section class="arch-endpoint-card">
          <div class="arch-endpoint-kicker">Reasoning</div>
          <div class="arch-endpoint-topline">
            <h3>Primary Ollama Host</h3>
            <span class="arch-step-badge">4</span>
          </div>
          <p class="arch-endpoint-copy">Run the main model roles. Planner, SPL writer, reviewers, adjudication, continuation, and summary roles propose and critique the bounded plan. This host remains the primary reasoning engine whether or not the edge helper exists.</p>
          <div class="arch-endpoint-meta">Remote API on <code>:11434</code><br/>Controller -&gt; primary inference host</div>
        </section>
        <section class="arch-endpoint-card">
          <div class="arch-endpoint-kicker">Retrieval</div>
          <div class="arch-endpoint-topline">
            <h3>Splunk MCP Endpoint</h3>
            <span class="arch-step-badge">5</span>
          </div>
          <p class="arch-endpoint-copy">Validate before touch, then retrieve and review. Only approved read-only calls execute here, and returned rows feed evidence review.</p>
          <div class="arch-endpoint-meta">Tools: query, metadata, indexes, info<br/>Approved plan -&gt; rows -&gt; evidence</div>
        </section>
        <section class="arch-endpoint-card">
          <div class="arch-endpoint-kicker">Data and Output</div>
          <div class="arch-endpoint-topline">
            <h3>Splunk + Data Domains</h3>
            <span class="arch-step-badge">6</span>
          </div>
          <p class="arch-endpoint-copy">Return findings. Results are rendered to the analyst while Data Domains and personalization improve future SPL for this environment.</p>
          <div class="arch-endpoint-meta">Indexes, sourcetypes, fields, artifacts<br/>Summary -&gt; UI + optional artifacts</div>
        </section>
      </div>
      <div class="arch-connection-band" aria-label="Primary connection path">
        <div class="arch-connection-link">UI request</div>
        <div class="arch-connection-link arrow">&rarr;</div>
        <div class="arch-connection-link">controller context</div>
        <div class="arch-connection-link arrow">&rarr;</div>
        <div class="arch-connection-link">optional edge routing</div>
        <div class="arch-connection-link arrow">&rarr;</div>
        <div class="arch-connection-link">role prompts</div>
        <div class="arch-connection-link arrow">&rarr;</div>
        <div class="arch-connection-link">validated plan</div>
        <div class="arch-connection-link arrow">&rarr;</div>
        <div class="arch-connection-link">read-only mcp</div>
        <div class="arch-connection-link arrow">&rarr;</div>
        <div class="arch-connection-link">rows + grounding</div>
      </div>
    </div>

    <div class="arch-tier" style="margin-top:14px;">
      <div class="arch-tier-label">What Moves Across The System</div>
      <div class="arch-handoff-grid">
        <div class="arch-handoff-card"><strong>What moves to the edge helper</strong>Only if enabled: compact routing context, cross-platform hints, and bounded split-query questions. No direct Splunk execution authority exists here.</div>
        <div class="arch-handoff-card"><strong>What moves to Ollama</strong>Question, data-domain hints, SPL guidance, known-field examples, and policy constraints.</div>
        <div class="arch-handoff-card"><strong>What moves to Splunk MCP</strong>Only the validated read-only tool call selected by the controller after deterministic checks.</div>
        <div class="arch-handoff-card"><strong>What comes back from Splunk</strong>Structured rows, counts, entities, and metadata used for evidence review and continuation decisions.</div>
        <div class="arch-handoff-card"><strong>What the analyst sees</strong>Evidence-backed summary, executed SPL, returned results, TDIR state, and optional deeper-investigation approval.</div>
      </div>
    </div>
  </div>

  <details class="arch-detail-shell">
    <summary>Show Detailed Component Inventory</summary>
    <div class="arch-detail-sub">Use this for the lower-level role inventory, trust boundaries, and implementation notes. The connected-device diagram and endpoint map above are the primary architecture views.</div>
    <div class="arch-detail-body">
      <div class="arch-panels">
        <div class="arch-panel">
          <h3>Control Plane</h3>
          <ul>
            <li>LangGraph executes orchestration and policy checks on the Linux controller host.</li>
            <li>LAN access is gated by login/session auth before any UI or API execution.</li>
            <li>Model outputs remain advisory until deterministic validation passes.</li>
            <li>If the optional edge helper is disabled, the controller sends questions straight to the primary inference host.</li>
            <li>Deeper Investigation Control enforces one automatic continuation pass, duplicate-pivot blocking, confidence/depth limits, and analyst approval beyond that point.</li>
          </ul>
        </div>
        <div class="arch-panel">
          <h3>Reasoning Roles</h3>
          <ul>
            <li>Optional Edge Helper only runs when explicitly enabled in runtime configuration.</li>
            <li>Its narrow role is routing, split-query hints, and cheap confidence pre-checks.</li>
            <li>Planner interprets the analyst question and proposes the bounded search strategy.</li>
            <li>SPL Writer generates the bounded read-only SPL from that plan.</li>
            <li>Security Reviewer critiques quality and safety.</li>
            <li>Peer Reviewer 1 and 2 adjudicate only when the reviewer contests or materially revises the writer output.</li>
            <li>Evidence Reviewer checks returned rows against the claim set.</li>
            <li>Continuation Reviewer decides whether another bounded pivot is warranted.</li>
            <li>Final Summary produces the analyst-facing narrative.</li>
          </ul>
        </div>
        <div class="arch-panel">
          <h3>Data Plane</h3>
          <ul>
            <li>Splunk MCP provides the read-only retrieval tools used in the current build.</li>
            <li>Coverage includes Windows, Linux, and Apache access logs.</li>
            <li>Environment profiles and personalized skillpacks keep SPL tied to local indexes, sourcetypes, and known fields.</li>
            <li>Documentation stays in <code>docs/</code>; runtime artifacts are written to <code>artifacts/runs/</code>.</li>
          </ul>
        </div>
      </div>
      <div class="arch-panels">
        <div class="arch-panel">
          <h3>Current vs Planned</h3>
          <ul>
            <li>Current: Detect, triage, investigate, summarize, and preserve optional artifacts.</li>
            <li>Current: bounded continuation with analyst approval for deeper follow-up.</li>
            <li>Current: edge-helper configuration is baked into setup and runtime config, but it remains inactive unless enabled by the operator.</li>
            <li>Current: offline LangGraph eval and topology experiments run beside the live runtime and do not alter the default path automatically.</li>
            <li>Planned: Respond and Recover workflow guidance beyond manual runbooks.</li>
            <li>Planned: SOAR-connected automation in a later phase.</li>
          </ul>
        </div>
        <div class="arch-panel">
          <h3>Trust Boundaries</h3>
          <ul>
            <li>The browser can ask questions but cannot execute Splunk directly.</li>
            <li>The optional edge helper can suggest routing, but it cannot execute Splunk or bypass controller policy checks.</li>
            <li>The primary model stack can recommend plans but cannot bypass controller policy checks.</li>
            <li>Only the controller can call Splunk MCP, and only after deterministic validation succeeds.</li>
            <li>Artifacts are optional outputs and remain separate from the documentation source tree.</li>
          </ul>
        </div>
        <div class="arch-panel">
          <h3>Persistence</h3>
          <ul>
            <li><code>docs/</code> contains the operator and architecture narrative shown in the portal.</li>
            <li><code>artifacts/runs/</code> stores optional runtime outputs for later inspection.</li>
            <li><code>artifacts/evals/langgraph/</code> stores the gold corpus, eval prompts, and topology experiment outputs used for offline optimization.</li>
            <li>Data Domains and personalization are built from the live environment and not baked into the vanilla deploy image.</li>
          </ul>
        </div>
      </div>
    </div>
  </details>

  <details class="guided">
    <summary>Show Endpoint-Level Walkthrough</summary>
    <div class="guided-body">
      <p class="muted">Default path for the <code>Multi-Model Reviewer</code> pipeline: optional edge helper when enabled, planner, writer, reviewer, optional peer review, deterministic validation, execution.</p>
      <div class="step">
        <div class="step-title">Browser -&gt; Controller</div>
        <div>The analyst question enters the authenticated web UI and is posted to <code>/api/ask</code>.</div>
        <div class="mini-flow">
          <span class="mini-node">Analyst Browser</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Linux Controller Host</span>
        </div>
      </div>
      <div class="step">
        <div class="step-title">Controller -&gt; Optional Edge Helper</div>
        <div>If enabled, the controller can call the small edge model for routing or split-query hints. If disabled, the controller bypasses this step and proceeds directly to the primary inference host.</div>
        <div class="mini-flow">
          <span class="mini-node">Grounded Prompt</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Optional Edge Helper</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Primary Ollama Host</span>
        </div>
      </div>
      <div class="step">
        <div class="step-title">Controller -&gt; Primary Ollama Host</div>
        <div>The controller sends the grounded prompt to the main model stack for planning, writing, critique, adjudication, evidence review, and summary.</div>
        <div class="mini-flow">
          <span class="mini-node">Grounded Prompt</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Primary Ollama Roles</span>
        </div>
      </div>
      <div class="step">
        <div class="step-title">Controller -&gt; Splunk MCP</div>
        <div>Only after deterministic validation passes does the controller send the approved read-only tool call to Splunk MCP.</div>
        <div class="mini-flow">
          <span class="mini-node">Approved Plan</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Splunk MCP</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Splunk Platform</span>
        </div>
      </div>
      <div class="step">
        <div class="step-title">Splunk -&gt; Evidence</div>
        <div>Returned rows are packaged, checked by the evidence reviewer, and then assessed for deeper follow-up.</div>
        <div class="mini-flow">
          <span class="mini-node">Structured Rows</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Evidence Review</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Continuation Decision</span>
        </div>
      </div>
      <div class="step">
        <div class="step-title">Controller -&gt; Analyst</div>
        <div>The final summary, executed SPL, returned rows, and optional artifacts are rendered back into the Investigation UI.</div>
        <div class="mini-flow">
          <span class="mini-node">Summary + Results</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Investigation UI</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Analyst</span>
        </div>
      </div>
      <p class="muted">If the selected pipeline is <code>Agentic Loop</code>, the controller can insert one bounded automatic follow-up round after evidence review and then requires analyst approval before any deeper continuation.</p>
    </div>
  </details>
</div>
"""


def _langgraph_graph_page_body() -> str:
    graph = describe_multi_model_graph()
    canonical = graph.get("canonical", {})
    active = graph.get("active", {})
    topology_settings = graph.get("topology_settings", {})
    notes = graph.get("notes", []) if isinstance(graph.get("notes", []), list) else []
    latest_overlay_html, executed_nodes = _latest_stage_overlay()
    canonical_mermaid = _graph_mermaid(canonical, title="Canonical LangGraph Topology", use_subgraphs=True)
    active_mermaid = _graph_mermaid(active, title="Active LangGraph Topology", executed_nodes=executed_nodes, use_subgraphs=True)
    canonical_mermaid_modal = _graph_mermaid(canonical, title="Canonical LangGraph Topology", direction="LR", use_subgraphs=True, expanded=True, subgraph_direction="TB")
    active_mermaid_modal = _graph_mermaid(active, title="Active LangGraph Topology", executed_nodes=executed_nodes, direction="LR", use_subgraphs=True, expanded=True, subgraph_direction="TB")
    canonical_mermaid_json = json.dumps(canonical_mermaid_modal)
    active_mermaid_json = json.dumps(active_mermaid_modal)
    flag_badges = "".join(
        f'<div class="lg-flag {"enabled" if bool(value) else "disabled"}"><span>{html.escape(str(key))}</span><strong>{html.escape("on" if bool(value) else "off")}</strong></div>'
        for key, value in topology_settings.items()
    )
    note_items = "".join(f"<li>{html.escape(str(item))}</li>" for item in notes)
    return f"""
<div class="card">
  <style>
    .lg-shell{{display:grid;gap:18px;}}
    .lg-hero{{border:1px solid #27415a;border-radius:18px;background:linear-gradient(180deg,#091423,#07111f);padding:18px;display:grid;gap:10px;}}
    .lg-kicker{{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#8fd8ff;font-weight:700;}}
    .lg-hero h1{{margin:0;font-size:34px;line-height:1.1;}}
    .lg-hero p{{margin:0;color:#dbeafe;line-height:1.7;}}
    .lg-grid{{display:grid;grid-template-columns:1fr 1fr;gap:18px;}}
    .lg-card{{border:1px solid #27415a;border-radius:18px;background:linear-gradient(180deg,#091423,#07111f);padding:18px;display:grid;gap:12px;}}
    .lg-card h2{{margin:0;font-size:20px;}}
    .lg-card .muted{{margin:0;color:#9fc2dd;line-height:1.6;}}
    .lg-flags{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;}}
    .lg-flag{{border:1px solid #254059;border-radius:14px;padding:10px 12px;background:#07111f;display:flex;justify-content:space-between;gap:12px;align-items:center;}}
    .lg-flag span{{font-size:12px;color:#bfd0df;word-break:break-word;}}
    .lg-flag strong{{font-size:13px;text-transform:uppercase;letter-spacing:.05em;}}
    .lg-flag.enabled{{border-color:#166534;background:#062313;color:#dcfce7;}}
    .lg-flag.disabled{{border-color:#5b4557;background:#1a1220;color:#f5d0fe;}}
    .lg-run-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;}}
    .lg-run-card{{border:1px solid #27415a;border-radius:14px;background:#07111f;padding:12px;display:grid;gap:8px;}}
    .lg-run-head{{display:flex;justify-content:space-between;gap:10px;align-items:center;}}
    .lg-run-stage{{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#8fd8ff;font-weight:700;}}
    .lg-run-ms{{font-size:12px;color:#9fc2dd;}}
    .lg-run-title{{font-size:13px;color:#f8fafc;font-weight:700;line-height:1.5;}}
    .lg-run-detail{{font-size:12px;color:#bfd0df;line-height:1.5;}}
    .lg-meta{{font-size:12px;color:#9fc2dd;line-height:1.6;overflow-wrap:anywhere;}}
    .lg-table-wrap{{overflow:auto;}}
    .lg-table{{width:100%;border-collapse:collapse;font-size:12px;}}
    .lg-table th,.lg-table td{{border-bottom:1px solid #203549;padding:9px 10px;text-align:left;color:#dbeafe;vertical-align:top;}}
    .lg-table th{{font-size:11px;color:#8fd8ff;text-transform:uppercase;letter-spacing:.08em;}}
    .lg-muted{{color:#9fc2dd;line-height:1.6;}}
    .lg-notes{{margin:0;padding-left:18px;color:#dbeafe;line-height:1.7;}}
    .lg-actions{{display:flex;gap:10px;flex-wrap:wrap;}}
    .lg-actions code{{background:#07111f;border:1px solid #254059;border-radius:10px;padding:8px 10px;display:inline-block;color:#dbeafe;}}
    .lg-graph-card{{position:relative;}}
    .lg-expand-btn{{justify-self:start;background:linear-gradient(180deg,#16324a,#102435);color:#dbeafe;border:1px solid #315a79;border-radius:12px;padding:9px 12px;font-weight:700;cursor:pointer;}}
    .lg-expand-btn:hover{{filter:brightness(1.05);}}
    .lg-graph-preview{{border:1px solid #27415a;border-radius:16px;background:radial-gradient(circle at top,#0b1730 0%,#07111f 72%);padding:14px;min-height:260px;display:grid;align-items:center;overflow:hidden;}}
    .lg-graph-preview .mermaid{{width:100%;max-width:100%;display:grid;justify-items:center;}}
    .lg-modal{{position:fixed;inset:0;background:rgba(2,8,15,.82);backdrop-filter:blur(4px);display:none;align-items:center;justify-content:center;padding:10px 10px;z-index:1200;}}
    .lg-modal.open{{display:flex;}}
    .lg-modal-panel{{width:min(3200px,99.2vw);max-height:94vh;overflow:hidden;border:1px solid #315a79;border-radius:26px;background:linear-gradient(180deg,#0b1528,#07111f);padding:22px;display:grid;gap:16px;box-shadow:0 40px 100px rgba(2,8,15,.62), inset 0 1px 0 rgba(255,255,255,.04);}}
    .lg-modal-head{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;}}
    .lg-modal-head h2{{margin:0;font-size:28px;line-height:1.1;}}
    .lg-modal-copy{{margin:6px 0 0;color:#b7cde2;line-height:1.6;max-width:1000px;}}
    .lg-modal-close{{background:linear-gradient(180deg,#18354f,#102435);color:#dbeafe;border:1px solid #4f82a8;border-radius:14px;padding:10px 14px;font-weight:700;cursor:pointer;box-shadow:0 10px 20px rgba(2,8,15,.18);}}
    .lg-modal-graph{{border:1px solid #325574;border-radius:22px;background:radial-gradient(circle at top,#10213b 0%,#09111f 70%);padding:32px;min-height:84vh;display:grid;align-items:center;justify-items:center;overflow:hidden;box-shadow:inset 0 1px 0 rgba(255,255,255,.04);background-image:radial-gradient(circle at top,#10213b 0%,#09111f 70%),linear-gradient(rgba(143,216,255,.06) 1px, transparent 1px),linear-gradient(90deg, rgba(143,216,255,.06) 1px, transparent 1px);background-size:auto, 28px 28px, 28px 28px;}}
    .lg-modal-graph .mermaid{{width:100%;max-width:100%;display:grid;justify-items:center;}}
    .lg-graph-preview svg,.lg-modal-graph svg{{width:100% !important;max-width:100% !important;height:auto !important;display:block;margin:0 auto;}}
    .lg-modal-graph .label foreignObject div,.lg-modal-graph .nodeLabel{{font-weight:700 !important;letter-spacing:.01em;}}
    .lg-modal-graph .cluster rect{{rx:22px;ry:22px;}}
    .lg-legend{{display:flex;gap:10px;flex-wrap:wrap;}}
    .lg-legend-item{{display:inline-flex;align-items:center;gap:8px;border:1px solid #254059;border-radius:999px;background:#07111f;padding:7px 10px;color:#dbeafe;font-size:12px;}}
    .lg-legend-swatch{{width:12px;height:12px;border-radius:999px;display:inline-block;}}
    @media (max-width: 1100px) {{ .lg-grid{{grid-template-columns:1fr;}} }}
    @media (max-width: 1100px) {{ .lg-modal-panel{{width:min(99vw,1600px);}} .lg-modal-graph{{min-height:70vh;padding:20px;}} }}
  </style>
  <div class="lg-shell">
    <section class="lg-hero">
      <div class="lg-kicker">Control Center</div>
      <h1>LangGraph Graph</h1>
      <p>The canonical graph shows every possible stage in the controller-hosted workflow. The active graph reflects the current topology flags. The latest execution panel shows what actually ran in the newest multi-model artifact, and the experiment table shows the latest offline topology comparison when evals have been run.</p>
      <div class="lg-actions">
        <code>make langgraph-gold-build</code>
        <code>make langgraph-eval-prompts</code>
        <code>make langgraph-topology-eval</code>
        <code>make langgraph-topology-optimize</code>
      </div>
      <div class="lg-legend">
        <div class="lg-legend-item"><span class="lg-legend-swatch" style="background:#10253d;border:1px solid #5db0ff;"></span>Planner / Control Entry</div>
        <div class="lg-legend-item"><span class="lg-legend-swatch" style="background:#132e28;border:1px solid #36c690;"></span>Writer</div>
        <div class="lg-legend-item"><span class="lg-legend-swatch" style="background:#2f2410;border:1px solid #f5b942;"></span>Review Stages</div>
        <div class="lg-legend-item"><span class="lg-legend-swatch" style="background:#352016;border:1px solid #ff8a4c;"></span>Validation</div>
        <div class="lg-legend-item"><span class="lg-legend-swatch" style="background:#13233b;border:1px solid #4da3ff;"></span>Execution</div>
        <div class="lg-legend-item"><span class="lg-legend-swatch" style="background:#24163a;border:1px solid #b388ff;"></span>Summary / Finalize</div>
      </div>
    </section>

    <section class="lg-card">
      <h2>Current Topology Flags</h2>
      <p class="muted">These flags determine the active graph layout used by the live controller-hosted LangGraph workflow.</p>
      <div class="lg-flags">{flag_badges}</div>
    </section>

    <div class="lg-grid">
      <section class="lg-card lg-graph-card">
        <h2 title="Canonical Graph shows the full possible workflow, including optional branches that may be disabled or skipped in the active runtime.">Canonical Graph</h2>
        <p class="muted">Full possible graph, including conditional branches that may be bypassed in the active runtime.</p>
        <button class="lg-expand-btn" type="button" data-lg-open="canonical" title="Canonical Graph shows the full possible workflow, including optional branches that may be disabled or skipped in the active runtime.">Expand graph</button>
        <div class="lg-graph-preview">{canonical_mermaid}</div>
      </section>
      <section class="lg-card lg-graph-card">
        <h2 title="Active Graph shows the workflow after applying current runtime settings and highlights the nodes that ran in the latest execution when available.">Active Graph</h2>
        <p class="muted">Graph after applying the current topology flags. Highlighted nodes ran in the latest multi-model artifact when one exists.</p>
        <button class="lg-expand-btn" type="button" data-lg-open="active" title="Active Graph shows the workflow after applying current runtime settings and highlights the nodes that ran in the latest execution when available.">Expand graph</button>
        <div class="lg-graph-preview">{active_mermaid}</div>
      </section>
    </div>

    <section class="lg-card">
      <h2>Latest Executed Path</h2>
      <p class="muted">This comes from the newest multi-model run artifact and shows the actual stage order, timings, and whether peer review was skipped.</p>
      {latest_overlay_html}
    </section>

    <div class="lg-grid">
      <section class="lg-card">
        <h2>Experiment Topology Ranking</h2>
        <p class="muted">Offline eval results appear here after <code>make langgraph-topology-eval</code> has been run against a gold corpus and prompt set.</p>
        {_experiment_summary_block()}
      </section>
      <section class="lg-card">
        <h2>How To Read This</h2>
        <ul class="lg-notes">{note_items}</ul>
      </section>
    </div>
  </div>
  <div id="lg-graph-modal" class="lg-modal" aria-hidden="true">
    <div class="lg-modal-panel" role="dialog" aria-modal="true" aria-labelledby="lg-graph-modal-title">
      <div class="lg-modal-head">
        <div>
          <h2 id="lg-graph-modal-title">Graph</h2>
          <p id="lg-graph-modal-copy" class="lg-modal-copy"></p>
        </div>
        <button id="lg-graph-modal-close" class="lg-modal-close" type="button">Close</button>
      </div>
      <div id="lg-graph-modal-body" class="lg-modal-graph"></div>
    </div>
  </div>
  <script>
    (() => {{
      const modal = document.getElementById('lg-graph-modal');
      const modalBody = document.getElementById('lg-graph-modal-body');
      const modalTitle = document.getElementById('lg-graph-modal-title');
      const modalCopy = document.getElementById('lg-graph-modal-copy');
      const closeBtn = document.getElementById('lg-graph-modal-close');
      if(!modal || !modalBody || !modalTitle || !modalCopy || !closeBtn) return;
      const graphHtml = {{
        canonical: {{
          title: 'Canonical Graph',
          copy: 'Full possible LangGraph topology, including branches that may be skipped in the active runtime.',
          html: {canonical_mermaid_json}
        }},
        active: {{
          title: 'Active Graph',
          copy: 'Current topology after applying the active runtime flags. Highlighted nodes reflect the latest executed path when available.',
          html: {active_mermaid_json}
        }}
      }};
      async function renderModal(which) {{
        const entry = graphHtml[which];
        if(!entry) return;
        modalTitle.textContent = entry.title;
        modalCopy.textContent = entry.copy;
        modalBody.innerHTML = entry.html;
        modal.classList.add('open');
        modal.setAttribute('aria-hidden', 'false');
        const mermaid = window.mermaid;
        const graphNode = modalBody.querySelector('.mermaid');
        if(graphNode) {{
          graphNode.removeAttribute('data-processed');
        }}
        if(mermaid && typeof mermaid.run === 'function' && graphNode) {{
          await mermaid.run({{ nodes: [graphNode] }});
        }}
      }}
      document.querySelectorAll('[data-lg-open]').forEach((btn) => {{
        btn.addEventListener('click', () => renderModal(btn.getAttribute('data-lg-open')));
      }});
      function closeModal() {{
        modal.classList.remove('open');
        modal.setAttribute('aria-hidden', 'true');
        modalBody.innerHTML = '';
      }}
      closeBtn.addEventListener('click', closeModal);
      modal.addEventListener('click', (event) => {{
        if(event.target === modal) closeModal();
      }});
      document.addEventListener('keydown', (event) => {{
        if(event.key === 'Escape' && modal.classList.contains('open')) closeModal();
      }});
    }})();
  </script>
</div>
"""


def _load_environment_profile_payload() -> dict[str, Any]:
    try:
        if ENV_PROFILE_PATH.exists():
            raw = ENV_PROFILE_PATH.read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _artifacts_page_body() -> str:
    if not ARTIFACTS_ROOT.exists():
        return """
<div class=\"card\">
  <h1>Artifact Repository</h1>
  <p class=\"muted\">Artifact directory does not exist yet.</p>
  <p>Create artifacts by running demos, evaluations, or profile refresh tasks.</p>
</div>
"""
    groups = sorted([p for p in ARTIFACTS_ROOT.iterdir() if p.is_dir()], key=lambda x: x.name)
    cards: list[str] = []
    for d in groups:
        files = sorted([f for f in d.rglob("*") if f.is_file()], key=lambda x: str(x))
        sample = files[:10]
        sample_items = "".join(
            f"<li><a href=\"/artifacts/raw?path={quote(str(f.relative_to(ARTIFACTS_ROOT)))}\">{html.escape(str(f.relative_to(ARTIFACTS_ROOT)))}</a></li>"
            for f in sample
        )
        cards.append(
            "<details class=\"env-card\">"
            "<summary>"
            f"<span class=\"env-title\">{html.escape(d.name)}</span>"
            f"<span class=\"badge\">files={len(files)}</span>"
            "</summary>"
            "<div class=\"env-body\">"
            f"<ul>{sample_items or '<li class=\"muted\">(empty)</li>'}</ul>"
            "</div>"
            "</details>"
        )
    return (
        "<div class=\"card\">"
        "<h1>Artifact Repository</h1>"
        "<p class=\"muted\">Operational run outputs are stored under artifacts/ and separated from documentation pages.</p>"
        f"<p><code>{html.escape(str(ARTIFACTS_ROOT.relative_to(PROJECT_ROOT)))}</code></p>"
        f"<div class=\"env-list\">{''.join(cards) if cards else '<p class=\"muted\">No artifact groups found.</p>'}</div>"
        "</div>"
    )


def _environment_page_body() -> str:
    profile = _load_environment_profile_payload()
    if not profile:
        if _running_in_container():
            return f"""
<div class=\"card\">
  <h1>Data Domains</h1>
  <p class=\"muted\">Container deployments do not expose Data Domains until Splunk MCP has been validated and the initial environment profile has finished building.</p>
  <p>Current profile path: <code>{html.escape(str(ENV_PROFILE_PATH.relative_to(PROJECT_ROOT)))}</code></p>
  <p>Next step: open <a href=\"/configure\">Configuration</a>, validate the Splunk MCP connection, then wait for the first environment profile build to complete.</p>
</div>
"""
        return f"""
<div class=\"card\">
  <h1>Data Domains</h1>
  <p class=\"muted\">Environment profile is missing or unreadable.</p>
  <p>Expected file: <code>{html.escape(str(ENV_PROFILE_PATH.relative_to(PROJECT_ROOT)))}</code></p>
  <p>Build it with:</p>
  <pre>make env-profile-refresh</pre>
</div>
"""

    timestamp = str(profile.get("timestamp_utc", "unknown"))
    counts = profile.get("counts", {}) if isinstance(profile.get("counts"), dict) else {}
    index_count = counts.get("index_count", 0)
    sourcetype_count = counts.get("sourcetype_count", 0)
    time_window = profile.get("time_window", {}) if isinstance(profile.get("time_window"), dict) else {}
    earliest = str(time_window.get("earliest_time", ""))
    latest = str(time_window.get("latest_time", ""))
    indexes = profile.get("indexes", []) if isinstance(profile.get("indexes"), list) else []
    semantics = profile.get("sourcetype_semantics", {}) if isinstance(profile.get("sourcetype_semantics"), dict) else {}
    field_inventory = (
        profile.get("sourcetype_field_inventory", {})
        if isinstance(profile.get("sourcetype_field_inventory"), dict)
        else {}
    )
    field_meta = profile.get("field_inventory_meta", {}) if isinstance(profile.get("field_inventory_meta"), dict) else {}

    def _render_index_cards(rows_payload: list[dict[str, Any]]) -> str:
        cards: list[str] = []
        for row in rows_payload:
            if not isinstance(row, dict):
                continue
            idx = str(row.get("index", "")).strip()
            if not idx:
                continue
            sourcetypes = row.get("sourcetypes", [])
            st_counts = row.get("sourcetype_event_counts", {}) if isinstance(row.get("sourcetype_event_counts"), dict) else {}
            error = str(row.get("error", "")).strip()
            if not isinstance(sourcetypes, list):
                sourcetypes = []

            sourcetype_cards: list[str] = []
            for st in sourcetypes:
                st_name = str(st).strip()
                if not st_name:
                    continue
                sem = semantics.get(st_name, {}) if isinstance(semantics.get(st_name), dict) else {}
                desc = str(sem.get("description", "")).strip()
                count = st_counts.get(st_name, "")
                st_field_meta = field_inventory.get(st_name, {}) if isinstance(field_inventory, dict) else {}
                field_preview = ""
                field_rows_html = ""
                if isinstance(st_field_meta, dict):
                    field_examples = st_field_meta.get("interesting_field_examples", [])
                    if isinstance(field_examples, list) and field_examples:
                        preview_parts: list[str] = []
                        for item in field_examples[:4]:
                            if not isinstance(item, dict):
                                continue
                            field_name = str(item.get("field", "")).strip()
                            samples = item.get("sample_values", [])
                            if not field_name:
                                continue
                            if isinstance(samples, list) and samples:
                                preview_parts.append(
                                    f"{field_name}={{{', '.join(str(x).strip() for x in samples[:2] if str(x).strip())}}}"
                                )
                            else:
                                preview_parts.append(field_name)
                        if preview_parts:
                            field_preview = "; ".join(preview_parts)
                    field_rows = st_field_meta.get("display_fields", [])
                    if not isinstance(field_rows, list) or not field_rows:
                        field_rows = st_field_meta.get("fields", [])
                    if isinstance(field_rows, list) and field_rows:
                        field_table_rows: list[str] = []
                        for item in field_rows[:20]:
                            if not isinstance(item, dict):
                                continue
                            field_name = str(item.get("field", "")).strip()
                            if not field_name:
                                continue
                            samples = item.get("sample_values", [])
                            if isinstance(samples, list):
                                sample_text = ", ".join(str(x).strip() for x in samples[:3] if str(x).strip())
                            else:
                                sample_text = ""
                            if not sample_text:
                                sample_text = "No high-signal preview"
                            field_table_rows.append(
                                "<tr>"
                                f"<td class=\"mono\">{html.escape(field_name)}</td>"
                                f"<td class=\"mono\">{html.escape(sample_text)}</td>"
                                f"<td class=\"mono\">{html.escape(str(item.get('count', '')))}</td>"
                                f"<td class=\"mono\">{html.escape(str(item.get('distinct_count', '')))}</td>"
                                "</tr>"
                            )
                        if field_table_rows:
                            field_rows_html = (
                                "<table class=\"env-table\"><thead><tr><th>Field</th><th>Sample Values</th><th>Count</th><th>Distinct</th></tr></thead>"
                                f"<tbody>{''.join(field_table_rows)}</tbody></table>"
                            )
                    field_names = st_field_meta.get("interesting_fields", [])
                    if not field_preview and (not isinstance(field_names, list) or not field_names):
                        field_rows = st_field_meta.get("fields", [])
                        if isinstance(field_rows, list) and field_rows:
                            field_names = [
                                str(item.get("field", "")).strip()
                                for item in field_rows[:8]
                                if isinstance(item, dict) and str(item.get("field", "")).strip()
                            ]
                    if not field_preview and field_names:
                        field_preview = ", ".join(str(name).strip() for name in field_names[:8] if str(name).strip())
                preview_html = html.escape(field_preview) if field_preview else "Field inventory pending refresh"
                field_rows_html = field_rows_html or "<p class=\"muted\">No field inventory captured yet for this sourcetype.</p>"
                sourcetype_cards.append(
                    "<details class=\"env-subcard\">"
                    "<summary>"
                    "<div>"
                    f"<div class=\"env-title\">sourcetype={html.escape(st_name)}</div>"
                    f"<div class=\"env-preview\">{html.escape(desc) if desc else 'No semantic description yet.'}</div>"
                    f"<div class=\"env-preview\">{preview_html}</div>"
                    "</div>"
                    "<div class=\"env-submeta\">"
                    f"<span class=\"badge\">events={html.escape(str(count))}</span>"
                    f"<span class=\"badge\">fields={html.escape(str(st_field_meta.get('field_count', 0) if isinstance(st_field_meta, dict) else 0))}</span>"
                    "</div>"
                    "</summary>"
                    "<div class=\"env-subbody\">"
                    f"{field_rows_html}"
                    "</div>"
                    "</details>"
                )

            details = "".join(sourcetype_cards) if sourcetype_cards else "<p class=\"muted\">No sourcetypes discovered.</p>"
            if error:
                details += f"<p class=\"kv\"><span class=\"badge\">metadata_error</span> {html.escape(error)}</p>"
            cards.append(
                "<details class=\"env-card\">"
                "<summary>"
                f"<span class=\"env-title\">index={html.escape(idx)}</span>"
                f"<span class=\"badge\">sourcetypes={len(sourcetypes)}</span>"
                "</summary>"
                "<div class=\"env-body\">"
                f"<div class=\"env-sublist\">{details}</div>"
                "</div>"
                "</details>"
            )
        return "".join(cards) if cards else "<div class=\"env-card\"><div class=\"env-body\"><p class=\"muted\">No index rows available.</p></div></div>"

    cards_html = _render_index_cards(indexes)

    profile_json = html.escape(json.dumps(profile, indent=2))
    return f"""
<div class=\"card\">
  <h1>Data Domains</h1>
  <p class=\"muted\">Environment-aware index, sourcetype, and known-field map used by query planning, validation, and SPL RAG constraints.</p>
  <div class=\"statline\">
    <span class=\"badge\">indexes={html.escape(str(index_count))}</span>
    <span class=\"badge\">sourcetypes={html.escape(str(sourcetype_count))}</span>
    <span class=\"badge\">field_inventory={html.escape(str(counts.get('field_inventory_sourcetypes', 0)))}</span>
    <span class=\"badge\">window={html.escape(earliest)} -> {html.escape(latest)}</span>
    <span class=\"badge\">timestamp={html.escape(timestamp)}</span>
  </div>
  <p class=\"muted\">Initial setup refreshes all missing sourcetypes in one run. After field inventory is established, maintenance refreshes incrementally to keep resource usage bounded. Last refreshed: <code>{html.escape(str(field_meta.get('last_refreshed_sourcetype', '')))}</code>. Next queued: <code>{html.escape(str(field_meta.get('next_sourcetype', '')))}</code>.</p>
  <p>Maintenance commands:</p>
  <pre>make env-profile-refresh
make env-profile-check</pre>
  <h2>All Domains (Global)</h2>
  <div class=\"env-list\">{cards_html}</div>
  <details class=\"guided\" style=\"margin-top:12px;\">
    <summary>Show Raw Environment Profile JSON</summary>
    <pre>{profile_json}</pre>
  </details>
</div>
"""


def _configure_page_body() -> str:
    return """
<div class="card">
  <style>
    .cfg-shell{display:grid;gap:16px;}
    .cfg-hero{display:grid;grid-template-columns:minmax(320px,.95fr) minmax(420px,1.05fr);gap:14px;align-items:stretch;margin-bottom:2px;}
    .cfg-hero-card{border:1px solid #244660;border-radius:18px;background:linear-gradient(160deg,#08182a,#091726 52%,#0a1d17);padding:18px 18px 16px;box-shadow:inset 0 0 0 1px rgba(255,255,255,.02);}
    .cfg-hero-title{margin:0 0 8px;font-size:28px;line-height:1.05;}
    .cfg-hero-copy{color:#a8c0d8;font-size:14px;line-height:1.65;margin:0;}
    .cfg-status-board{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;}
    .cfg-health-card{border:1px solid #234059;border-radius:14px;background:#081220;padding:12px;}
    .cfg-health-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:6px;}
    .cfg-health-name{color:#f8fafc;font-size:13px;font-weight:800;}
    .cfg-health-dot{width:12px;height:12px;border-radius:999px;background:#64748b;box-shadow:0 0 0 3px rgba(100,116,139,.15);}
    .cfg-health-dot.ok{background:#22c55e;box-shadow:0 0 0 3px rgba(34,197,94,.16);}
    .cfg-health-dot.warn{background:#f59e0b;box-shadow:0 0 0 3px rgba(245,158,11,.16);}
    .cfg-health-dot.error{background:#ef4444;box-shadow:0 0 0 3px rgba(239,68,68,.16);}
    .cfg-health-detail{color:#9fb4cc;font-size:12px;line-height:1.45;min-height:34px;}
    .cfg-step{border:1px solid #23445f;border-radius:18px;background:linear-gradient(180deg,#081525,#06111d);padding:18px;box-shadow:inset 0 0 0 1px rgba(255,255,255,.015);}
    .cfg-step summary{cursor:pointer;list-style:none;display:flex;align-items:center;justify-content:space-between;gap:12px;}
    .cfg-step summary::-webkit-details-marker{display:none;}
    .cfg-step-label{display:flex;align-items:center;gap:12px;}
    .cfg-step-num{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border-radius:999px;background:#0b2130;border:1px solid #294560;color:#dbeafe;font-size:13px;font-weight:900;}
    .cfg-step-title{font-size:19px;font-weight:800;color:#f8fafc;}
    .cfg-step-toggle{color:#9fb4cc;font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;}
    .cfg-step[open] .cfg-step-toggle::after{content:"Hide";}
    .cfg-step:not([open]) .cfg-step-toggle::after{content:"Show";}
    .cfg-step-body{margin-top:16px;}
    .cfg-stack{display:grid;gap:16px;}
    .cfg-grid{display:grid;grid-template-columns:minmax(320px,.95fr) minmax(420px,1.05fr);gap:16px;align-items:start;}
    .cfg-panel{border:1px solid #23445f;border-radius:18px;background:linear-gradient(180deg,#081525,#06111d);padding:18px;box-shadow:inset 0 0 0 1px rgba(255,255,255,.015);}
    .cfg-panel h2{margin:0 0 10px;font-size:19px;letter-spacing:.2px;}
    .cfg-panel h3{margin:18px 0 8px;font-size:13px;color:#b9d9f6;text-transform:uppercase;letter-spacing:.09em;}
    .cfg-help{color:#9fb4cc;font-size:13px;line-height:1.6;margin:0 0 12px;}
    .cfg-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;}
    .cfg-row{display:grid;grid-template-columns:1fr;gap:6px;align-items:start;margin:0;}
    .cfg-row.wide{grid-column:1 / -1;}
    .cfg-row label{margin:0;color:#d7e6f5;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.08em;}
    .cfg-example{color:#89a7c4;font-size:11px;line-height:1.45;margin-top:2px;}
    .cfg-field, .cfg-row input,.cfg-row select,.cfg-row textarea, .cfg-model-row input, .cfg-model-row select{
      width:100%;box-sizing:border-box;background:linear-gradient(180deg,#06101b,#040c18);color:#f8fafc;border:1px solid #33506a;border-radius:14px;
      padding:12px 14px;font-size:13px;outline:none;transition:border-color .16s ease, box-shadow .16s ease, transform .16s ease;
      appearance:none;
    }
    .cfg-row input:focus,.cfg-row select:focus,.cfg-row textarea:focus,.cfg-model-row input:focus,.cfg-model-row select:focus{
      border-color:#60a5fa;box-shadow:0 0 0 3px rgba(96,165,250,.14);
    }
    .cfg-row select option,.cfg-model-row select option{
      background:#06101b;
      color:#f8fafc;
    }
    .cfg-row textarea{min-height:100px;resize:vertical;font-family:"Consolas","SFMono-Regular",Menlo,monospace;}
    .cfg-select-wrap{position:relative;}
    .cfg-select-wrap::after{content:"";position:absolute;right:16px;top:50%;width:10px;height:10px;border-right:2px solid #8fb6d9;border-bottom:2px solid #8fb6d9;transform:translateY(-65%) rotate(45deg);pointer-events:none;}
    .cfg-actions{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:16px;}
    .cfg-status{font-size:13px;color:#9fb4cc;}
    .cfg-note{margin-top:14px;padding:12px 14px;border:1px solid #36516b;border-radius:14px;background:#091423;color:#dbeafe;font-size:13px;line-height:1.55;}
    .cfg-pre{white-space:pre-wrap;background:#020617;border:1px solid #1f2937;border-radius:14px;padding:14px;overflow:auto;line-height:1.5;font-family:"Consolas","SFMono-Regular",Menlo,monospace;font-size:12px;}
    .cfg-badges{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 0;}
    .cfg-badge{display:inline-flex;align-items:center;padding:4px 10px;border-radius:999px;border:1px solid #294560;background:#0b2130;color:#bde6ff;font-size:12px;font-weight:700;}
    .cfg-linkline{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:10px 0 16px;}
    .cfg-linkbtn{
      display:inline-flex;align-items:center;gap:8px;padding:11px 15px;border-radius:16px;
      border:1px solid #315a79;background:linear-gradient(180deg,#16324a,#102435);color:#e0f2fe;
      text-decoration:none;font-size:13px;font-weight:800;letter-spacing:.01em;
      box-shadow:0 12px 24px rgba(8,23,37,.26), inset 0 1px 0 rgba(255,255,255,.05);
      transition:transform .18s ease, box-shadow .18s ease, border-color .18s ease, filter .18s ease;
    }
    .cfg-linkbtn:hover{
      transform:translateY(-1px);filter:brightness(1.04);border-color:#60a5fa;
      box-shadow:0 16px 30px rgba(8,23,37,.34), inset 0 1px 0 rgba(255,255,255,.06);
    }
    .cfg-validate-grid{display:grid;gap:8px;}
    .cfg-check{border:1px solid #25384d;border-radius:14px;padding:12px 14px;background:#091423;}
    .cfg-check.ok{border-color:#166534;background:#062313;}
    .cfg-check.warn{border-color:#a16207;background:#2a1a06;}
    .cfg-check.error{border-color:#991b1b;background:#2a0d0d;}
    .cfg-check-head{display:flex;justify-content:space-between;gap:10px;align-items:center;margin-bottom:4px;}
    .cfg-check-name{font-weight:800;color:#f8fafc;font-size:13px;}
    .cfg-check-detail{color:#d7e6f5;font-size:13px;line-height:1.45;white-space:pre-wrap;}
    .cfg-check-meta{margin-top:6px;color:#bfd3e7;font-size:12px;line-height:1.4;white-space:pre-wrap;}
    .cfg-model-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin-top:14px;}
    .cfg-model-card{
      --cfg-accent:#38bdf8;
      border:1px solid color-mix(in srgb, var(--cfg-accent) 34%, #183246);border-radius:20px;
      background:
        radial-gradient(circle at top right, color-mix(in srgb, var(--cfg-accent) 18%, transparent), transparent 38%),
        linear-gradient(180deg,#0a1627,#07111f 78%);
      padding:16px 16px 14px;
      box-shadow:0 16px 30px rgba(2,6,23,.18), inset 0 1px 0 rgba(255,255,255,.03);
      position:relative;overflow:hidden;
    }
    .cfg-model-card::before{
      content:"";position:absolute;left:0;right:0;top:0;height:3px;
      background:linear-gradient(90deg,var(--cfg-accent), rgba(255,255,255,.06));
      opacity:.95;
    }
    .cfg-model-card.role-query-writer{--cfg-accent:#38bdf8;}
    .cfg-model-card.role-repair{--cfg-accent:#0ea5e9;}
    .cfg-model-card.role-evidence{--cfg-accent:#14b8a6;}
    .cfg-model-card.role-security{--cfg-accent:#22c55e;}
    .cfg-model-card.role-peer1{--cfg-accent:#a78bfa;}
    .cfg-model-card.role-peer2{--cfg-accent:#f472b6;}
    .cfg-model-card.role-continuation{--cfg-accent:#f59e0b;}
    .cfg-model-card.role-summary{--cfg-accent:#fb7185;}
    .cfg-model-card h4{margin:0 0 4px;font-size:15px;color:#f8fafc;}
    .cfg-model-card p{margin:0 0 12px;color:#9fb4cc;font-size:12px;line-height:1.55;}
    .cfg-model-label{display:block;margin:0 0 6px;color:#d7e6f5;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.08em;}
    .cfg-model-picker{display:grid;gap:12px;}
    .cfg-model-input{
      width:100%;box-sizing:border-box;background:linear-gradient(180deg,color-mix(in srgb, var(--cfg-accent) 8%, #06101b),#040c18);color:#f8fafc;border:1px solid color-mix(in srgb, var(--cfg-accent) 44%, #2a4a64);border-radius:14px;
      padding:12px 14px;font-size:13px;outline:none;transition:border-color .16s ease, box-shadow .16s ease;
    }
    .cfg-model-input:focus{border-color:var(--cfg-accent);box-shadow:0 0 0 3px color-mix(in srgb, var(--cfg-accent) 20%, transparent);}
    .cfg-model-picks{display:grid;grid-template-columns:1fr;gap:8px;max-height:188px;overflow:auto;padding-right:4px;}
    .cfg-model-pick{
      border:1px solid color-mix(in srgb, var(--cfg-accent) 38%, #29465e);
      background:linear-gradient(180deg,color-mix(in srgb, var(--cfg-accent) 13%, #13283d),#0c1d2e);
      color:#dbeafe;
      border-radius:12px;
      padding:10px 12px;
      font-size:12px;
      line-height:1.25;
      cursor:pointer;
      box-shadow:inset 0 1px 0 rgba(255,255,255,.04);
      transition:transform .16s ease, border-color .16s ease, background .16s ease, box-shadow .16s ease;
      text-align:left;
      width:100%;
      overflow-wrap:anywhere;
      word-break:break-word;
    }
    .cfg-model-pick:hover{
      transform:translateY(-1px);
      border-color:var(--cfg-accent);
      background:linear-gradient(180deg,color-mix(in srgb, var(--cfg-accent) 20%, #17324b),#10263a);
      box-shadow:0 10px 20px rgba(2,6,23,.18), inset 0 1px 0 rgba(255,255,255,.05);
    }
    .cfg-model-pick.active{
      border-color:color-mix(in srgb, var(--cfg-accent) 70%, #ffffff10);
      background:linear-gradient(180deg,color-mix(in srgb, var(--cfg-accent) 30%, #10263a),color-mix(in srgb, var(--cfg-accent) 18%, #0c1d2e));
      color:#f8fbff;
      box-shadow:0 10px 20px rgba(3,18,13,.18), inset 0 1px 0 rgba(255,255,255,.05);
    }
    .cfg-model-pick-empty{
      color:#94a3b8;
      font-size:12px;
      padding:2px 0 0;
    }
    .cfg-tip{font-size:12px;color:#a9bfd6;line-height:1.55;margin-top:8px;}
    .cfg-subgrid{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
    .cfg-compare{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin:14px 0 16px;}
    .cfg-compare-card{
      border:1px solid #2a4a64;border-radius:18px;
      background:linear-gradient(180deg,#0a1627,#07111f 78%);
      padding:14px;
      box-shadow:0 14px 26px rgba(2,6,23,.16), inset 0 1px 0 rgba(255,255,255,.03);
      min-width:0;
    }
    .cfg-compare-card h4{margin:0 0 10px;font-size:13px;color:#f8fafc;letter-spacing:.02em;}
    .cfg-compare-list{display:grid;gap:6px;min-width:0;}
    .cfg-compare-item{border:1px solid #254059;border-radius:12px;background:#07111f;padding:9px 11px;color:#dbeafe;font-size:12px;line-height:1.5;overflow-wrap:anywhere;word-break:break-word;min-width:0;}
    .cfg-compare-item.ok{border-color:#166534;background:#062313;color:#dcfce7;}
    .cfg-compare-item.warn{border-color:#a16207;background:#2a1a06;color:#fde68a;}
    .cfg-personalize-card{border:1px solid #27415a;border-radius:16px;background:linear-gradient(180deg,#091423,#07111f);padding:16px;}
    .cfg-personalize-status{display:flex;gap:10px;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;}
    .cfg-personalize-copy{color:#dbeafe;font-size:13px;line-height:1.6;}
    .cfg-personalize-meta{margin-top:10px;display:grid;gap:8px;}
    .cfg-progress-wrap{display:grid;gap:8px;margin-top:12px;}
    .cfg-progress-head{display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap;}
    .cfg-progress-track{width:100%;height:12px;border-radius:999px;border:1px solid #26435c;background:#07111f;overflow:hidden;}
    .cfg-progress-bar{height:100%;width:0%;background:linear-gradient(90deg,#22c55e,#10b981);transition:width .25s ease;}
    .cfg-progress-log{max-height:220px;}
    .cfg-shell button{
      margin-top:0;
      background:linear-gradient(135deg,#22c55e,#14b86a);
      color:#03210d;
      border:1px solid rgba(134,239,172,.22);
      border-radius:16px;
      font-weight:800;
      padding:12px 16px;
      cursor:pointer;
      letter-spacing:.01em;
      box-shadow:0 12px 24px rgba(20,184,106,.24), inset 0 1px 0 rgba(255,255,255,.18);
      transition:transform .18s ease, box-shadow .18s ease, filter .18s ease, border-color .18s ease;
    }
    .cfg-shell button:hover{
      transform:translateY(-1px);
      filter:brightness(1.03);
      box-shadow:0 16px 30px rgba(20,184,106,.30), inset 0 1px 0 rgba(255,255,255,.2);
    }
    .cfg-shell .btn-secondary{
      background:linear-gradient(180deg,#16324a,#102435);
      color:#dbeafe;
      border-color:#315a79;
      box-shadow:0 12px 24px rgba(8,23,37,.26), inset 0 1px 0 rgba(255,255,255,.05);
    }
    .cfg-shell .btn-secondary:hover{
      box-shadow:0 16px 30px rgba(8,23,37,.34), inset 0 1px 0 rgba(255,255,255,.06);
    }
    @media (max-width: 1120px){.cfg-grid{grid-template-columns:1fr;}.cfg-hero{grid-template-columns:1fr;}}
    @media (max-width: 980px){.cfg-form-grid,.cfg-subgrid,.cfg-status-board,.cfg-model-grid,.cfg-compare{grid-template-columns:1fr;}}
  </style>
  <h1>Configuration</h1>
  <p class="muted">Central runtime setup for A.G.E.N.T. Smith, including Splunk MCP, the primary Ollama host, optional edge-helper routing, UI auth, tasker-role assignments, and repeatable deployment guidance for both host and Docker runtimes.</p>
  <div class="cfg-shell">
  <div class="cfg-hero">
    <div class="cfg-hero-card">
      <h2 class="cfg-hero-title">AGENT Smith runtime control center</h2>
      <p class="cfg-hero-copy">Use this page to point A.G.E.N.T. Smith at the right primary Ollama and Splunk services, optionally include a small edge helper for routing, assign model roles, validate live dependencies, and bring the platform online in the right order for either host or Docker deployment.</p>
      <div id="cfg-runtime" class="cfg-badges"></div>
      <div class="cfg-linkline">
        <a id="cfg-setup-link" class="cfg-linkbtn" href="/docs/view?path=runbooks/initial_setup.md">Open Initial Setup Guide</a>
        <span class="cfg-tip">Use this first on a new machine. It assumes Splunk is already installed and walks the rest of the setup step by step.</span>
      </div>
    </div>
    <div class="cfg-hero-card">
      <h3 style="margin:0 0 12px;font-size:13px;color:#b9d9f6;text-transform:uppercase;letter-spacing:.09em;">Live Dependency Status</h3>
      <div id="cfg-health-board" class="cfg-status-board">
        <div class="cfg-health-card"><div class="cfg-health-head"><span class="cfg-health-name">Ollama</span><span class="cfg-health-dot"></span></div><div class="cfg-health-detail">Waiting for validation.</div></div>
        <div class="cfg-health-card"><div class="cfg-health-head"><span class="cfg-health-name">Edge Helper</span><span class="cfg-health-dot"></span></div><div class="cfg-health-detail">Waiting for validation.</div></div>
        <div class="cfg-health-card"><div class="cfg-health-head"><span class="cfg-health-name">Splunk Base</span><span class="cfg-health-dot"></span></div><div class="cfg-health-detail">Waiting for validation.</div></div>
        <div class="cfg-health-card"><div class="cfg-health-head"><span class="cfg-health-name">Splunk MCP</span><span class="cfg-health-dot"></span></div><div class="cfg-health-detail">Waiting for validation.</div></div>
        <div class="cfg-health-card"><div class="cfg-health-head"><span class="cfg-health-name">Data Domains Init</span><span class="cfg-health-dot"></span></div><div class="cfg-health-detail">Waiting for validation.</div></div>
      </div>
    </div>
  </div>
  <div class="cfg-stack">
    <div class="cfg-step" open>
      <div class="cfg-step-label">
        <span class="cfg-step-num">1</span>
        <div class="cfg-step-title">Open Initial Setup Guide</div>
      </div>
      <div class="cfg-step-body">
        <p class="cfg-help">Use the setup guide first on a new machine. It is now Docker-first and is meant to get a fresh deployment online with the fewest possible steps.</p>
        <div class="cfg-linkline" style="margin:0;">
          <a id="cfg-setup-link-inline" class="cfg-linkbtn" href="/docs/view?path=runbooks/initial_setup.md">Open Initial Setup Guide</a>
        </div>
      </div>
    </div>
    <details class="cfg-step">
      <summary>
        <div class="cfg-step-label">
          <span class="cfg-step-num">2</span>
          <div class="cfg-step-title">Runtime Endpoints</div>
        </div>
        <span class="cfg-step-toggle"></span>
      </summary>
      <div class="cfg-step-body">
      <div class="cfg-panel" style="padding:0;border:0;background:transparent;box-shadow:none;">
      <p class="cfg-help">These values drive the current host runtime and both Docker modes. Saving writes <code>config/ui.env</code>. In Docker, the initial Data Domains build starts only after Splunk MCP validates successfully.</p>
      <div class="cfg-form-grid">
      <div class="cfg-row"><label for="cfg-ollama-host">OLLAMA_HOST</label><div class="cfg-example">Example URL: <code>http://192.168.1.50:11434</code></div><input id="cfg-ollama-host" placeholder="http://192.168.1.50:11434" /></div>
      <div class="cfg-row"><label for="cfg-splunk-base">SPLUNK_BASE_URL</label><div class="cfg-example">Example URL: <code>https://192.168.1.60:8089</code></div><input id="cfg-splunk-base" placeholder="https://192.168.1.60:8089" /></div>
      <div class="cfg-row wide"><label for="cfg-splunk-mcp">SPLUNK_MCP_URL</label><div class="cfg-example">Example URL: <code>https://192.168.1.60:8089/services/mcp</code></div><input id="cfg-splunk-mcp" placeholder="https://192.168.1.60:8089/services/mcp" /></div>
      <div class="cfg-row wide"><label for="cfg-splunk-token">SPLUNK_LAB_BEARER_TOKEN</label><div class="cfg-example">Example: paste the Splunk MCP bearer token used by the server-side runtime.</div><textarea id="cfg-splunk-token" placeholder="Bearer token value"></textarea></div>
      <h3>UI Access</h3>
      <div class="cfg-row"><label for="cfg-auth-enabled">SOC_UI_AUTH_ENABLED</label><div class="cfg-example">Keep this enabled for a guarded multi-user UI. First-run setup creates the initial user automatically.</div><div class="cfg-select-wrap"><select id="cfg-auth-enabled"><option value="1">1</option><option value="0">0</option></select></div></div>
      </div>
      <div class="cfg-actions">
        <button id="cfg-save">Save Configuration</button>
        <button id="cfg-validate" class="btn-secondary">Validate Current Config</button>
        <span id="cfg-status" class="cfg-status">Loading current values...</span>
      </div>
      <div class="cfg-note">
        Save updates <code>config/ui.env</code>. Restart guidance is shown on the right for host runtime, Docker wrapper, and deployment image.
      </div>
      <h3>Validation Checker</h3>
      <p class="cfg-help">This runs bounded live checks against the current values and confirms whether the Ollama endpoint, expected models, Splunk base URL, and Splunk MCP endpoint are reachable. In Docker, a successful MCP check also kicks off the first Data Domains build if it has not been created yet.</p>
      <div id="cfg-validation-summary" class="cfg-badges"></div>
      <div id="cfg-validation-results" class="cfg-validate-grid">
        <div class="cfg-note">No validation has been run yet.</div>
      </div>
     </div>
     </div>
    </details>
    <details class="cfg-step">
      <summary>
        <div class="cfg-step-label">
          <span class="cfg-step-num">3</span>
          <div class="cfg-step-title">Expected Models and Commands</div>
        </div>
        <span class="cfg-step-toggle"></span>
      </summary>
      <div class="cfg-step-body">
      <div class="cfg-panel" style="padding:0;border:0;background:transparent;box-shadow:none;">
    <p class="cfg-help">These model slots are used by the primary inference pipeline. If the primary Ollama endpoint is reachable, the selectors below are populated from the currently installed model list. Saving a model name here only assigns that role; it does not install the model. The optional edge-helper model is configured separately in Step 4.</p>
    <div id="cfg-model-compare" class="cfg-compare">
      <div class="cfg-compare-card"><h4>Expected</h4><div id="cfg-expected-list" class="cfg-compare-list"></div></div>
      <div class="cfg-compare-card"><h4>Installed</h4><div id="cfg-installed-list" class="cfg-compare-list"></div></div>
      <div class="cfg-compare-card"><h4>Missing</h4><div id="cfg-missing-list" class="cfg-compare-list"></div></div>
    </div>
    <div class="cfg-model-grid">
      <div class="cfg-model-card role-security"><h4>Planner</h4><p>Interprets analyst intent, likely data sources, and search strategy before SPL generation.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-planner">Assigned model</label><input id="cfg-model-planner" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-planner-picks" class="cfg-model-picks"></div></div></div></div>
      <div class="cfg-model-card role-query-writer"><h4>SPL Writer</h4><p>Turns the structured plan into bounded read-only SPL or a bounded MCP retrieval call.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-query-writer">Assigned model</label><input id="cfg-model-query-writer" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-query-writer-picks" class="cfg-model-picks"></div></div></div></div>
      <div class="cfg-model-card role-repair"><h4>Query Repair</h4><p>Used when the reviewer or validation path requests a bounded rewrite of the SPL before final approval.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-repair">Assigned model</label><input id="cfg-model-repair" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-repair-picks" class="cfg-model-picks"></div></div></div></div>
      <div class="cfg-model-card role-evidence"><h4>Evidence Reviewer</h4><p>Checks whether conclusions are supported by the returned rows.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-evidence">Assigned model</label><input id="cfg-model-evidence" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-evidence-picks" class="cfg-model-picks"></div></div></div></div>
      <div class="cfg-model-card role-security"><h4>Security Reviewer</h4><p>Critiques the planned query for quality, alignment, and safety.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-security">Assigned model</label><input id="cfg-model-security" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-security-picks" class="cfg-model-picks"></div></div></div></div>
      <div class="cfg-model-card role-peer1"><h4>Peer Reviewer 1</h4><p>Conditional adjudication pass used only when the security reviewer does not cleanly approve the writer output.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-peer1">Assigned model</label><input id="cfg-model-peer1" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-peer1-picks" class="cfg-model-picks"></div></div></div></div>
      <div class="cfg-model-card role-peer2"><h4>Peer Reviewer 2</h4><p>Conditional second adjudication pass that validates or overrides the first peer-review decision.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-peer2">Assigned model</label><input id="cfg-model-peer2" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-peer2-picks" class="cfg-model-picks"></div></div></div></div>
      <div class="cfg-model-card role-continuation"><h4>Continuation Reviewer</h4><p>Decides whether deeper investigation is worth another bounded pivot.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-continuation">Assigned model</label><input id="cfg-model-continuation" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-continuation-picks" class="cfg-model-picks"></div></div></div></div>
      <div class="cfg-model-card role-summary"><h4>Final Summary</h4><p>Produces the analyst-facing narrative after evidence and gates are complete.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-summary">Assigned model</label><input id="cfg-model-summary" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-summary-picks" class="cfg-model-picks"></div></div></div></div>
    </div>
    <datalist id="cfg-models-list"></datalist>
    <div class="cfg-tip">Recommended flow: pick a model already visible from Ollama, save the assignment, then use the generated pull commands below to install anything that is missing.</div>
    <div class="cfg-subgrid">
      <div>
        <h3>Generated Ollama Pull Commands</h3>
        <pre id="cfg-ollama-pulls" class="cfg-pre"></pre>
        <h3>Connectivity Checks</h3>
        <pre id="cfg-checks" class="cfg-pre"></pre>
      </div>
      <div>
        <h3>Generated Splunk MCP Config</h3>
        <pre id="cfg-mcp-json" class="cfg-pre"></pre>
        <h3>Restart Commands</h3>
        <pre id="cfg-restart" class="cfg-pre"></pre>
      </div>
    </div>
    </div>
    </details>
    <details class="cfg-step">
      <summary>
        <div class="cfg-step-label">
          <span class="cfg-step-num">4</span>
          <div class="cfg-step-title">Optional Edge Helper</div>
        </div>
        <span class="cfg-step-toggle"></span>
      </summary>
      <div class="cfg-step-body">
      <div class="cfg-panel" style="padding:0;border:0;background:transparent;box-shadow:none;">
      <p class="cfg-help">This is optional. Leave it disabled if you want the primary inference host to handle all planning, writing, and review stages. Enable it only when you want a small edge-hosted model to assist with question routing, split-query hints, or cheap confidence pre-checks.</p>
      <div class="cfg-form-grid">
      <div class="cfg-row"><label for="cfg-edge-enabled">EDGE_LLM_ENABLED</label><div class="cfg-example">Use <code>0</code> to leave the edge helper out of the runtime entirely.</div><div class="cfg-select-wrap"><select id="cfg-edge-enabled"><option value="0">0</option><option value="1">1</option></select></div></div>
      <div class="cfg-row"><label for="cfg-edge-role">EDGE_LLM_ROLE</label><div class="cfg-example">Recommended: <code>edge_router_splitter</code></div><input id="cfg-edge-role" placeholder="edge_router_splitter" /></div>
      <div class="cfg-row"><label for="cfg-edge-host">EDGE_LLM_HOST</label><div class="cfg-example">Example URL: <code>http://192.168.1.70:11434</code></div><input id="cfg-edge-host" placeholder="http://192.168.1.70:11434" /></div>
      <div class="cfg-row"><label for="cfg-edge-timeout">EDGE_LLM_TIMEOUT_SEC</label><div class="cfg-example">Short timeout for a cheap routing helper. Example: <code>20</code></div><input id="cfg-edge-timeout" placeholder="20" /></div>
      <div class="cfg-row wide"><label for="cfg-edge-model">EDGE_LLM_MODEL</label><div class="cfg-example">Small routing model name visible from the edge Ollama host. Example: <code>qwen2.5:1.5b</code></div><input id="cfg-edge-model" list="cfg-edge-models-list" placeholder="qwen2.5:1.5b" /></div>
      </div>
      <div class="cfg-note">
        If enabled, validation checks the edge endpoint and confirms the assigned model is installed. If disabled, the validation board records that the helper is intentionally excluded.
      </div>
      <div class="cfg-subgrid">
        <div>
          <h3>Edge Helper Checks</h3>
          <pre id="cfg-edge-checks" class="cfg-pre"></pre>
        </div>
        <div>
          <h3>Discovered Edge Models</h3>
          <pre id="cfg-edge-model-list" class="cfg-pre"></pre>
        </div>
      </div>
      <h3>Edge Pull Command</h3>
      <pre id="cfg-edge-pull" class="cfg-pre"></pre>
      <datalist id="cfg-edge-models-list"></datalist>
      </div>
      </div>
    </details>
    <details class="cfg-step">
      <summary>
        <div class="cfg-step-label">
          <span class="cfg-step-num">5</span>
          <div class="cfg-step-title">Personalize SPL With Environmental Awareness</div>
        </div>
        <span class="cfg-step-toggle"></span>
      </summary>
      <div class="cfg-step-body">
      <div class="cfg-panel" style="padding:0;border:0;background:transparent;box-shadow:none;">
        <div class="cfg-personalize-card">
          <div class="cfg-personalize-status">
            <div>
              <h3 style="margin-top:0;">Refresh Data Domains</h3>
              <p class="cfg-help">This runs the same <code>make env-profile-refresh</code> workflow from the web UI. Use it when you want to rebuild environment awareness after Splunk data changes or after the initial MCP connection is established.</p>
            </div>
            <span id="cfg-env-refresh-state" class="cfg-badge">state=unknown</span>
          </div>
          <div id="cfg-env-refresh-detail" class="cfg-personalize-copy">Waiting for configuration load.</div>
          <div class="cfg-actions">
            <button id="cfg-env-refresh">Refresh Data Domains</button>
            <span id="cfg-env-refresh-status" class="cfg-status">Not started.</span>
          </div>
          <div class="cfg-progress-wrap">
            <div class="cfg-progress-head">
              <span id="cfg-env-refresh-phase" class="cfg-note" style="margin-top:0;">phase=idle</span>
              <span id="cfg-env-refresh-pct" class="cfg-badge">0%</span>
            </div>
            <div class="cfg-progress-track"><div id="cfg-env-refresh-bar" class="cfg-progress-bar"></div></div>
            <pre id="cfg-env-refresh-log" class="cfg-pre cfg-progress-log">No refresh output yet.</pre>
          </div>
          <div class="cfg-personalize-meta">
            <div id="cfg-env-refresh-path" class="cfg-note">Refresh log path will appear here.</div>
          </div>
        </div>
        <div class="cfg-personalize-card" style="margin-top:14px;">
          <div class="cfg-personalize-status">
            <div>
              <h3 style="margin-top:0;">Environment-Aware SPL Personalization</h3>
              <p class="cfg-help">This step builds the personalized SPL guidance layer that combines shipped RAG with the live environment profile. On first setup, it is created automatically when Data Domains completes successfully. Use this button later to rebuild personalization after environment changes.</p>
            </div>
            <span id="cfg-personalize-state" class="cfg-badge">state=unknown</span>
          </div>
          <div id="cfg-personalize-detail" class="cfg-personalize-copy">Waiting for configuration load.</div>
          <div class="cfg-actions">
            <button id="cfg-personalize">Build Personalization</button>
            <span id="cfg-personalize-status" class="cfg-status">Not started.</span>
          </div>
          <div class="cfg-progress-wrap">
            <div class="cfg-progress-head">
              <span id="cfg-personalize-phase" class="cfg-note" style="margin-top:0;">phase=idle</span>
              <span id="cfg-personalize-pct" class="cfg-badge">0%</span>
            </div>
            <div class="cfg-progress-track"><div id="cfg-personalize-bar" class="cfg-progress-bar"></div></div>
            <pre id="cfg-personalize-log" class="cfg-pre cfg-progress-log">No personalization output yet.</pre>
          </div>
          <div class="cfg-personalize-meta">
            <div id="cfg-personalize-path" class="cfg-note">Skillpack path will appear after personalization exists.</div>
            <div class="cfg-note">What this does: refreshes the environment profile once, rebuilds the SPL skillpack, and updates the environment-aware RAG used by query writing, validation, and repair. Initial Data Domains refresh already creates this automatically.</div>
          </div>
        </div>
      </div>
      </div>
    </details>
  </div>
</div>
</div>
<script>
  const cfg$ = (id) => document.getElementById(id);
  function cfgEscape(v){return String(v ?? '');}
  const cfgModelPairs = [
    ['cfg-model-planner','cfg-model-planner-picks'],
    ['cfg-model-query-writer','cfg-model-query-writer-picks'],
    ['cfg-model-repair','cfg-model-repair-picks'],
    ['cfg-model-evidence','cfg-model-evidence-picks'],
    ['cfg-model-security','cfg-model-security-picks'],
    ['cfg-model-peer1','cfg-model-peer1-picks'],
    ['cfg-model-peer2','cfg-model-peer2-picks'],
    ['cfg-model-continuation','cfg-model-continuation-picks'],
    ['cfg-model-summary','cfg-model-summary-picks']
  ];
  function cfgApplyPayload(values){
    const payload = values || {};
    cfg$('cfg-ollama-host').value = payload.OLLAMA_HOST || '';
    cfg$('cfg-splunk-base').value = payload.SPLUNK_BASE_URL || '';
    cfg$('cfg-splunk-mcp').value = payload.SPLUNK_MCP_URL || '';
    cfg$('cfg-splunk-token').value = payload.SPLUNK_LAB_BEARER_TOKEN || '';
    cfg$('cfg-auth-enabled').value = payload.SOC_UI_AUTH_ENABLED || '1';
    cfg$('cfg-edge-enabled').value = payload.EDGE_LLM_ENABLED || '0';
    cfg$('cfg-edge-host').value = payload.EDGE_LLM_HOST || '';
    cfg$('cfg-edge-model').value = payload.EDGE_LLM_MODEL || '';
    cfg$('cfg-edge-role').value = payload.EDGE_LLM_ROLE || 'edge_router_splitter';
    cfg$('cfg-edge-timeout').value = payload.EDGE_LLM_TIMEOUT_SEC || '20';
    cfg$('cfg-model-planner').value = payload.OLLAMA_MODEL_QUERY_PLANNER || '';
    cfg$('cfg-model-query-writer').value = payload.OLLAMA_MODEL_QUERY_WRITER || '';
    cfg$('cfg-model-repair').value = payload.OLLAMA_MODEL_QUERY_REPAIR || '';
    cfg$('cfg-model-evidence').value = payload.OLLAMA_MODEL_EVIDENCE_REVIEWER || '';
    cfg$('cfg-model-security').value = payload.OLLAMA_MODEL_SECURITY_REVIEWER || '';
    cfg$('cfg-model-peer1').value = payload.OLLAMA_MODEL_PEER_REVIEWER || '';
    cfg$('cfg-model-peer2').value = payload.OLLAMA_MODEL_PEER_REVIEWER_2 || '';
    cfg$('cfg-model-continuation').value = payload.OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER || '';
    cfg$('cfg-model-summary').value = payload.OLLAMA_MODEL_FINAL_SUMMARY || '';
  }
  const cfgDefaultAssignments = {
    OLLAMA_MODEL_QUERY_PLANNER: 'hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M',
    OLLAMA_MODEL_QUERY_WRITER: 'deepseek-coder-v2:lite',
    OLLAMA_MODEL_QUERY_REPAIR: 'deepseek-coder-v2:lite',
    OLLAMA_MODEL_EVIDENCE_REVIEWER: 'hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M',
    OLLAMA_MODEL_SECURITY_REVIEWER: 'hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M',
    OLLAMA_MODEL_PEER_REVIEWER: 'hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M',
    OLLAMA_MODEL_PEER_REVIEWER_2: 'hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M',
    OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER: 'hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest',
    OLLAMA_MODEL_FINAL_SUMMARY: 'hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest'
  };
  function cfgExpectedModelsFromValues(values, explicitExpected){
    const explicit = Array.isArray(explicitExpected) ? explicitExpected.filter(Boolean) : [];
    if(explicit.length){ return explicit; }
    const raw = Object.values(cfgDefaultAssignments).map((model) => String(model || '').trim()).filter(Boolean);
    return raw.filter((model, index) => raw.indexOf(model) === index);
  }
  function cfgRenderModelCompare(values, installedModels, explicitExpected){
    const expected = cfgExpectedModelsFromValues(values || {}, explicitExpected);
    const installed = Array.isArray(installedModels) ? installedModels : [];
    const missing = expected.filter(model => !installed.includes(model));
    const renderList = (id, items, cls='') => {
      cfg$(id).innerHTML = items.length
        ? items.map(item => `<div class="cfg-compare-item ${cls}">${cfgEscape(item)}</div>`).join('')
        : '<div class="cfg-compare-item">None</div>';
    };
    renderList('cfg-expected-list', expected);
    renderList('cfg-installed-list', installed, 'ok');
    renderList('cfg-missing-list', missing, missing.length ? 'warn' : 'ok');
  }
  function cfgAutoAssignDefaults(values, installedModels){
    const assigned = {...values};
    const installed = new Set(Array.isArray(installedModels) ? installedModels : []);
    Object.entries(cfgDefaultAssignments).forEach(([key, model]) => {
      if(String(assigned[key] || '').trim()){ return; }
      if(installed.has(model)){ assigned[key] = model; }
    });
    return assigned;
  }
  function cfgRenderPersonalization(meta){
    const state = String(meta?.state || 'unknown');
    const pct = Math.max(0, Math.min(100, Number(meta?.progress_pct || 0)));
    cfg$('cfg-personalize-state').textContent = `state=${state}`;
    cfg$('cfg-personalize-detail').textContent = meta?.detail || 'No personalization state available.';
    const path = meta?.path ? `Skillpack path: ${meta.path}` : 'Skillpack path will appear after personalization exists.';
    cfg$('cfg-personalize-path').textContent = path;
    cfg$('cfg-personalize-phase').textContent = `phase=${meta?.phase || 'idle'}`;
    cfg$('cfg-personalize-pct').textContent = `${Math.round(pct)}%`;
    cfg$('cfg-personalize-bar').style.width = `${pct}%`;
    cfg$('cfg-personalize-log').textContent = meta?.output || 'No personalization output yet.';
    const btn = cfg$('cfg-personalize');
    const blocked = state === 'blocked' || state === 'in_progress';
    btn.disabled = blocked;
    if(state === 'in_progress'){
      btn.textContent = 'Personalization Running...';
    } else if (state === 'ready'){
      btn.textContent = 'Rebuild Personalization';
    } else {
      btn.textContent = 'Build Personalization';
    }
  }
  let cfgPersonalizePoll = null;
  async function cfgPollPersonalization(){
    const resp = await fetch('/api/config/personalize');
    const data = await resp.json();
    if(!resp.ok){
      cfg$('cfg-personalize-status').textContent = data.error || `personalization status failed (${resp.status})`;
      return;
    }
    cfgRenderPersonalization(data.personalization || {});
    const state = String(data.personalization?.state || 'unknown');
    if(state === 'in_progress'){
      cfg$('cfg-personalize-status').textContent = data.personalization?.detail || 'Building personalization...';
      if(!cfgPersonalizePoll){
        cfgPersonalizePoll = window.setInterval(cfgPollPersonalization, 1200);
      }
      return;
    }
    if(cfgPersonalizePoll){
      window.clearInterval(cfgPersonalizePoll);
      cfgPersonalizePoll = null;
    }
    if(state === 'ready'){
      cfg$('cfg-personalize-status').textContent = data.personalization?.detail || 'Personalization complete.';
      return;
    }
    if(state === 'error'){
      cfg$('cfg-personalize-status').textContent = data.personalization?.detail || 'Personalization failed.';
      return;
    }
    cfg$('cfg-personalize-status').textContent = data.personalization?.detail || 'Ready.';
  }
  function cfgRenderEnvRefresh(meta){
    const state = String(meta?.state || 'unknown');
    const pct = Math.max(0, Math.min(100, Number(meta?.progress_pct || 0)));
    cfg$('cfg-env-refresh-state').textContent = `state=${state}`;
    cfg$('cfg-env-refresh-detail').textContent = meta?.detail || 'No environment refresh state available.';
    cfg$('cfg-env-refresh-phase').textContent = `phase=${meta?.phase || 'idle'}`;
    cfg$('cfg-env-refresh-pct').textContent = `${Math.round(pct)}%`;
    cfg$('cfg-env-refresh-bar').style.width = `${pct}%`;
    cfg$('cfg-env-refresh-log').textContent = meta?.output || 'No refresh output yet.';
    cfg$('cfg-env-refresh-path').textContent = meta?.log_path ? `Refresh log: ${meta.log_path}` : 'Refresh log path will appear here.';
    cfg$('cfg-env-refresh').disabled = state === 'in_progress';
  }
  let cfgEnvRefreshPoll = null;
  async function cfgPollEnvRefresh(){
    const resp = await fetch('/api/config/env-refresh');
    const data = await resp.json();
    if(!resp.ok){
      cfg$('cfg-env-refresh-status').textContent = data.error || `refresh status failed (${resp.status})`;
      return;
    }
    cfgRenderEnvRefresh(data.refresh || {});
    const state = String(data.refresh?.state || 'unknown');
    if(state === 'in_progress'){
      cfg$('cfg-env-refresh-status').textContent = data.refresh?.detail || 'Refreshing Data Domains...';
      if(!cfgEnvRefreshPoll){
        cfgEnvRefreshPoll = window.setInterval(cfgPollEnvRefresh, 1200);
      }
      return;
    }
    if(cfgEnvRefreshPoll){
      window.clearInterval(cfgEnvRefreshPoll);
      cfgEnvRefreshPoll = null;
    }
    if(state === 'ready'){
      cfg$('cfg-env-refresh-status').textContent = data.refresh?.detail || 'Data Domains refresh complete.';
    } else if(state === 'error'){
      cfg$('cfg-env-refresh-status').textContent = data.refresh?.detail || 'Data Domains refresh failed.';
    }
  }
  function cfgCollectPayload(){
    return {
      OLLAMA_HOST: cfg$('cfg-ollama-host').value.trim(),
      SPLUNK_BASE_URL: cfg$('cfg-splunk-base').value.trim(),
      SPLUNK_MCP_URL: cfg$('cfg-splunk-mcp').value.trim(),
      SPLUNK_LAB_BEARER_TOKEN: cfg$('cfg-splunk-token').value.trim(),
      SOC_UI_AUTH_ENABLED: cfg$('cfg-auth-enabled').value.trim(),
      EDGE_LLM_ENABLED: cfg$('cfg-edge-enabled').value.trim(),
      EDGE_LLM_HOST: cfg$('cfg-edge-host').value.trim(),
      EDGE_LLM_MODEL: cfg$('cfg-edge-model').value.trim(),
      EDGE_LLM_ROLE: cfg$('cfg-edge-role').value.trim(),
      EDGE_LLM_TIMEOUT_SEC: cfg$('cfg-edge-timeout').value.trim(),
      OLLAMA_MODEL_QUERY_PLANNER: cfg$('cfg-model-planner').value.trim(),
      OLLAMA_MODEL_QUERY_WRITER: cfg$('cfg-model-query-writer').value.trim(),
      OLLAMA_MODEL_QUERY_REPAIR: cfg$('cfg-model-repair').value.trim(),
      OLLAMA_MODEL_EVIDENCE_REVIEWER: cfg$('cfg-model-evidence').value.trim(),
      OLLAMA_MODEL_SECURITY_REVIEWER: cfg$('cfg-model-security').value.trim(),
      OLLAMA_MODEL_PEER_REVIEWER: cfg$('cfg-model-peer1').value.trim(),
      OLLAMA_MODEL_PEER_REVIEWER_2: cfg$('cfg-model-peer2').value.trim(),
      OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER: cfg$('cfg-model-continuation').value.trim(),
      OLLAMA_MODEL_FINAL_SUMMARY: cfg$('cfg-model-summary').value.trim()
    };
  }
  function cfgRenderQuickPicks(inputId, pickerId, models){
    const picker = cfg$(pickerId);
    const input = cfg$(inputId);
    const current = String(input.value || '').trim();
    if(!Array.isArray(models) || !models.length){
      picker.innerHTML = '<div class="cfg-model-pick-empty">No installed models discovered yet.</div>';
      return;
    }
    picker.innerHTML = models.map((model) => {
      const active = current === model ? ' active' : '';
      return `<button type="button" class="cfg-model-pick${active}" data-model="${cfgEscape(model)}">${cfgEscape(model)}</button>`;
    }).join('');
    picker.querySelectorAll('.cfg-model-pick').forEach((btn) => {
      btn.onclick = () => {
        input.value = btn.getAttribute('data-model') || '';
        cfgRenderQuickPicks(inputId, pickerId, models);
      };
    });
  }
  function cfgPopulateModelOptions(models){
    const list = cfg$('cfg-models-list');
    list.innerHTML = '';
    const normalized = Array.isArray(models) ? models : [];
    normalized.forEach((model) => {
      const option = document.createElement('option');
      option.value = model;
      list.appendChild(option);
    });
    cfgModelPairs.forEach(([inputId, pickerId]) => {
      const input = cfg$(inputId);
      input.oninput = () => cfgRenderQuickPicks(inputId, pickerId, normalized);
      cfgRenderQuickPicks(inputId, pickerId, normalized);
    });
  }
  function cfgRenderValidation(data){
    const summary = data.summary || {};
    cfg$('cfg-validation-summary').innerHTML = [
      `<span class="cfg-badge">ok=${cfgEscape(summary.ok || 0)}</span>`,
      `<span class="cfg-badge">warn=${cfgEscape(summary.warn || 0)}</span>`,
      `<span class="cfg-badge">error=${cfgEscape(summary.error || 0)}</span>`
    ].join('');
    const checks = Array.isArray(data.checks) ? data.checks : [];
    if(!checks.length){
      cfg$('cfg-validation-results').innerHTML = '<div class="cfg-note">No validation results available.</div>';
      return;
    }
    cfg$('cfg-validation-results').innerHTML = checks.map((check) => {
      const extraBits = [];
      if(Array.isArray(check.models) && check.models.length){ extraBits.push(`models: ${check.models.join(', ')}`); }
      if(Array.isArray(check.missing_models) && check.missing_models.length){ extraBits.push(`missing: ${check.missing_models.join(', ')}`); }
      return `
        <div class="cfg-check ${cfgEscape(check.status || 'warn')}">
          <div class="cfg-check-head">
            <div class="cfg-check-name">${cfgEscape(check.name || 'check')}</div>
            <span class="cfg-badge">${cfgEscape(check.status || 'unknown')}</span>
          </div>
          <div class="cfg-check-detail">${cfgEscape(check.detail || '')}</div>
          ${extraBits.length ? `<div class="cfg-check-meta">${cfgEscape(extraBits.join('\\n'))}</div>` : ''}
        </div>
      `;
    }).join('');
    const statusMap = {};
    checks.forEach((check) => { statusMap[check.name] = check; });
    const healthCards = [
      ['ollama_api', 'Ollama'],
      ['edge_helper', 'Edge Helper'],
      ['splunk_base', 'Splunk Base'],
      ['splunk_mcp', 'Splunk MCP'],
      ['environment_profile', 'Data Domains Init']
    ];
    cfg$('cfg-health-board').innerHTML = healthCards.map(([key, label]) => {
      const check = statusMap[key] || {};
      const state = cfgEscape(check.status || 'warn');
      const detail = cfgEscape(check.detail || 'Validation has not completed yet.');
      return `
        <div class="cfg-health-card">
          <div class="cfg-health-head">
            <span class="cfg-health-name">${cfgEscape(label)}</span>
            <span class="cfg-health-dot ${state}"></span>
          </div>
          <div class="cfg-health-detail">${detail}</div>
        </div>
      `;
    }).join('');
  }
  function cfgRender(data){
    const values = data.values || {};
    cfgApplyPayload(values);
    cfgPopulateModelOptions(data.ollama_available_models || []);
    cfgRenderModelCompare(values, data.ollama_available_models || [], data.expected_models || []);
    cfg$('cfg-ollama-pulls').textContent = (data.ollama_pull_commands || []).join('\\n') || 'No model pull commands generated.';
    cfg$('cfg-mcp-json').textContent = data.splunk_mcp_config_json || '{}';
    cfg$('cfg-checks').textContent = [
      data.connectivity_checks?.ollama_tags || '',
      data.connectivity_checks?.edge_ollama_tags || '',
      data.connectivity_checks?.splunk_mcp || ''
    ].filter(Boolean).join('\\n\\n');
    cfg$('cfg-edge-checks').textContent = data.connectivity_checks?.edge_ollama_tags || 'Edge helper disabled or not configured.';
    cfg$('cfg-edge-model-list').textContent = (data.edge_ollama_available_models || []).join('\\n') || 'No edge models discovered.';
    cfg$('cfg-edge-pull').textContent = data.edge_helper?.pull_command || 'No edge model pull command generated.';
    const edgeList = cfg$('cfg-edge-models-list');
    edgeList.innerHTML = '';
    (data.edge_ollama_available_models || []).forEach((model) => {
      const option = document.createElement('option');
      option.value = model;
      edgeList.appendChild(option);
    });
    cfg$('cfg-restart').textContent = [
      `Host runtime:\\n${data.host_restart_command || ''}`,
      `Docker wrapper:\\n${data.docker_wrapper_restart_command || ''}`,
      `Deployment image:\\n${data.docker_deploy_restart_command || ''}`
    ].join('\\n\\n');
    cfg$('cfg-runtime').innerHTML = [
      `<span class="cfg-badge">mode=${cfgEscape(data.runtime_mode || 'unknown')}</span>`,
      `<span class="cfg-badge">config=${cfgEscape(data.config_path || '')}</span>`
    ].join('');
    const setupPath = data.setup_guide_path || 'runbooks/initial_setup.md';
    cfg$('cfg-setup-link').href = `/docs/view?path=${encodeURIComponent(setupPath)}`;
    cfg$('cfg-setup-link-inline').href = `/docs/view?path=${encodeURIComponent(setupPath)}`;
    cfgRenderEnvRefresh(data.environment_profile_refresh || {});
    cfgRenderPersonalization(data.personalization || {});
  }
  async function cfgLoad(){
    const resp = await fetch('/api/config/runtime');
    const data = await resp.json();
    if(!resp.ok){ cfg$('cfg-status').textContent = data.error || `load failed (${resp.status})`; return; }
    cfgRender(data);
    cfg$('cfg-status').textContent = 'Loaded current configuration.';
    if(String(data.environment_profile_refresh?.state || '') === 'in_progress'){
      await cfgPollEnvRefresh();
    }
    if(String(data.personalization?.state || '') === 'in_progress'){
      await cfgPollPersonalization();
    }
    await cfgValidate();
  }
  async function cfgValidate(){
    const draft = cfgCollectPayload();
    cfg$('cfg-status').textContent = 'Validating live connections...';
    const resp = await fetch('/api/config/validate', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({values: draft})
    });
    const data = await resp.json();
    if(!resp.ok){
      cfgApplyPayload(draft);
      cfg$('cfg-status').textContent = data.error || `validation failed (${resp.status})`;
      return;
    }
    if(Array.isArray(data.ollama_available_models)){ cfgPopulateModelOptions(data.ollama_available_models); }
    cfgApplyPayload(draft);
    cfgRenderModelCompare(draft, data.ollama_available_models || [], data.expected_models || []);
    cfgRenderValidation(data);
    if(data.environment_profile_status === 'in_progress'){
      cfg$('cfg-status').textContent = 'Validation complete. Data Domains initialization started.';
    } else {
      cfg$('cfg-status').textContent = 'Validation complete.';
    }
    const runtime = await fetch('/api/config/runtime');
    if(runtime.ok){
      const runtimeData = await runtime.json();
      cfgRender(runtimeData);
    }
  }
  cfg$('cfg-save').onclick = async () => {
    cfg$('cfg-status').textContent = 'Saving...';
    let payload = cfgCollectPayload();
    const validationResp = await fetch('/api/config/validate', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({values: payload})
    });
    const validationData = await validationResp.json();
    if(!validationResp.ok){
      cfg$('cfg-status').textContent = validationData.error || `pre-save validation failed (${validationResp.status})`;
      return;
    }
    payload = cfgAutoAssignDefaults(payload, validationData.ollama_available_models || []);
    const resp = await fetch('/api/config/runtime', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({values: payload})
    });
    const data = await resp.json();
    if(!resp.ok){
      cfg$('cfg-status').textContent = data.error || `save failed (${resp.status})`;
      return;
    }
    cfgRender(data);
    cfg$('cfg-status').textContent = 'Saved to config/ui.env.';
    await cfgValidate();
  };
  cfg$('cfg-personalize').onclick = async () => {
    cfg$('cfg-personalize-status').textContent = 'Starting personalization...';
    const resp = await fetch('/api/config/personalize', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({})
    });
    const data = await resp.json();
    if(!resp.ok && resp.status !== 202){
      cfg$('cfg-personalize-status').textContent = data.detail || data.error || `personalization failed (${resp.status})`;
      return;
    }
    cfgRenderPersonalization(data.personalization || {});
    cfg$('cfg-personalize-status').textContent = data.detail || 'Personalization started.';
    await cfgPollPersonalization();
  };
  cfg$('cfg-env-refresh').onclick = async () => {
    cfg$('cfg-env-refresh-status').textContent = 'Starting Data Domains refresh...';
    const resp = await fetch('/api/config/env-refresh', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({})
    });
    const data = await resp.json();
    if(!resp.ok && resp.status !== 202){
      cfg$('cfg-env-refresh-status').textContent = data.detail || data.error || `refresh failed (${resp.status})`;
      return;
    }
    cfgRenderEnvRefresh(data.refresh || {});
    cfg$('cfg-env-refresh-status').textContent = data.detail || 'Data Domains refresh started.';
    await cfgPollEnvRefresh();
  };
  cfg$('cfg-validate').onclick = cfgValidate;
  cfgLoad();
</script>
"""


def _users_page_body() -> str:
    return """
<div class="card">
  <style>
    .users-shell{display:grid;gap:16px;}
    .users-hero{border:1px solid #244660;border-radius:18px;background:linear-gradient(160deg,#08182a,#091726 52%,#0a1d17);padding:18px;}
    .users-hero h1{margin:0 0 8px;font-size:28px;line-height:1.05;}
    .users-hero p{margin:0;color:#a8c0d8;font-size:14px;line-height:1.65;}
    .users-grid{display:grid;grid-template-columns:minmax(340px,.95fr) minmax(420px,1.05fr);gap:16px;}
    .users-panel{border:1px solid #23445f;border-radius:18px;background:linear-gradient(180deg,#081525,#06111d);padding:18px;}
    .users-panel h2{margin:0 0 10px;font-size:18px;}
    .users-help{margin:0 0 12px;color:#9fb4cc;font-size:13px;line-height:1.55;}
    .users-form-grid{display:grid;grid-template-columns:1fr 180px;gap:12px;}
    .users-row{display:grid;gap:6px;}
    .users-row.wide{grid-column:1 / -1;}
    .users-row label{font-size:12px;color:#dbeafe;font-weight:800;text-transform:uppercase;letter-spacing:.08em;}
    .users-row input,.users-row select{width:100%;box-sizing:border-box;background:#040c18;color:#f8fafc;border:1px solid #33506a;border-radius:14px;padding:12px 14px;font-size:14px;outline:none;}
    .users-row input:focus,.users-row select:focus{border-color:#60a5fa;box-shadow:0 0 0 3px rgba(96,165,250,.15);}
    .users-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:14px;}
    .users-actions button{appearance:none;border:0;border-radius:14px;padding:12px 16px;background:linear-gradient(135deg,#22c55e,#16a34a);color:#03230f;font-weight:900;cursor:pointer;font-size:14px;}
    .users-actions .btn-secondary{background:linear-gradient(180deg,#16324a,#102435);color:#dbeafe;border:1px solid #315a79;}
    .users-status{color:#9fb4cc;font-size:13px;}
    .users-list{display:grid;gap:10px;}
    .users-item{border:1px solid #27415a;border-radius:12px;background:#081729;padding:12px;}
    .users-item-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:6px;}
    .users-item-name{font-weight:800;color:#f8fafc;}
    .users-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;border:1px solid #294560;background:#0b2130;color:#dbeafe;font-size:12px;font-weight:800;}
    .users-item-meta{color:#9fb4cc;font-size:12px;line-height:1.5;white-space:pre-wrap;}
    .users-item-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;}
    .users-item-btn{appearance:none;border:1px solid #315a79;border-radius:10px;padding:8px 10px;background:linear-gradient(180deg,#16324a,#102435);color:#dbeafe;font-weight:800;cursor:pointer;font-size:12px;letter-spacing:.02em;}
    .users-item-btn:hover{border-color:#60a5fa;transform:translateY(-1px);}
    .users-item-btn.danger{border-color:#6b2a2a;background:linear-gradient(180deg,#3f1518,#271013);color:#fecaca;}
    @media (max-width: 980px){.users-grid,.users-form-grid{grid-template-columns:1fr;}}
  </style>
  <div class="users-shell">
    <div class="users-hero">
      <h1>Users and Audit</h1>
      <p>Manage local Smith Console users and review which operator launched which investigation. First-run setup creates the initial admin user. New or updated passwords are stored as salted hashes.</p>
    </div>
    <div class="users-grid">
      <section class="users-panel">
        <h2>User Management</h2>
        <p class="users-help">This is local runtime user management for the web UI. It is intentionally simple and does not replace enterprise IAM.</p>
        <div id="users-list" class="users-list"><div class="users-item"><div class="users-item-meta">Loading users...</div></div></div>
        <div class="users-panel" style="margin-top:14px;padding:14px;background:#07121f;">
          <h2 style="font-size:16px;">Create or Update User</h2>
          <div class="users-form-grid">
            <div class="users-row"><label for="users-username">Username</label><input id="users-username" placeholder="analyst2" /></div>
            <div class="users-row"><label for="users-role">Role</label><select id="users-role"><option value="analyst">analyst</option><option value="ops">ops</option><option value="admin">admin</option></select></div>
            <div class="users-row wide"><label for="users-password">Password</label><input id="users-password" type="password" placeholder="Set a strong password" /></div>
          </div>
          <div class="users-actions">
            <button id="users-create">Create User</button>
            <button id="users-update" class="btn-secondary">Update User</button>
            <button id="users-delete" class="btn-secondary">Delete User</button>
            <span id="users-status" class="users-status">No changes submitted yet.</span>
          </div>
        </div>
      </section>
      <section class="users-panel">
        <h2>Recent Query Audit</h2>
        <p class="users-help">Recent investigations launched from the authenticated web UI. This is the local operator audit trail for `/api/ask` runs. Admin role required.</p>
        <div id="users-audit-path" class="users-help" style="margin-bottom:12px;">Loading audit log path...</div>
        <div id="users-audit-list" class="users-list"><div class="users-item"><div class="users-item-meta">No audit entries yet.</div></div></div>
      </section>
    </div>
  </div>
  <script>
    const users$ = (id) => document.getElementById(id);
    function usersEscape(v){ return String(v ?? ''); }
    function renderUsers(rows){
      const items = Array.isArray(rows) ? rows : [];
      users$('users-list').innerHTML = items.length ? items.map((user) => `
        <div class="users-item">
          <div class="users-item-head">
            <div class="users-item-name">${usersEscape(user.username || 'unknown')}</div>
            <span class="users-badge">role=${usersEscape(user.role || 'analyst')}</span>
          </div>
          <div class="users-item-meta">password=${usersEscape(user.password_kind || 'unknown')}</div>
          <div class="users-item-actions">
            <button class="users-item-btn" data-action="reset-password" data-username="${usersEscape(user.username || '')}">Reset Password</button>
            <button class="users-item-btn danger" data-action="delete-user" data-username="${usersEscape(user.username || '')}">Delete</button>
          </div>
        </div>
      `).join('') : '<div class="users-item"><div class="users-item-meta">No managed users found.</div></div>';
    }
    function renderAudit(audit){
      const recent = Array.isArray(audit?.recent) ? audit.recent : [];
      users$('users-audit-path').textContent = `Audit log: ${String(audit?.path || 'artifacts/audit/query_runs.jsonl')}`;
      users$('users-audit-list').innerHTML = recent.length ? recent.map((item) => `
        <div class="users-item">
          <div class="users-item-head">
            <div class="users-item-name">${usersEscape(item.username || 'unknown')} -> ${usersEscape(item.selected_tool || 'n/a')}</div>
            <span class="users-badge">rows=${usersEscape(item.rows_returned ?? 'n/a')}</span>
          </div>
          <div class="users-item-meta">${usersEscape(item.question || '')}</div>
          <div class="users-item-meta">${usersEscape(`pipeline=${item.pipeline || 'n/a'} | intent=${item.intent || 'n/a'}${item.query ? `\nquery=${item.query}` : ''}`)}</div>
        </div>
      `).join('') : '<div class="users-item"><div class="users-item-meta">No audit entries captured yet.</div></div>';
    }
    async function loadUsersPage(){
      const resp = await fetch('/api/config/users');
      const data = await resp.json();
      if(!resp.ok){
        users$('users-status').textContent = data.error || `load failed (${resp.status})`;
        return;
      }
      renderUsers(data.auth_users || []);
      try {
        const auditResp = await fetch('/api/config/audit');
        if(auditResp.ok){
          renderAudit(await auditResp.json());
        } else if (auditResp.status === 403) {
          users$('users-audit-path').textContent = 'Audit log: admin role required';
          users$('users-audit-list').innerHTML = '<div class="users-item"><div class="users-item-meta">Only admin can view the query audit trail.</div></div>';
        }
      } catch (_err) {
        users$('users-audit-list').innerHTML = '<div class="users-item"><div class="users-item-meta">Unable to load audit trail.</div></div>';
      }
    }
    async function submitUserAction(action){
      users$('users-status').textContent = 'Saving user change...';
      const resp = await fetch('/api/config/users', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({
          action,
          username: users$('users-username').value.trim(),
          role: users$('users-role').value.trim(),
          password: users$('users-password').value
        })
      });
      const data = await resp.json();
      if(!resp.ok){
        users$('users-status').textContent = data.error || `user action failed (${resp.status})`;
        return;
      }
      renderUsers(data.auth_users || []);
      users$('users-password').value = '';
      users$('users-status').textContent = `User action complete: ${action}.`;
      const auditResp = await fetch('/api/config/audit');
      if(auditResp.ok){
        renderAudit(await auditResp.json());
      } else if (auditResp.status === 403) {
        users$('users-audit-path').textContent = 'Audit log: admin role required';
      }
    }
    async function directUserAction(action, username){
      if(!username){ return; }
      if(action === 'delete-user'){
        if(!window.confirm(`Delete user "${username}"?`)){ return; }
        users$('users-status').textContent = `Deleting ${username}...`;
        const resp = await fetch('/api/config/users', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ action:'delete', username })
        });
        const data = await resp.json();
        if(!resp.ok){
          users$('users-status').textContent = data.error || `delete failed (${resp.status})`;
          return;
        }
        renderUsers(data.auth_users || []);
        users$('users-status').textContent = `Deleted user: ${username}.`;
        return;
      }
      if(action === 'reset-password'){
        const nextPassword = window.prompt(`Set a new password for "${username}" (minimum 12 characters):`, '');
        if(nextPassword === null){ return; }
        if(String(nextPassword).length < 12){
          users$('users-status').textContent = 'password must be at least 12 characters';
          return;
        }
        users$('users-status').textContent = `Resetting password for ${username}...`;
        const resp = await fetch('/api/config/users', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ action:'update', username, password: nextPassword })
        });
        const data = await resp.json();
        if(!resp.ok){
          users$('users-status').textContent = data.error || `password reset failed (${resp.status})`;
          return;
        }
        renderUsers(data.auth_users || []);
        users$('users-status').textContent = `Password reset for ${username}.`;
      }
    }
    users$('users-list').addEventListener('click', (event) => {
      const button = event.target.closest('[data-action][data-username]');
      if(!button){ return; }
      directUserAction(String(button.dataset.action || ''), String(button.dataset.username || ''));
    });
    users$('users-create').onclick = () => submitUserAction('create');
    users$('users-update').onclick = () => submitUserAction('update');
    users$('users-delete').onclick = () => submitUserAction('delete');
    loadUsersPage();
  </script>
</div>
"""


def _mcp_page_body() -> str:
    return """
<div class=\"card\">
  <style>
    .mcp-shell { display:grid; grid-template-columns: 1.05fr .95fr; gap:12px; }
    .mcp-pane {
      background: linear-gradient(170deg,#081a2c,#071321);
      border:1px solid #294560;
      border-radius: 14px;
      padding: 12px;
      box-shadow: inset 0 0 0 1px rgba(255,255,255,0.02);
    }
    .mcp-pane h2 { margin:0 0 8px; font-size:18px; }
    .mcp-sub { color:#abc1d7; font-size:12px; line-height:1.45; margin-bottom:8px; }
    .mcp-prompt {
      min-height: 170px;
      border:1px solid #3b5f7f;
      background:#051120;
      color:#e5e7eb;
      border-radius:10px;
      padding:12px;
      font-size:14px;
      line-height:1.45;
      resize:vertical;
      box-sizing:border-box;
      width:100%;
      font-family:"Trebuchet MS","Segoe UI","Helvetica Neue",Helvetica,sans-serif;
    }
    .mcp-actions { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-top:10px; }
    .mcp-send {
      margin-top:0;
      background:#22c55e;
      color:#04210e;
      border:0;
      border-radius:10px;
      font-weight:800;
      padding:11px 14px;
      cursor:pointer;
    }
    .mcp-status-pill {
      display:inline-block;
      border:1px solid #2d4f6c;
      border-radius:999px;
      padding:3px 10px;
      font-size:12px;
      color:#dbeafe;
      background:#0a2338;
    }
    .mcp-status-pill.ok { border-color:#166534; background:#052e16; color:#bbf7d0; }
    .mcp-status-pill.bad { border-color:#7f1d1d; background:#2a0d0d; color:#fecaca; }
    .mcp-progress {
      margin-top:10px;
      border:1px solid #2a4056;
      border-radius:10px;
      background:#07111f;
      padding:8px;
      display:none;
    }
    .mcp-progress-meta {
      display:flex; justify-content:space-between; gap:8px; align-items:center;
      font-size:12px; color:#c7d8eb; margin-bottom:6px;
    }
    .mcp-progress-track {
      width:100%; height:10px; border-radius:999px; border:1px solid #1f2937;
      background:#0b2130; overflow:hidden;
    }
    .mcp-progress-bar {
      width:0%; height:100%; border-radius:999px;
      background:linear-gradient(90deg,#22c55e,#10b981);
      transition:width .2s ease;
    }
    .mcp-chat {
      height: 410px;
      overflow:auto;
      white-space: pre-wrap;
      border-radius:10px;
      border:1px solid #26435c;
      background:#030b17;
      padding:10px;
      font-family:"Consolas","SFMono-Regular",Menlo,monospace;
      font-size:12.5px;
      line-height:1.45;
    }
    .mcp-metrics { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:8px; }
    .mcp-metric {
      border:1px solid #28445f;
      background:#071628;
      color:#d5e6f8;
      border-radius:999px;
      padding:4px 10px;
      font-size:12px;
      font-family:"Consolas","SFMono-Regular",Menlo,monospace;
    }
    .mcp-domain-box {
      border:1px solid #27415a;
      background:#061423;
      border-radius:10px;
      padding:8px;
      margin-top:8px;
    }
    .mcp-domain-item {
      border:1px solid #25435f;
      background:#0a1b2d;
      border-radius:8px;
      padding:6px 8px;
      margin-bottom:6px;
      font-size:12px;
    }
    .mcp-domain-item:last-child { margin-bottom:0; }
    .mcp-domain-item .idx {
      color:#93c5fd; font-weight:700;
      font-family:"Consolas","SFMono-Regular",Menlo,monospace;
    }
    @media (max-width: 1080px) { .mcp-shell { grid-template-columns: 1fr; } }
  </style>
  <h1>Splunk MCP Chat</h1>
  <p class=\"muted\">Ask a natural-language security question. The backend uses the same guarded multi-model + RAG + Data Domain context used by Investigation UI.</p>
  <div class=\"mcp-shell\">
    <div class=\"mcp-pane\">
      <h2>Prompt</h2>
      <div class=\"mcp-sub\">Single natural-language prompt input. No artifact controls.</div>
      <textarea id=\"mcp-question\" class=\"mcp-prompt\" placeholder=\"Example: Show failed Linux and Windows login activity in the last 24 hours, then summarize suspicious sources.\">Show failed login activity in the last 24 hours</textarea>
      <div class=\"mcp-actions\">
        <button id=\"mcp-send\" class=\"mcp-send\">Ask Splunk MCP</button>
        <span id=\"mcp-status-pill\" class=\"mcp-status-pill\">idle</span>
      </div>
      <div id=\"mcp-progress\" class=\"mcp-progress\">
        <div class=\"mcp-progress-meta\">
          <span id=\"mcp-progress-label\">Preparing MCP query...</span>
          <span id=\"mcp-progress-pct\">0%</span>
        </div>
        <div class=\"mcp-progress-track\"><div id=\"mcp-progress-bar\" class=\"mcp-progress-bar\"></div></div>
      </div>
      <p id=\"mcp-status\" class=\"muted\"></p>
      <div class=\"mcp-domain-box\">
        <div class=\"mcp-sub\" style=\"margin:0 0 6px;\">Data Domain Hints Used for Query Planning</div>
        <div id=\"mcp-domain-hints\" class=\"muted\">Run a question to view likely index/sourcetype targets.</div>
      </div>
    </div>
    <div class=\"mcp-pane\">
      <h2>Assistant Output</h2>
      <div class=\"mcp-sub\">Natural-language response plus execution telemetry from the guarded MCP flow.</div>
      <pre id=\"mcp-chat\" class=\"mcp-chat\"></pre>
    </div>
  </div>
  <h2>Execution Details</h2>
  <div class=\"mcp-metrics\">
    <span id=\"mcp-intent\" class=\"mcp-metric\">intent=n/a</span>
    <span id=\"mcp-tool\" class=\"mcp-metric\">tool=n/a</span>
    <span id=\"mcp-rows\" class=\"mcp-metric\">rows=0</span>
    <span id=\"mcp-writer\" class=\"mcp-metric\">writer_model=unknown</span>
    <span id=\"mcp-runtime\" class=\"mcp-metric\">spl_run_ms=unknown</span>
    <span id=\"mcp-rag\" class=\"mcp-metric\">rag=unknown</span>
  </div>
  <h3>SPL</h3>
  <pre id=\"mcp-spl\"></pre>
  <div><a id=\"mcp-spl-link\" href=\"#\" target=\"_blank\" rel=\"noopener noreferrer\" style=\"display:none; color:#93c5fd; text-decoration:none; font-size:13px;\">View in Splunk</a></div>
  <h3>Result Rows (sample)</h3>
  <pre id=\"mcp-results\"></pre>
  <details class=\"guided\" style=\"margin-top:12px;\">
    <summary>Show Raw JSON</summary>
    <pre id=\"mcp-json\"></pre>
  </details>
</div>
<script>
  const q = document.getElementById('mcp-question');
  const send = document.getElementById('mcp-send');
  const statusEl = document.getElementById('mcp-status');
  const chat = document.getElementById('mcp-chat');
  const intent = document.getElementById('mcp-intent');
  const tool = document.getElementById('mcp-tool');
  const rows = document.getElementById('mcp-rows');
  const writer = document.getElementById('mcp-writer');
  const runtime = document.getElementById('mcp-runtime');
  const rag = document.getElementById('mcp-rag');
  const statusPill = document.getElementById('mcp-status-pill');
  const spl = document.getElementById('mcp-spl');
  const splLink = document.getElementById('mcp-spl-link');
  const results = document.getElementById('mcp-results');
  const raw = document.getElementById('mcp-json');
  const domainHints = document.getElementById('mcp-domain-hints');
  const progressWrap = document.getElementById('mcp-progress');
  const progressBar = document.getElementById('mcp-progress-bar');
  const progressPct = document.getElementById('mcp-progress-pct');
  const progressLabel = document.getElementById('mcp-progress-label');
  let progressTimer = null;
  let progressValue = 0;

  function setStatus(label, cls='') {
    statusPill.textContent = label;
    statusPill.className = 'mcp-status-pill';
    if (cls) statusPill.classList.add(cls);
  }

  function appendChat(role, text) {
    const ts = new Date().toISOString();
    chat.textContent += `[${ts}] ${role}: ${text}\\n\\n`;
    chat.scrollTop = chat.scrollHeight;
  }

  function setProgress(v, label='') {
    progressValue = Math.max(0, Math.min(100, Number(v || 0)));
    progressWrap.style.display = 'block';
    progressBar.style.width = `${progressValue}%`;
    progressPct.textContent = `${Math.round(progressValue)}%`;
    if (label) progressLabel.textContent = label;
  }

  function startProgress() {
    if (progressTimer) clearInterval(progressTimer);
    setProgress(3, 'Planning guarded MCP query...');
    progressTimer = setInterval(() => {
      if (progressValue < 40) {
        setProgress(progressValue + 2.4, 'Applying RAG + Data Domain context...');
        return;
      }
      if (progressValue < 76) {
        setProgress(progressValue + 1.05, 'Executing Splunk MCP tool...');
        return;
      }
      if (progressValue < 93) {
        setProgress(progressValue + 0.42, 'Summarizing evidence...');
      }
    }, 350);
  }

  function stopProgress(ok) {
    if (progressTimer) {
      clearInterval(progressTimer);
      progressTimer = null;
    }
    setProgress(100, ok ? 'MCP query complete.' : 'MCP query failed.');
    setTimeout(() => { progressWrap.style.display = 'none'; }, 700);
  }

  send.onclick = async () => {
    const question = (q.value || '').trim();
    if (!question) return;
    send.disabled = true;
    setStatus('running');
    statusEl.textContent = 'Running MCP query...';
    startProgress();
    appendChat('You', question);
    try {
      const resp = await fetch('/api/mcp/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: question
        })
      });
      setProgress(95, 'Finalizing MCP output...');
      const data = await resp.json();
      if (!resp.ok) {
        statusEl.textContent = `error: ${data.error || `http_${resp.status}`}`;
        setStatus('error', 'bad');
        appendChat('System', statusEl.textContent);
        stopProgress(false);
        return;
      }
      setStatus('complete', 'ok');
      statusEl.textContent = 'Complete';
      appendChat('Assistant', data.summary || '(no summary)');
      intent.textContent = `intent=${data.intent || 'unknown'}`;
      tool.textContent = `tool=${data.selected_tool || 'n/a'}`;
      rows.textContent = `rows=${String(data.rows_returned ?? 0)} total=${String(data.total_rows ?? 0)}`;
      writer.textContent = `writer_model=${String(data.spl_writer_model || 'unknown')}`;
      runtime.textContent = `spl_run_ms=${String(data.spl_run_time_ms ?? 'unknown')}`;
      rag.textContent = `rag=${data.rag_enabled ? 'enabled' : 'disabled'} max_chars=${String(data.rag_max_chars ?? 'n/a')}`;
      const qArgs = data.query_args && typeof data.query_args === 'object' ? data.query_args : {};
      spl.textContent = qArgs.query || '(no splunk_run_query selected for this request)';
      if (qArgs.query) {
        const params = new URLSearchParams({
          q: String(qArgs.query),
          'display.page.search.mode': 'smart',
          'dispatch.sample_ratio': '1',
          workload_pool: '',
          earliest: String(qArgs.earliest_time || '-24h@h'),
          latest: String(qArgs.latest_time || 'now'),
          'display.page.search.tab': 'statistics',
          'display.general.type': 'statistics',
        });
        splLink.href = `http://174.175.242.244:8042/en-US/app/search/search?${params.toString()}`;
        splLink.style.display = 'inline';
      } else {
        splLink.href = '#';
        splLink.style.display = 'none';
      }
      const sample = Array.isArray(data.sample_rows) ? data.sample_rows : [];
      results.textContent = sample.length ? JSON.stringify(sample, null, 2) : '(no sample rows)';
      const hints = Array.isArray(data.domain_hints) ? data.domain_hints : [];
      if (!hints.length) {
        domainHints.innerHTML = '<div class=\"muted\">No strong domain hints were returned for this question.</div>';
      } else {
        domainHints.innerHTML = hints.slice(0, 4).map((h) => {
          const idx = String(h.index || '');
          const sts = Array.isArray(h.sourcetypes) ? h.sourcetypes : [];
          const why = Array.isArray(h.reasons) ? h.reasons.join('; ') : '';
          return (
            `<div class=\"mcp-domain-item\">` +
            `<div><span class=\"idx\">index=${idx}</span> <span class=\"badge\">score=${String(h.score ?? '')}</span></div>` +
            `<div class=\"muted\">sourcetypes: ${sts.join(', ')}</div>` +
            `<div class=\"muted\">why: ${why || 'keyword/domain match'}</div>` +
            `</div>`
          );
        }).join('');
      }
      raw.textContent = JSON.stringify(data, null, 2);
      stopProgress(true);
    } catch (err) {
      setStatus('error', 'bad');
      statusEl.textContent = `request failed: ${String(err)}`;
      appendChat('System', statusEl.textContent);
      stopProgress(false);
    } finally {
      send.disabled = false;
    }
  };
</script>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "SOCWebUI/0.3"

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(
        self,
        status: int,
        body_html: str,
        title: str = "A.G.E.N.T. Smith",
        nav_active: str = "docs",
        show_nav: bool = True,
    ) -> None:
        user = self._authenticated_user()
        body = DOCS_SHELL_HTML.format(
            title=html.escape(title),
            body=body_html,
            nav=_global_nav(nav_active) if show_nav else "",
            onboarding_user=html.escape(str((user or {}).get("username", ""))),
            onboarding_role=html.escape(str((user or {}).get("role", ""))),
            onboarding_modal=_admin_onboarding_modal(user),
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _session_token_from_cookie(self) -> str:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        try:
            cookie = SimpleCookie()
            cookie.load(raw)
            morsel = cookie.get(SESSION_COOKIE_NAME)
            return morsel.value if morsel else ""
        except Exception:
            return ""

    def _authenticated_user(self) -> dict[str, Any] | None:
        if not _auth_enabled():
            return {"username": "auth_disabled", "role": "admin"}
        token = self._session_token_from_cookie()
        return _get_session(token)

    def _set_session_cookie(self, token: str) -> None:
        self.send_header(
            "Set-Cookie",
            f"{SESSION_COOKIE_NAME}={token}; Max-Age={SESSION_TTL_SECONDS}; Path=/; HttpOnly; SameSite=Lax",
        )

    def _clear_session_cookie(self) -> None:
        self.send_header(
            "Set-Cookie",
            f"{SESSION_COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax",
        )

    def _redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        self.end_headers()

    def _require_auth(self, *, api_mode: bool = False) -> bool:
        if self._authenticated_user() is not None:
            return True
        if api_mode:
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized", "detail": "login required"})
            return False
        self._redirect("/login")
        return False

    def _login_page_body(self, error: str = "") -> str:
        error_html = ""
        if error:
            error_html = f"<div class=\"login-error\">{html.escape(error)}</div>"
        return (
            "<style>"
            ".login-shell{min-height:78vh;display:grid;place-items:center;padding:20px;}"
            ".login-card{width:min(520px,92vw);border:1px solid #284154;background:linear-gradient(165deg,#091727,#07111f);"
            "border-radius:18px;padding:22px;box-shadow:0 20px 44px rgba(0,0,0,.45);}"
            ".login-brand{display:flex;align-items:center;gap:10px;margin-bottom:8px;}"
            ".login-dot{width:11px;height:11px;border-radius:999px;background:#22c55e;box-shadow:0 0 14px rgba(34,197,94,.7);}"
            ".login-title{margin:0;font-size:27px;line-height:1.15;letter-spacing:.2px;}"
            ".login-sub{margin:4px 0 14px;color:#9fb4cc;font-size:13px;line-height:1.45;}"
            ".login-form label{display:block;font-size:13px;color:#d7e6f5;margin:10px 0 6px;}"
            ".login-form input{width:100%;box-sizing:border-box;background:#040c18;color:#e5e7eb;border:1px solid #33506a;"
            "border-radius:10px;padding:11px 12px;font-size:14px;outline:none;transition:border-color .15s ease;}"
            ".login-form input:focus{border-color:#58a6d9;}"
            ".login-error{margin:0 0 12px;padding:10px 12px;border-radius:10px;border:1px solid #7f1d1d;"
            "background:#2a0d0d;color:#fecaca;font-size:13px;}"
            ".login-actions{display:flex;gap:10px;align-items:center;margin-top:16px;}"
            ".login-btn{appearance:none;border:0;border-radius:10px;padding:11px 14px;background:#22c55e;color:#03230f;"
            "font-weight:800;cursor:pointer;font-size:14px;}"
            ".login-note{color:#9ca3af;font-size:12px;line-height:1.4;}"
            "</style>"
            "<div class=\"login-shell\">"
            "<div class=\"login-card\">"
            "<div class=\"login-brand\"><span class=\"login-dot\"></span><span class=\"badge\">Lab-Only</span></div>"
            "<h1 class=\"login-title\">SOC Analyst Console Login</h1>"
            "<p class=\"login-sub\">Authenticate to access investigation tools, docs, and Splunk-connected workflows on this LAN host.</p>"
            f"{error_html}"
            "<form class=\"login-form\" method=\"post\" action=\"/login\">"
            "<label>Username</label><input name=\"username\" autocomplete=\"username\" required />"
            "<label>Password</label><input type=\"password\" name=\"password\" autocomplete=\"current-password\" required />"
            "<div class=\"login-actions\">"
            "<button class=\"login-btn\" type=\"submit\">Sign In</button>"
            "<span class=\"login-note\">Session expires automatically for safety.</span>"
            "</div>"
            "</form>"
            "</div>"
            "</div>"
        )

    def _first_run_page_body(self, error: str = "") -> str:
        error_html = ""
        if error:
            error_html = f"<div class=\"login-error\">{html.escape(error)}</div>"
        return (
            "<style>"
            ".setup-shell{min-height:82vh;display:grid;place-items:center;padding:24px;}"
            ".setup-card{width:min(860px,96vw);display:grid;grid-template-columns:minmax(280px,.95fr) minmax(320px,1.05fr);gap:18px;"
            "border:1px solid #284154;background:linear-gradient(160deg,#081525,#07111f 52%,#0b1d17);border-radius:22px;padding:24px;"
            "box-shadow:0 24px 50px rgba(0,0,0,.46);}"
            ".setup-hero{padding:8px 6px 8px 0;}"
            ".setup-kicker{display:inline-flex;align-items:center;gap:8px;padding:6px 10px;border-radius:999px;border:1px solid #294560;background:#0b2130;color:#bde6ff;font-size:12px;font-weight:800;}"
            ".setup-title{margin:14px 0 8px;font-size:30px;line-height:1.05;letter-spacing:.2px;}"
            ".setup-copy{color:#a9bfd6;font-size:14px;line-height:1.65;margin:0 0 14px;}"
            ".setup-list{display:grid;gap:10px;margin-top:14px;}"
            ".setup-item{border:1px solid #203448;border-radius:14px;background:#091423;padding:12px 14px;}"
            ".setup-item strong{display:block;color:#f8fafc;font-size:13px;margin-bottom:4px;}"
            ".setup-item span{color:#b7cadc;font-size:13px;line-height:1.45;}"
            ".setup-form{border:1px solid #294560;border-radius:18px;background:rgba(5,16,29,.84);padding:18px;}"
            ".setup-form h2{margin:0 0 6px;font-size:20px;}"
            ".setup-form p{margin:0 0 12px;color:#9fb4cc;font-size:13px;line-height:1.55;}"
            ".setup-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}"
            ".setup-form label{display:block;font-size:12px;color:#dbeafe;margin:10px 0 6px;font-weight:800;text-transform:uppercase;letter-spacing:.08em;}"
            ".setup-form input,.setup-form select{width:100%;box-sizing:border-box;background:#040c18;color:#f8fafc;border:1px solid #33506a;border-radius:14px;"
            "padding:12px 14px;font-size:14px;outline:none;appearance:none;}"
            ".setup-form input:focus,.setup-form select:focus{border-color:#60a5fa;box-shadow:0 0 0 3px rgba(96,165,250,.15);}"
            ".setup-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:16px;}"
            ".setup-btn{appearance:none;border:0;border-radius:14px;padding:12px 16px;background:linear-gradient(135deg,#22c55e,#16a34a);color:#03230f;font-weight:900;cursor:pointer;font-size:14px;}"
            ".setup-note{color:#9ca3af;font-size:12px;line-height:1.45;}"
            "@media (max-width: 860px){.setup-card{grid-template-columns:1fr;}.setup-grid{grid-template-columns:1fr;}}"
            "</style>"
            "<div class=\"setup-shell\">"
            "<div class=\"setup-card\">"
            "<div class=\"setup-hero\">"
            "<div class=\"setup-kicker\">First-Run Setup</div>"
            "<h1 class=\"setup-title\">Finish securing A.G.E.N.T. Smith before first use</h1>"
            "<p class=\"setup-copy\">Set the first login, choose the operator role, and lock in credentials before the rest of the platform becomes available.</p>"
            "<div class=\"setup-list\">"
            "<div class=\"setup-item\"><strong>Why this appears</strong><span>A.G.E.N.T. Smith detected a fresh or placeholder UI auth configuration.</span></div>"
            "<div class=\"setup-item\"><strong>What this does</strong><span>Writes the initial local user into <code>config/ui.env</code>, stores a salted password hash, and marks the instance initialized.</span></div>"
            "<div class=\"setup-item\"><strong>What happens next</strong><span>After setup, sign in normally and continue to Configuration to validate Splunk, Ollama, and model assignments.</span></div>"
            "</div>"
            "</div>"
            "<div class=\"setup-form\">"
            "<h2>Create first login</h2>"
            "<p>Use a strong password. This is the credential that gates the web UI on your LAN.</p>"
            f"{error_html}"
            "<form method=\"post\" action=\"/setup/first-run\">"
            "<div class=\"setup-grid\">"
            "<div><label>Username</label><input name=\"username\" autocomplete=\"username\" required placeholder=\"analyst\" /></div>"
            "<div><label>Role</label><select name=\"role\"><option value=\"admin\">admin</option><option value=\"ops\">ops</option><option value=\"analyst\">analyst</option></select></div>"
            "</div>"
            "<label>Password</label><input type=\"password\" name=\"password\" autocomplete=\"new-password\" required minlength=\"12\" />"
            "<label>Confirm Password</label><input type=\"password\" name=\"confirm_password\" autocomplete=\"new-password\" required minlength=\"12\" />"
            "<div class=\"setup-actions\">"
            "<button class=\"setup-btn\" type=\"submit\">Save And Continue</button>"
            "<span class=\"setup-note\">You can change these later from Configuration after sign-in.</span>"
            "</div>"
            "</form>"
            "</div>"
            "</div>"
            "</div>"
        )

    def _handle_first_run_get(self) -> None:
        if not _first_run_setup_required():
            self._redirect("/login")
            return
        self._html(HTTPStatus.OK, self._first_run_page_body(), title="A.G.E.N.T. Smith First-Run Setup", show_nav=False)

    def _handle_first_run_post(self) -> None:
        if not _first_run_setup_required():
            self._redirect("/login")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(length)
        parsed = parse_qs(raw.decode("utf-8", errors="replace"))
        username = str((parsed.get("username", [""])[0] or "")).strip()
        role = str((parsed.get("role", ["admin"])[0] or "admin")).strip().lower()
        password = parsed.get("password", [""])[0] or ""
        confirm_password = parsed.get("confirm_password", [""])[0] or ""

        if not username:
            self._html(HTTPStatus.BAD_REQUEST, self._first_run_page_body("Username is required."), title="A.G.E.N.T. Smith First-Run Setup", show_nav=False)
            return
        if role not in ALLOWED_APP_ROLES:
            role = "admin"
        if len(password) < 12:
            self._html(HTTPStatus.BAD_REQUEST, self._first_run_page_body("Password must be at least 12 characters."), title="A.G.E.N.T. Smith First-Run Setup", show_nav=False)
            return
        if password != confirm_password:
            self._html(HTTPStatus.BAD_REQUEST, self._first_run_page_body("Password and confirmation do not match."), title="A.G.E.N.T. Smith First-Run Setup", show_nav=False)
            return
        if password in DEFAULT_UI_PASSWORDS:
            self._html(HTTPStatus.BAD_REQUEST, self._first_run_page_body("Choose a password that is not one of the default placeholders."), title="A.G.E.N.T. Smith First-Run Setup", show_nav=False)
            return

        hashed = _hash_password(password)
        write_env_file(
            {
                "SOC_UI_AUTH_ENABLED": "1",
                "SOC_UI_AUTH_USERNAME": username,
                "SOC_UI_AUTH_PASSWORD": hashed,
                "SOC_UI_AUTH_ROLE": role,
                "SOC_UI_AUTH_USERS_JSON": json.dumps([{"username": username, "password": hashed, "role": role}], separators=(",", ":")),
                "SOC_UI_AUTH_INITIALIZED": "1",
            },
            UI_ENV_PATH,
        )
        os.environ["SOC_UI_AUTH_ENABLED"] = "1"
        os.environ["SOC_UI_AUTH_USERNAME"] = username
        os.environ["SOC_UI_AUTH_PASSWORD"] = hashed
        os.environ["SOC_UI_AUTH_ROLE"] = role
        os.environ["SOC_UI_AUTH_USERS_JSON"] = json.dumps([{"username": username, "password": hashed, "role": role}], separators=(",", ":"))
        os.environ["SOC_UI_AUTH_INITIALIZED"] = "1"
        token = _create_session(username, role)
        self.send_response(HTTPStatus.FOUND)
        self._set_session_cookie(token)
        self.send_header("Location", "/configure")
        self.end_headers()

    def _handle_login_get(self) -> None:
        if not _auth_enabled():
            self._redirect("/")
            return
        if _first_run_setup_required():
            self._redirect("/setup/first-run")
            return
        if self._authenticated_user() is not None:
            self._redirect("/")
            return
        self._html(HTTPStatus.OK, self._login_page_body(), title="Smith Console Login", show_nav=False)

    def _handle_logout_get(self) -> None:
        token = self._session_token_from_cookie()
        _delete_session(token)
        self.send_response(HTTPStatus.FOUND)
        self._clear_session_cookie()
        self.send_header("Location", "/login")
        self.end_headers()

    def _handle_login_post(self) -> None:
        if not _auth_enabled():
            self._redirect("/")
            return
        if _first_run_setup_required():
            self._redirect("/setup/first-run")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(length)
        body = raw.decode("utf-8", errors="replace")
        parsed = parse_qs(body)
        username = (parsed.get("username", [""])[0] or "").strip()
        password = parsed.get("password", [""])[0] or ""

        users = _load_auth_users()
        user = users.get(username)
        if not user or not _password_matches(str(user.get("password", "")), password):
            self._html(
                HTTPStatus.UNAUTHORIZED,
                self._login_page_body("Invalid username or password."),
                title="Smith Console Login",
                show_nav=False,
            )
            return

        role = str(user.get("role", "analyst")).strip().lower()
        if role not in ALLOWED_APP_ROLES:
            role = "analyst"
        token = _create_session(username, role)
        self.send_response(HTTPStatus.FOUND)
        self._set_session_cookie(token)
        self.send_header("Location", "/")
        self.end_headers()

    def _ops_role(self, parsed_query: dict[str, list[str]]) -> str:
        user = self._authenticated_user()
        if user is not None:
            return str(user.get("role", "")).strip().lower()
        # Fallback path (expected only when auth is disabled).
        query_role = (parsed_query.get("role", [""])[0] or "").strip().lower()
        header_role = (
            self.headers.get("X-User-Role")
            or self.headers.get("X-Role")
            or self.headers.get("X-Lab-Role")
            or ""
        ).strip().lower()
        return query_role or header_role

    def _require_ops_role(self, parsed_query: dict[str, list[str]]) -> bool:
        role = self._ops_role(parsed_query)
        if role_allowed(role):
            return True
        self._json(
            403,
            {
                "error": "forbidden",
                "detail": "ops/admin role required",
            },
        )
        return False

    def _require_ops_page(self) -> bool:
        role = self._ops_role({})
        if role_allowed(role):
            return True
        self._html(
            HTTPStatus.FORBIDDEN,
            "<div class=\"card\"><h1>Configuration</h1><p class=\"muted\">ops/admin role required.</p></div>",
            title="Configuration",
            nav_active="configure",
        )
        return False

    def _require_admin_role(self, parsed_query: dict[str, list[str]]) -> bool:
        role = self._ops_role(parsed_query)
        if role == "admin":
            return True
        self._json(
            403,
            {
                "error": "forbidden",
                "detail": "admin role required",
            },
        )
        return False

    def _require_admin_page(self) -> bool:
        role = self._ops_role({})
        if role == "admin":
            return True
        self._html(
            HTTPStatus.FORBIDDEN,
            "<div class=\"card\"><h1>Users</h1><p class=\"muted\">admin role required.</p></div>",
            title="Users",
            nav_active="control",
        )
        return False

    def _api_config_runtime_get(self) -> None:
        if not self._require_ops_role({}):
            return
        self._json(HTTPStatus.OK, _config_snapshot())

    def _api_config_validate_post(self) -> None:
        if not self._require_ops_role({}):
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode("utf-8")) if raw else {}
        values = payload.get("values", {}) if isinstance(payload, dict) else {}
        if not isinstance(values, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "values must be an object"})
            return
        merged = _config_snapshot().get("values", {})
        if isinstance(merged, dict):
            merged.update({key: str(value).strip() for key, value in values.items()})
        validation = _validate_runtime_config(merged)
        validation["environment_profile_status"] = _maybe_trigger_environment_profile_bootstrap(validation)
        self._json(HTTPStatus.OK, validation)

    def _api_config_runtime_post(self) -> None:
        if not self._require_ops_role({}):
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode("utf-8")) if raw else {}
        values = payload.get("values", {}) if isinstance(payload, dict) else {}
        if not isinstance(values, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "values must be an object"})
            return
        updates = {
            key: str(values.get(key, "")).strip()
            for key in CONFIG_EDITABLE_KEYS
            if key in values
        }
        ollama_host = str(updates.get("OLLAMA_HOST", "")).strip().rstrip("/") or get_ollama_host()
        available_models = _discover_ollama_models(ollama_host)
        updates = _autofill_model_assignments(updates, available_models)
        write_env_file(updates, UI_ENV_PATH)
        snapshot = _config_snapshot()
        validation = _validate_runtime_config(snapshot.get("values", {}) if isinstance(snapshot.get("values", {}), dict) else {})
        snapshot["environment_profile_status"] = _maybe_trigger_environment_profile_bootstrap(validation)
        self._json(HTTPStatus.OK, snapshot)

    def _api_config_users_get(self) -> None:
        if not self._require_admin_role({}):
            return
        self._json(HTTPStatus.OK, _users_snapshot())

    def _api_config_users_post(self) -> None:
        if not self._require_admin_role({}):
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode("utf-8")) if raw else {}
        if not isinstance(payload, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "payload must be an object"})
            return
        action = str(payload.get("action", "")).strip().lower()
        username = str(payload.get("username", "")).strip()
        role = str(payload.get("role", "analyst")).strip().lower()
        password = str(payload.get("password", ""))
        current_user = self._authenticated_user() or {}
        current_username = str(current_user.get("username", "")).strip()

        users = _load_auth_users()
        if action == "create":
            if not username:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "username is required"})
                return
            if username in users:
                self._json(HTTPStatus.CONFLICT, {"error": "user already exists"})
                return
            if role not in ALLOWED_APP_ROLES:
                role = "analyst"
            if len(password) < 12:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "password must be at least 12 characters"})
                return
            users[username] = {"password": _hash_password(password), "role": role}
        elif action == "update":
            if not username or username not in users:
                self._json(HTTPStatus.NOT_FOUND, {"error": "user not found"})
                return
            if role in ALLOWED_APP_ROLES:
                users[username]["role"] = role
            if password:
                if len(password) < 12:
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "password must be at least 12 characters"})
                    return
                users[username]["password"] = _hash_password(password)
        elif action == "delete":
            if not username or username not in users:
                self._json(HTTPStatus.NOT_FOUND, {"error": "user not found"})
                return
            if username == current_username:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "cannot delete the currently signed-in user"})
                return
            if len(users) <= 1:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "at least one user must remain"})
                return
            users.pop(username, None)
        else:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "unsupported action"})
            return

        _persist_auth_users(users)
        self._json(HTTPStatus.OK, {"status": "ok", **_users_snapshot()})

    def _api_query_audit_get(self) -> None:
        if not self._require_admin_role({}):
            return
        self._json(
            HTTPStatus.OK,
            {
                "path": display_path(QUERY_AUDIT_LOG),
                "recent": _recent_query_audit(50),
            },
        )

    def _api_session_onboarding_post(self) -> None:
        user = self._authenticated_user()
        if not isinstance(user, dict):
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        if str(user.get("role", "")).strip().lower() != "admin":
            self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden", "detail": "admin role required"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode("utf-8")) if raw else {}
        if not isinstance(payload, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "payload must be an object"})
            return
        action = str(payload.get("action", "")).strip().lower()
        if action not in {"skip"}:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "unsupported action"})
            return
        token = self._session_token_from_cookie()
        if not _set_session_admin_onboarding_skip(token, True):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "session not found"})
            return
        self._json(HTTPStatus.OK, {"status": "ok", "action": action})

    def _api_config_personalize_post(self) -> None:
        if not self._require_ops_role({}):
            return
        if _personalization_in_progress():
            self._json(
                HTTPStatus.ACCEPTED,
                {
                    "status": "in_progress",
                    "detail": "Personalization build is already running.",
                    "personalization": _personalization_status(),
                },
            )
            return
        if not _environment_profile_exists():
            self._json(
                HTTPStatus.PRECONDITION_FAILED,
                {
                    "error": "environment_profile_missing",
                    "detail": "Build Data Domains first by validating Splunk MCP and waiting for the environment profile to finish.",
                    "environment_profile_status": _environment_profile_bootstrap_state(),
                },
            )
            return
        threading.Thread(target=_run_personalization_refresh, daemon=True).start()
        self._json(
            HTTPStatus.ACCEPTED,
            {
                "status": "started",
                "detail": "Environment-aware SPL personalization build started.",
                "personalization": {
                    "state": "in_progress",
                    "detail": "Environment-aware SPL personalization build is running.",
                    "path": display_path(SPL_SKILLPACK_PATH),
                },
            },
        )

    def _api_config_personalize_get(self) -> None:
        if not self._require_ops_role({}):
            return
        self._json(HTTPStatus.OK, {"personalization": _personalization_status()})

    def _api_config_env_refresh_get(self) -> None:
        if not self._require_ops_role({}):
            return
        self._json(HTTPStatus.OK, {"refresh": _environment_profile_refresh_status()})

    def _api_config_env_refresh_post(self) -> None:
        if not self._require_ops_role({}):
            return
        if _environment_profile_refresh_in_progress():
            self._json(
                HTTPStatus.ACCEPTED,
                {
                    "status": "in_progress",
                    "detail": "Environment profile refresh is already running.",
                    "refresh": _environment_profile_refresh_status(),
                },
            )
            return
        threading.Thread(target=_run_environment_profile_refresh, daemon=True).start()
        self._json(
            HTTPStatus.ACCEPTED,
            {
                "status": "started",
                "detail": "Environment profile refresh started.",
                "refresh": _environment_profile_refresh_status(),
            },
        )

    def _stream_ollama_logs(self, parsed: Any) -> None:
        query = parse_qs(parsed.query)
        if not self._require_ops_role(query):
            return

        config = _remote_log_config_status()
        if config["mode"] != "remote_windows":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(
                format_sse(
                    "error",
                    {
                        "type": "error",
                        "code": "source_disabled",
                        "message": "OLLAMA_LOG_SOURCE is not set to remote_windows",
                        "ts": "now",
                    },
                )
            )
            self.wfile.flush()
            return

        params = StreamParams.from_values(
            query.get("tail", ["200"])[0],
            query.get("level", [""])[0],
            query.get("grep", [""])[0],
        )

        source = LOG_SOURCE_REGISTRY.get_source(params)
        if not config["config_ok"]:
            missing = ", ".join(config["missing_vars"])
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(
                format_sse(
                    "error",
                    {
                        "type": "error",
                        "code": "missing_config",
                        "message": f"Set required server env vars for remote_windows: {missing}",
                        "ts": "now",
                        "missing_vars": config["missing_vars"],
                    },
                )
            )
            self.wfile.flush()
            return

        remote_url = os.getenv("OLLAMA_LOG_REMOTE_URL", "").strip()
        remote_token = os.getenv("OLLAMA_LOG_REMOTE_TOKEN", "").strip()
        health_url = get_remote_health_url(remote_url)
        health_ok, health_detail = check_remote_health(health_url, remote_token, timeout=4.0)

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        sid, sub_q = source.subscribe()
        try:
            if health_ok:
                self.wfile.write(format_sse("status", {"type": "status", "state": "connected", "detail": "health_ok"}))
            else:
                self.wfile.write(
                    format_sse(
                        "error",
                        {
                            "type": "error",
                            "code": "remote_health_check_failed",
                            "message": redact_secrets(health_detail),
                            "ts": "now",
                        },
                    )
                )
                self.wfile.write(
                    format_sse(
                        "status",
                        {"type": "status", "state": "reconnecting", "detail": "waiting_for_remote_source"},
                    )
                )
            self.wfile.flush()

            replay_count = min(200, params.tail)
            for entry in source.get_recent(replay_count):
                payload = dict(entry)
                payload["line"] = redact_secrets(str(payload.get("line", "")))
                self.wfile.write(format_sse("log", payload))
            self.wfile.flush()

            while True:
                try:
                    event = sub_q.get(timeout=15.0)
                except queue.Empty:
                    self.wfile.write(b": heartbeat\\n\\n")
                    self.wfile.flush()
                    continue

                event_type = str(event.get("type", "log"))
                payload = dict(event)
                if "line" in payload:
                    payload["line"] = redact_secrets(str(payload.get("line", "")))
                self.wfile.write(format_sse(event_type, payload))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            source.unsubscribe(sid)

    def _ops_ollama_logs_health(self, parsed: Any) -> None:
        query = parse_qs(parsed.query)
        if not self._require_ops_role(query):
            return

        config = _remote_log_config_status()
        remote_health_ok = False
        remote_health_detail = "remote health check skipped"
        if config["mode"] == "remote_windows" and config["config_ok"]:
            remote_url = os.getenv("OLLAMA_LOG_REMOTE_URL", "").strip()
            remote_token = os.getenv("OLLAMA_LOG_REMOTE_TOKEN", "").strip()
            health_url = get_remote_health_url(remote_url)
            remote_health_ok, remote_health_detail = check_remote_health(health_url, remote_token, timeout=4.0)
            remote_health_detail = redact_secrets(remote_health_detail)

        status_code = 200 if (config["config_ok"] and (config["mode"] != "remote_windows" or remote_health_ok)) else 503
        self._json(
            status_code,
            {
                "mode": config["mode"],
                "config_ok": config["config_ok"],
                "missing_vars": config["missing_vars"],
                "required_vars": config["required_vars"],
                "remote_health_ok": remote_health_ok,
                "remote_health_detail": remote_health_detail,
            },
        )

    def _api_environment_profile(self) -> None:
        payload = _load_environment_profile_payload()
        if not payload:
            self._json(
                HTTPStatus.NOT_FOUND,
                {
                    "error": "environment_profile_missing",
                    "path": str(ENV_PROFILE_PATH),
                    "hint": "Run make env-profile-refresh",
                },
            )
            return
        self._json(HTTPStatus.OK, payload)

    def _api_environment_hint(self, parsed: Any) -> None:
        query = parse_qs(parsed.query)
        question = str(query.get("question", [""])[0]).strip()
        if not question:
            self._json(HTTPStatus.OK, {"hints": [], "question": ""})
            return
        hints = suggest_domains_for_question(question)
        self._json(
            HTTPStatus.OK,
            {
                "question": question,
                "hints": hints,
                "profile_path": str(ENV_PROFILE_PATH),
            },
        )

    def _api_mcp_chat(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        data = json.loads(raw.decode("utf-8")) if raw else {}
        question = str(data.get("message", "")).strip()
        if not question:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "message is required"})
            return

        session_id = str(data.get("session_id", "")).strip()
        # MCP chat is intentionally non-artifact mode: interactive ask/answer only.
        payload = run_multi_model_soc(question, session_id=session_id, write_artifact=False)
        result = payload.get("result", {}) if isinstance(payload, dict) else {}
        if not isinstance(result, dict):
            result = {}
        result_compact = dict(result)
        result_compact.pop("tdir_case", None)

        selected_tool = str(result.get("selected_tool", "")).strip()
        query_args = result.get("query_args", {}) if isinstance(result.get("query_args"), dict) else {}
        selected_spl_details = result.get("selected_spl_details", [])
        if not isinstance(selected_spl_details, list):
            selected_spl_details = []
        latest_spl = selected_spl_details[-1] if selected_spl_details and isinstance(selected_spl_details[-1], dict) else {}
        spl_writer_model = str(latest_spl.get("writer_model", "")).strip() or "unknown"
        spl_run_time_ms = latest_spl.get("execution_ms", None)
        if spl_run_time_ms is None:
            spl_run_time_ms = result.get("node_timings_ms", {}).get("run_tool") if isinstance(result.get("node_timings_ms"), dict) else None
        sample_rows: list[dict[str, Any]] = []
        sample_source = "none"
        sample_error = ""
        if selected_tool == "splunk_run_query" and str(query_args.get("query", "")).strip():
            rerun_args = dict(query_args)
            try:
                row_limit = int(rerun_args.get("row_limit", 25))
            except Exception:
                row_limit = 25
            rerun_args["row_limit"] = max(1, min(50, row_limit))
            try:
                rerun = run_splunk_query_args(
                    rerun_args,
                    intent=str(result.get("intent", "mcp_chat")).strip() or "mcp_chat",
                    summary_hint="mcp chat sample rows",
                )
                rows = rerun.get("structured", {}).get("results", []) if isinstance(rerun, dict) else []
                if isinstance(rows, list):
                    sample_rows = [r for r in rows if isinstance(r, dict)][:25]
                    sample_source = "splunk_run_query_rerun"
            except Exception as exc:
                sample_error = f"{type(exc).__name__}: {exc}"

        if not sample_rows:
            evidence = result.get("evidence", {}) if isinstance(result.get("evidence"), dict) else {}
            top = evidence.get("top_entities", []) if isinstance(evidence.get("top_entities"), list) else []
            sample_rows = [r for r in top if isinstance(r, dict)]
            if sample_rows:
                sample_source = "pipeline_evidence_top_entities"
        domain_hints = suggest_domains_for_question(question, max_indexes=4, max_sourcetypes_per_index=4)

        self._json(
            HTTPStatus.OK,
            {
                "question": question,
                "summary": str(result.get("summary", "")),
                "intent": result.get("intent"),
                "supported": result.get("supported"),
                "selected_tool": selected_tool,
                "query_args": query_args,
                "rows_returned": result.get("rows_returned"),
                "total_rows": result.get("total_rows"),
                "spl_writer_model": spl_writer_model,
                "spl_run_time_ms": spl_run_time_ms,
                "rag_enabled": bool(result.get("rag_enabled", False)),
                "rag_max_chars": result.get("rag_max_chars"),
                "domain_hints": domain_hints,
                "sample_rows": sample_rows,
                "sample_rows_source": sample_source,
                "sample_rows_error": sample_error,
                "selected_spl_details": selected_spl_details,
                "result": result_compact,
                "meta": payload.get("meta", {}) if isinstance(payload, dict) else {},
            },
        )

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path in {"/favicon.ico", "/favicon.svg"}:
            body = FAVICON_SVG.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/login":
            self._handle_login_get()
            return
        if parsed.path == "/setup/first-run":
            self._handle_first_run_get()
            return
        if parsed.path == "/logout":
            self._handle_logout_get()
            return

        if _first_run_setup_required():
            self._redirect("/setup/first-run")
            return

        if parsed.path.startswith("/api/"):
            if not self._require_auth(api_mode=True):
                return
        else:
            if not self._require_auth(api_mode=False):
                return

        if parsed.path == "/api/ops/ollama/logs/stream":
            self._stream_ollama_logs(parsed)
            return
        if parsed.path == "/api/ops/ollama/logs/health":
            self._ops_ollama_logs_health(parsed)
            return
        if parsed.path == "/api/environment/profile":
            self._api_environment_profile()
            return
        if parsed.path == "/api/environment/hint":
            self._api_environment_hint(parsed)
            return
        if parsed.path == "/api/config/runtime":
            self._api_config_runtime_get()
            return
        if parsed.path == "/api/config/users":
            self._api_config_users_get()
            return
        if parsed.path == "/api/config/audit":
            self._api_query_audit_get()
            return
        if parsed.path == "/api/session/onboarding":
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED, "POST required")
            return
        if parsed.path == "/api/config/env-refresh":
            self._api_config_env_refresh_get()
            return
        if parsed.path == "/api/config/personalize":
            self._api_config_personalize_get()
            return
        if parsed.path == "/api/config/validate":
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED, "POST required")
            return

        if parsed.path == "/":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/mcp")
            self.end_headers()
            return

        if parsed.path == "/investigation":
            body = APP_HTML.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/docs":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/docs/view?path=whitepapers/project_one_page_white_paper.md")
            self.end_headers()
            return

        if parsed.path == "/docs/index":
            self._html(HTTPStatus.OK, _docs_index_body(), title="Documentation Portal", nav_active="control")
            return

        if parsed.path == "/docs/view":
            path_value = parse_qs(parsed.query).get("path", [""])[0]
            self._html(HTTPStatus.OK, _docs_view_body(path_value), title="Documentation Viewer", nav_active="control")
            return

        if parsed.path == "/docs/raw":
            path_value = parse_qs(parsed.query).get("path", [""])[0]
            doc_path = _safe_docs_path(path_value)
            if doc_path is None:
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            body = doc_path.read_bytes()
            ctype = "text/plain; charset=utf-8"
            if doc_path.suffix.lower() == ".json":
                ctype = "application/json; charset=utf-8"
            elif doc_path.suffix.lower() == ".csv":
                ctype = "text/csv; charset=utf-8"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/favicon-preview":
            self._html(HTTPStatus.OK, _favicon_preview_body(), title="A.G.E.N.T. Smith Favicon Preview", nav_active="control")
            return

        if parsed.path == "/artifacts/raw":
            path_value = parse_qs(parsed.query).get("path", [""])[0]
            rel = Path(path_value)
            target = (ARTIFACTS_ROOT / rel).resolve()
            try:
                target.relative_to(ARTIFACTS_ROOT.resolve())
            except Exception:
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            if not target.exists() or not target.is_file():
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            body = target.read_bytes()
            ctype = "text/plain; charset=utf-8"
            if target.suffix.lower() == ".json":
                ctype = "application/json; charset=utf-8"
            elif target.suffix.lower() == ".csv":
                ctype = "text/csv; charset=utf-8"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/architecture":
            self._html(HTTPStatus.OK, _architecture_page_body(), title="Architecture Graph", nav_active="control")
            return

        if parsed.path == "/langgraph-graph":
            self._html(HTTPStatus.OK, _langgraph_graph_page_body(), title="LangGraph Graph", nav_active="control")
            return

        if parsed.path == "/artifacts":
            self._html(HTTPStatus.OK, _artifacts_page_body(), title="Artifact Repository", nav_active="artifacts")
            return

        if parsed.path == "/environment":
            if _running_in_container() and not _can_show_environment_page():
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/configure")
                self.end_headers()
                return
            self._html(HTTPStatus.OK, _environment_page_body(), title="Data Domains", nav_active="environment")
            return

        if parsed.path == "/configure":
            if not self._require_ops_page():
                return
            self._html(HTTPStatus.OK, _configure_page_body(), title="Configuration", nav_active="control")
            return

        if parsed.path == "/users":
            if not self._require_admin_page():
                return
            self._html(HTTPStatus.OK, _users_page_body(), title="Users", nav_active="control")
            return

        if parsed.path == "/mcp":
            self._html(HTTPStatus.OK, _mcp_page_body(), title="Splunk MCP Chat", nav_active="mcp")
            return

        if parsed.path == "/docs/architecture":
            self.send_response(HTTPStatus.MOVED_PERMANENTLY)
            self.send_header("Location", "/architecture")
            self.end_headers()
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            self._handle_login_post()
            return
        if parsed.path == "/setup/first-run":
            self._handle_first_run_post()
            return

        if _first_run_setup_required():
            self._json(HTTPStatus.PRECONDITION_FAILED, {"error": "first_run_setup_required", "redirect": "/setup/first-run"})
            return

        if parsed.path == "/api/mcp/chat":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_mcp_chat()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return
        if parsed.path == "/api/config/runtime":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_config_runtime_post()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return
        if parsed.path == "/api/config/users":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_config_users_post()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return
        if parsed.path == "/api/config/validate":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_config_validate_post()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return
        if parsed.path == "/api/config/personalize":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_config_personalize_post()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return
        if parsed.path == "/api/config/env-refresh":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_config_env_refresh_post()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return
        if parsed.path == "/api/session/onboarding":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_session_onboarding_post()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return

        if parsed.path != "/api/ask":
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return
        if not self._require_auth(api_mode=True):
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        try:
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8")) if raw else {}
            question = str(data.get("question", "")).strip()
            if not question:
                self._json(400, {"error": "question is required"})
                return
            session_id = str(data.get("session_id", "")).strip()
            max_steps = data.get("max_steps", 3)
            if not isinstance(max_steps, int):
                try:
                    max_steps = int(max_steps)
                except Exception:
                    max_steps = 3
            write_artifact = bool(data.get("write_artifact", True))
            approved_deeper_investigation = bool(data.get("approved_deeper_investigation", False))
            continuation_state = data.get("continuation_state", None)

            pipeline = str(data.get("pipeline", "multi_model")).strip().lower()
            if pipeline == "agentic":
                result = run_agentic_investigation(
                    question,
                    max_steps=max_steps,
                    session_id=session_id,
                    write_artifact=write_artifact,
                    approved_deeper_investigation=approved_deeper_investigation,
                    continuation_state=continuation_state if isinstance(continuation_state, dict) else None,
                )
            else:
                result = run_multi_model_soc(
                    question,
                    session_id=session_id,
                    write_artifact=write_artifact,
                )
            user = self._authenticated_user() or {}
            selected_tool = str(result.get("selected_tool", "")).strip()
            selected_spl_details = result.get("selected_spl_details", [])
            if not isinstance(selected_spl_details, list):
                selected_spl_details = []
            latest_spl = selected_spl_details[-1] if selected_spl_details and isinstance(selected_spl_details[-1], dict) else {}
            executed_query = ""
            query_args = result.get("query_args", {}) if isinstance(result.get("query_args"), dict) else {}
            if str(latest_spl.get("query", "")).strip():
                executed_query = str(latest_spl.get("query", "")).strip()
            elif str(query_args.get("query", "")).strip():
                executed_query = str(query_args.get("query", "")).strip()
            _append_query_audit(
                {
                    "ts_epoch": int(time.time()),
                    "username": str(user.get("username", "unknown")),
                    "role": str(user.get("role", "unknown")),
                    "pipeline": pipeline,
                    "question": question,
                    "selected_tool": selected_tool,
                    "intent": result.get("intent"),
                    "rows_returned": result.get("rows_returned"),
                    "total_rows": result.get("total_rows"),
                    "query": executed_query,
                    "session_id": session_id,
                }
            )
            self._json(200, result)
        except Exception as exc:
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local SOC web UI server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()

    if _auth_enabled():
        users = _load_auth_users()
        if not users:
            print("Startup validation failed for UI auth.")
            print("No auth users configured. Set SOC_UI_AUTH_USERS_JSON or SOC_UI_AUTH_USERNAME/SOC_UI_AUTH_PASSWORD.")
            return 2
        if "analyst" in users and users["analyst"].get("password") == "changeme123!":
            print("WARNING: default UI auth credential detected (analyst/changeme123!). Change it in config/ui.env.")

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Web UI running at http://{args.host}:{args.port}")
    print(f"UI auth enabled: {_auth_enabled()}")
    print("Default landing: /mcp")
    print("Investigation UI: /investigation")
    print("Docs portal: /docs")
    print("Architecture graph: /architecture")
    print("Splunk MCP chat: /mcp")
    print("Artifact repository: /artifacts")
    print("Press Ctrl+C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
