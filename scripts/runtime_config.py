#!/usr/bin/env python3
"""Shared runtime configuration helpers for A.G.E.N.T. Smith."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"
DEFAULT_SPLUNK_MCP_URL = "https://127.0.0.1:8089/services/mcp"
DEFAULT_SPLUNK_BASE_URL = "https://127.0.0.1:8089"
DEFAULT_EDGE_LLM_ROLE = "edge_router_splitter"
DEFAULT_EDGE_LLM_TIMEOUT_SEC = "60"
# Google/US, ~815MB, non-Chinese by design (matches the v1.5.x US-primary
# stack rationale in docs/model_strategy.md). Right-sized for a
# classification-only task -- turns a raw question into a small structured
# hint (platform/activity/data_category/entities/time_hint) consumed by
# resolve_authoritative_domains_for_question's embedding retrieval blend.
DEFAULT_EDGE_LLM_MODEL = "gemma3:1b"
DEFAULT_SOC_UI_SESSION_TIMEOUT_MIN = "60"
DEFAULT_SOC_UI_SESSION_REMEMBER_TIMEOUT_MIN = "480"
DEFAULT_OLLAMA_KEEP_ALIVE = "0"
DEFAULT_OLLAMA_WARM_KEEP_ALIVE = "30m"
LOCAL_OLLAMA_HOSTNAMES: frozenset[str] = frozenset(
    {
        "127.0.0.1",
        "localhost",
        "::1",
        "host.docker.internal",
        "ollama",
    }
)

# Data Domains (environment profile) auto-refresh scheduler. Checked on by
# default at first-run configuration time so the profile self-heals without
# an operator remembering to click "Refresh Data Domains" manually.
DEFAULT_ENV_PROFILE_AUTO_REFRESH_ENABLED = "1"
DEFAULT_ENV_PROFILE_REFRESH_INTERVAL_MINUTES = "60"
ENV_PROFILE_AUTO_REFRESH_INTERVAL_CHOICES_MINUTES = (60, 240, 1440)

# Wide, wildcard `index=*` searches over broad windows (a month, a quarter, a
# year -- see question_intelligence.infer_time_window) legitimately scan far
# more data than the narrow 24h/7d windows this budget was originally tuned
# for. 90s was already tight for a 7-day full-index scan on a moderately
# sized lab; a shorter total MCP budget than the search itself needs simply
# converts "answer took a while" into "guardrail-shaped timeout error" for
# exactly the broader-window questions this time-window fix now honors
# correctly. 240s keeps ad hoc UI queries from hanging forever while giving
# multi-week/month scans realistic room to finish.
DEFAULT_MCP_REQUEST_TIMEOUT_SEC = "240"
DEFAULT_OLLAMA_REQUEST_TIMEOUT_SEC = "180"

# v1.5.x stack — split planner / writer (2026-07-23 bake-off on RTX 1000 Ada).
# Bake-off winner (artifact): HF EnlistedGhost Ministral-3B-Reasoning Q5_K_M (59.68 avg).
# Production default: TechyShishy Ministral-3B-Reasoning Q4_K_M — same model family; EnlistedGhost GGUF crashes Ollama here.
DEFAULT_MODEL_QUERY_PLANNER = "TechyShishy/ministral-3:3b-reasoning-2512-q4_K_M"
PLANNER_BAKEOFF_WINNER_ARTIFACT = "hf.co/EnlistedGhost/Ministral-3-3B-Reasoning-2512-GGUF:Q5_K_M"
DEFAULT_MODEL_QUERY_PLANNER_FALLBACK = "ministral-3:3b"
DEFAULT_MODEL_QUERY_WRITER = "granite4:3b"
DEFAULT_MODEL_US_PEER = "gemma3:4b"
DEFAULT_MODEL_REASONING = "hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
DEFAULT_MODEL_SECURITY_REVIEWER = DEFAULT_MODEL_REASONING
DEFAULT_MODEL_EVIDENCE_REVIEWER = DEFAULT_MODEL_REASONING
DEFAULT_MODEL_ANALYST_REVIEWER = DEFAULT_MODEL_QUERY_PLANNER
DEFAULT_MODEL_PEER_REVIEWER = DEFAULT_MODEL_US_PEER
DEFAULT_MODEL_PEER_REVIEWER_2 = DEFAULT_MODEL_US_PEER
DEFAULT_MODEL_AGENTIC_CONTINUATION_REVIEWER = DEFAULT_MODEL_REASONING
DEFAULT_MODEL_FINAL_SUMMARY = DEFAULT_MODEL_REASONING
DEFAULT_MODEL_QUERY_REPAIR = DEFAULT_MODEL_QUERY_WRITER

MODEL_ASSIGNMENT_KEYS = [
    "OLLAMA_MODEL_QUERY_PLANNER",
    "OLLAMA_MODEL_QUERY_WRITER",
    "OLLAMA_MODEL_QUERY_REPAIR",
    "OLLAMA_MODEL_EVIDENCE_REVIEWER",
    "OLLAMA_MODEL_ANALYST_REVIEWER",
    "OLLAMA_MODEL_SECURITY_REVIEWER",
    "OLLAMA_MODEL_PEER_REVIEWER",
    "OLLAMA_MODEL_PEER_REVIEWER_2",
    "OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER",
    "OLLAMA_MODEL_FINAL_SUMMARY",
]

# Pulled alongside role assignments but not a separate LangGraph role key.
MODEL_PULL_EXTRA_KEYS = [
    "OLLAMA_MODEL_QUERY_PLANNER_FALLBACK",
]

DEFAULT_MODEL_ASSIGNMENTS: dict[str, str] = {
    "OLLAMA_MODEL_QUERY_PLANNER": DEFAULT_MODEL_QUERY_PLANNER,
    "OLLAMA_MODEL_QUERY_PLANNER_FALLBACK": DEFAULT_MODEL_QUERY_PLANNER_FALLBACK,
    "OLLAMA_MODEL_QUERY_WRITER": DEFAULT_MODEL_QUERY_WRITER,
    "OLLAMA_MODEL_QUERY_REPAIR": DEFAULT_MODEL_QUERY_REPAIR,
    "OLLAMA_MODEL_EVIDENCE_REVIEWER": DEFAULT_MODEL_EVIDENCE_REVIEWER,
    "OLLAMA_MODEL_ANALYST_REVIEWER": DEFAULT_MODEL_ANALYST_REVIEWER,
    "OLLAMA_MODEL_SECURITY_REVIEWER": DEFAULT_MODEL_SECURITY_REVIEWER,
    "OLLAMA_MODEL_PEER_REVIEWER": DEFAULT_MODEL_PEER_REVIEWER,
    "OLLAMA_MODEL_PEER_REVIEWER_2": DEFAULT_MODEL_PEER_REVIEWER_2,
    "OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER": DEFAULT_MODEL_AGENTIC_CONTINUATION_REVIEWER,
    "OLLAMA_MODEL_FINAL_SUMMARY": DEFAULT_MODEL_FINAL_SUMMARY,
}


def expected_ollama_models(values: dict[str, str] | None = None) -> list[str]:
    """Unique Ollama tags required for the active or default model stack."""
    ordered: list[str] = []
    for key in (*MODEL_ASSIGNMENT_KEYS, *MODEL_PULL_EXTRA_KEYS):
        configured = str(values.get(key, "")).strip() if values else ""
        model = configured or str(DEFAULT_MODEL_ASSIGNMENTS.get(key, "")).strip()
        if model and model not in ordered:
            ordered.append(model)
    return ordered


MODEL_ROLE_FAMILIES: list[dict[str, object]] = [
    {
        "id": "planning",
        "title": "Planning",
        "description": "Interpret analyst intent and search strategy before SPL generation.",
        "accent": "#38bdf8",
        "stage_count": 2,
        "core": True,
        "assignments": [
            {"env_key": "OLLAMA_MODEL_QUERY_PLANNER", "label": "Reasoning Planner", "primary": True},
            {"env_key": "OLLAMA_MODEL_QUERY_PLANNER_FALLBACK", "label": "Planner Fallback", "optional": True},
        ],
    },
    {
        "id": "generation",
        "title": "Generation",
        "description": "Write and repair bounded read-only SPL.",
        "accent": "#14b8a6",
        "stage_count": 2,
        "core": True,
        "assignments": [
            {
                "env_key": "OLLAMA_MODEL_QUERY_WRITER",
                "label": "SPL Writer & Repair",
                "primary": True,
                "mirror_keys": ["OLLAMA_MODEL_QUERY_REPAIR"],
            },
        ],
    },
    {
        "id": "peer_review",
        "title": "Peer Review",
        "description": "Adjudicate writer vs security reviewer when queries stay contested.",
        "accent": "#f59e0b",
        "stage_count": 2,
        "core": True,
        "assignments": [
            {
                "env_key": "OLLAMA_MODEL_PEER_REVIEWER",
                "label": "Peer Reviewers 1 & 2",
                "primary": True,
                "mirror_keys": ["OLLAMA_MODEL_PEER_REVIEWER_2"],
            },
        ],
    },
    {
        "id": "analysis",
        "title": "Analysis & Summary",
        "description": "Security review, evidence checks, continuation, and final narrative.",
        "accent": "#a78bfa",
        "stage_count": 4,
        "core": False,
        "assignments": [
            {
                "env_key": "OLLAMA_MODEL_SECURITY_REVIEWER",
                "label": "Review & Summary",
                "primary": True,
                "mirror_keys": [
                    "OLLAMA_MODEL_EVIDENCE_REVIEWER",
                    "OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER",
                    "OLLAMA_MODEL_FINAL_SUMMARY",
                ],
            },
        ],
    },
]


def _family_env_keys(family: dict[str, object]) -> list[str]:
    keys: list[str] = []
    for assignment in family.get("assignments", []):
        if not isinstance(assignment, dict):
            continue
        env_key = str(assignment.get("env_key", "")).strip()
        if env_key:
            keys.append(env_key)
        for mirror in assignment.get("mirror_keys", []):
            mirror_key = str(mirror).strip()
            if mirror_key:
                keys.append(mirror_key)
    return keys


def apply_model_family_assignments(values: dict[str, str]) -> dict[str, str]:
    """Expand family-level assignments into all mirrored runtime role keys."""
    updated = {str(key): str(value).strip() for key, value in values.items()}
    for family in MODEL_ROLE_FAMILIES:
        for assignment in family.get("assignments", []):
            if not isinstance(assignment, dict):
                continue
            env_key = str(assignment.get("env_key", "")).strip()
            if not env_key:
                continue
            model = str(updated.get(env_key, "")).strip()
            if not model:
                continue
            for mirror in assignment.get("mirror_keys", []):
                mirror_key = str(mirror).strip()
                if mirror_key:
                    updated[mirror_key] = model
    return updated


def model_stack_summary(values: dict[str, str] | None = None) -> dict[str, object]:
    """Summarize unique tags, role count, and core vs optional pulls."""
    source = values or {}
    expected = expected_ollama_models(source)
    core_tags: list[str] = []
    optional_tags: list[str] = []
    for family in MODEL_ROLE_FAMILIES:
        family_tags: list[str] = []
        for env_key in _family_env_keys(family):
            tag = str(source.get(env_key, "")).strip() or str(DEFAULT_MODEL_ASSIGNMENTS.get(env_key, "")).strip()
            if tag and tag not in family_tags:
                family_tags.append(tag)
        if bool(family.get("core")):
            core_tags.extend(tag for tag in family_tags if tag not in core_tags)
        else:
            optional_tags.extend(tag for tag in family_tags if tag not in optional_tags and tag not in core_tags)
    role_count = len(MODEL_ASSIGNMENT_KEYS) + len(MODEL_PULL_EXTRA_KEYS)
    return {
        "unique_tag_count": len(expected),
        "role_count": role_count,
        "core_tags": core_tags,
        "optional_tags": optional_tags,
        "families": MODEL_ROLE_FAMILIES,
    }

# v1.4.x legacy defaults (documented for rollback / upstream parity).
LEGACY_V14_MODEL_QUERY_PLANNER = "hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
LEGACY_V14_MODEL_QUERY_WRITER = "deepseek-coder-v2:lite"
LEGACY_V14_MODEL_PEER_REVIEWER = LEGACY_V14_MODEL_QUERY_PLANNER

PROJECT_ROOT = Path(__file__).resolve().parent.parent
UI_ENV_PATH = PROJECT_ROOT / "config" / "ui.env"

# Values that must come from config/ui.env when present — shell exports truncate MCP tokens at '='.
UI_ENV_PREFERRED_KEYS = frozenset(
    {
        "SPLUNK_LAB_BEARER_TOKEN",
        "SPLUNK_HEC_TOKEN",
        "SPLUNK_PASS",
        "SPLUNK_PASSWORD",
    }
)


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT.resolve()))
    except Exception:
        return str(path)


def get_ollama_host() -> str:
    value = _get_config_value("OLLAMA_HOST", DEFAULT_OLLAMA_HOST)
    return str(value).strip().rstrip("/")


def get_ollama_keep_alive() -> str | int:
    """Ollama model retention after each request (0 = unload immediately)."""
    raw = str(_get_config_value("OLLAMA_KEEP_ALIVE", DEFAULT_OLLAMA_KEEP_ALIVE)).strip()
    if not raw:
        return 0
    lowered = raw.lower()
    if lowered in {"0", "false", "no", "off", "immediate"}:
        return 0
    if lowered.isdigit():
        return int(lowered)
    return raw


def get_ollama_warm_keep_alive() -> str | int:
    """Ollama keep_alive used when the UI keep-warm toggle is enabled."""
    raw = str(_get_config_value("OLLAMA_WARM_KEEP_ALIVE", DEFAULT_OLLAMA_WARM_KEEP_ALIVE)).strip()
    if not raw:
        return DEFAULT_OLLAMA_WARM_KEEP_ALIVE
    lowered = raw.lower()
    if lowered in {"0", "false", "no", "off", "immediate"}:
        return 0
    if lowered.isdigit():
        return int(lowered)
    return raw


def is_local_ollama_host(host: str | None = None) -> bool:
    """True when Ollama is reachable on the same machine as the UI sidecar."""
    from urllib.parse import urlparse

    raw = str(host or get_ollama_host()).strip()
    if not raw:
        return False
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    hostname = str(parsed.hostname or "").strip().lower()
    return hostname in LOCAL_OLLAMA_HOSTNAMES


def ollama_warm_model_names(values: dict[str, str] | None = None) -> list[str]:
    """Primary models to preload when keep-warm is enabled."""
    names: list[str] = []
    for key in ("OLLAMA_MODEL_QUERY_PLANNER", "OLLAMA_MODEL_QUERY_WRITER"):
        if isinstance(values, dict) and key in values:
            model = str(values.get(key, "")).strip()
        else:
            model = str(_get_config_value(key, "")).strip()
        if model and model not in names:
            names.append(model)
    return names


def get_mcp_request_timeout_sec() -> float:
    """Return the total timeout budget for one MCP request including retries."""
    raw = str(
        _get_config_value(
            "AGTSMITH_MCP_REQUEST_TIMEOUT_SEC",
            DEFAULT_MCP_REQUEST_TIMEOUT_SEC,
        )
    ).strip()
    try:
        return max(0.1, float(raw))
    except (TypeError, ValueError):
        return float(DEFAULT_MCP_REQUEST_TIMEOUT_SEC)


def get_ollama_request_timeout_sec() -> float:
    """Return the timeout budget for one non-streaming Ollama request."""
    raw = str(
        _get_config_value(
            "AGTSMITH_OLLAMA_REQUEST_TIMEOUT_SEC",
            DEFAULT_OLLAMA_REQUEST_TIMEOUT_SEC,
        )
    ).strip()
    try:
        return max(0.1, float(raw))
    except (TypeError, ValueError):
        return float(DEFAULT_OLLAMA_REQUEST_TIMEOUT_SEC)


def get_edge_llm_enabled() -> bool:
    return str(_get_config_value("EDGE_LLM_ENABLED", "0")).strip() == "1"


def get_edge_llm_host() -> str:
    value = _get_config_value("EDGE_LLM_HOST", "")
    return str(value).strip().rstrip("/")


def get_edge_llm_model() -> str:
    return str(_get_config_value("EDGE_LLM_MODEL", DEFAULT_EDGE_LLM_MODEL)).strip() or DEFAULT_EDGE_LLM_MODEL


def get_edge_llm_role() -> str:
    return str(_get_config_value("EDGE_LLM_ROLE", DEFAULT_EDGE_LLM_ROLE)).strip() or DEFAULT_EDGE_LLM_ROLE


def get_edge_llm_timeout_sec() -> str:
    return str(_get_config_value("EDGE_LLM_TIMEOUT_SEC", DEFAULT_EDGE_LLM_TIMEOUT_SEC)).strip() or DEFAULT_EDGE_LLM_TIMEOUT_SEC


def mcp_pipeline_router_enabled() -> bool:
    return str(_get_config_value("MCP_PIPELINE_ROUTER_ENABLED", "1")).strip() == "1"


def mcp_deterministic_auto_route() -> bool:
    return str(_get_config_value("MCP_DETERMINISTIC_AUTO_ROUTE", "1")).strip() == "1"


def mcp_deterministic_min_confidence() -> float:
    raw = str(_get_config_value("MCP_DETERMINISTIC_MIN_CONFIDENCE", "0.90")).strip()
    try:
        return max(0.0, min(1.0, float(raw)))
    except (TypeError, ValueError):
        return 0.90


def get_soc_ui_session_timeout_min() -> str:
    return (
        str(_get_config_value("SOC_UI_SESSION_TIMEOUT_MIN", DEFAULT_SOC_UI_SESSION_TIMEOUT_MIN)).strip()
        or DEFAULT_SOC_UI_SESSION_TIMEOUT_MIN
    )


def get_soc_ui_session_remember_timeout_min() -> str:
    return (
        str(_get_config_value("SOC_UI_SESSION_REMEMBER_TIMEOUT_MIN", DEFAULT_SOC_UI_SESSION_REMEMBER_TIMEOUT_MIN)).strip()
        or DEFAULT_SOC_UI_SESSION_REMEMBER_TIMEOUT_MIN
    )


def get_env_profile_auto_refresh_enabled() -> bool:
    """Whether the background Data Domains scheduler should run at all."""
    raw = str(
        _get_config_value("ENV_PROFILE_AUTO_REFRESH_ENABLED", DEFAULT_ENV_PROFILE_AUTO_REFRESH_ENABLED)
    ).strip()
    return raw != "0"


def get_env_profile_refresh_interval_minutes() -> int:
    """Cadence, in minutes, for the Data Domains auto-refresh scheduler.

    Configure page offers 60 minutes (default), 4 hours, or once a day, but
    any positive integer supplied directly via env/config is honored so
    operators can fine-tune it outside the UI if needed.
    """
    raw = str(
        _get_config_value(
            "ENV_PROFILE_REFRESH_INTERVAL_MINUTES", DEFAULT_ENV_PROFILE_REFRESH_INTERVAL_MINUTES
        )
    ).strip()
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return int(DEFAULT_ENV_PROFILE_REFRESH_INTERVAL_MINUTES)
    return value if value > 0 else int(DEFAULT_ENV_PROFILE_REFRESH_INTERVAL_MINUTES)


def get_splunk_mcp_url() -> str:
    return str(_get_config_value("SPLUNK_MCP_URL", DEFAULT_SPLUNK_MCP_URL)).strip()


def get_splunk_base_url() -> str:
    explicit = str(_get_config_value("SPLUNK_BASE_URL", "")).strip()
    if explicit:
        return explicit.rstrip("/")
    parsed = urlparse(get_splunk_mcp_url())
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return DEFAULT_SPLUNK_BASE_URL


def get_runtime_secret(name: str, default: str = "") -> str:
    return str(_get_config_value(name, default)).strip()


def get_model_assignment(name: str, default: str = "") -> str:
    return str(_get_config_value(name, default)).strip() or default


def parse_env_file(path: Path | None = None) -> tuple[list[str], dict[str, str]]:
    target = path or UI_ENV_PATH
    if not target.exists():
        return [], {}
    lines = target.read_text(encoding="utf-8").splitlines()
    values: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return lines, values


def _get_config_value(name: str, default: str = "") -> str:
    env_val = str(os.getenv(name, "")).strip()
    _lines, values = parse_env_file()
    file_val = str(values.get(name, "")).strip()

    if name in UI_ENV_PREFERRED_KEYS and file_val:
        # config/ui.env is the source of truth for secrets. Shell exports (IDE sessions,
        # `set -a; source config/ui.env` in an old terminal) often carry stale or
        # truncated MCP tokens that survive reboots and override the good file value.
        return file_val

    if env_val:
        return env_val
    if file_val:
        return file_val
    return default


def write_env_file(updates: dict[str, str], path: Path | None = None) -> Path:
    target = path or UI_ENV_PATH
    lines, current = parse_env_file(target)
    normalized = {str(k).strip(): str(v).strip() for k, v in updates.items() if str(k).strip()}
    if not lines:
        lines = ["# Lab-only, temporary values. Not production-safe."]

    seen: set[str] = set()
    new_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            new_lines.append(line)
            continue
        key, _value = line.split("=", 1)
        key = key.strip()
        if key in normalized:
            new_lines.append(f"{key}={normalized[key]}")
            seen.add(key)
        else:
            new_lines.append(line)
            seen.add(key)

    missing = [k for k in normalized.keys() if k not in seen]
    if missing:
        if new_lines and new_lines[-1].strip():
            new_lines.append("")
        for key in missing:
            new_lines.append(f"{key}={normalized[key]}")

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(new_lines).rstrip() + "\n", encoding="utf-8")
    return target


DEFAULT_SAVED_QUERY_SAVE_REQUIRES_APPROVAL = "0"
DEFAULT_SAVED_QUERY_SHORTCUT_ENABLED = "1"
DEFAULT_SAVED_QUERY_AUTO_THRESHOLD = "0.92"
DEFAULT_SAVED_QUERY_SUGGEST_THRESHOLD = "0.80"
DEFAULT_SAVED_QUERY_INCLUDE_OPTIMIZATION_ASSETS = "0"


def _env_flag(name: str, default: str = "0") -> bool:
    value = _get_config_value(name, default).strip().lower()
    return value not in {"0", "false", "no", ""}


def _env_float(name: str, default: str) -> float:
    raw = _get_config_value(name, default).strip()
    try:
        return float(raw)
    except Exception:
        return float(default)


def saved_query_save_requires_approval() -> bool:
    return _env_flag("SPL_SAVED_QUERY_SAVE_REQUIRES_APPROVAL", DEFAULT_SAVED_QUERY_SAVE_REQUIRES_APPROVAL)


def saved_query_shortcut_enabled() -> bool:
    return _env_flag("SPL_SAVED_QUERY_SHORTCUT_ENABLED", DEFAULT_SAVED_QUERY_SHORTCUT_ENABLED)


def saved_query_include_optimization_assets() -> bool:
    return _env_flag(
        "SPL_SAVED_QUERY_INCLUDE_OPTIMIZATION_ASSETS",
        DEFAULT_SAVED_QUERY_INCLUDE_OPTIMIZATION_ASSETS,
    )


def saved_query_auto_threshold() -> float:
    return _env_float("SPL_SAVED_QUERY_AUTO_THRESHOLD", DEFAULT_SAVED_QUERY_AUTO_THRESHOLD)


def saved_query_suggest_threshold() -> float:
    return _env_float("SPL_SAVED_QUERY_SUGGEST_THRESHOLD", DEFAULT_SAVED_QUERY_SUGGEST_THRESHOLD)
