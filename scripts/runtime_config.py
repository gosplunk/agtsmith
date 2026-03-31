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
DEFAULT_MODEL_QUERY_PLANNER = "hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
DEFAULT_MODEL_QUERY_WRITER = "deepseek-coder-v2:lite"
DEFAULT_MODEL_REASONING = "hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
DEFAULT_MODEL_SECURITY_REVIEWER = DEFAULT_MODEL_REASONING
DEFAULT_MODEL_EVIDENCE_REVIEWER = DEFAULT_MODEL_REASONING
DEFAULT_MODEL_PEER_REVIEWER = DEFAULT_MODEL_QUERY_PLANNER
DEFAULT_MODEL_PEER_REVIEWER_2 = DEFAULT_MODEL_QUERY_PLANNER
DEFAULT_MODEL_AGENTIC_CONTINUATION_REVIEWER = DEFAULT_MODEL_REASONING
DEFAULT_MODEL_FINAL_SUMMARY = DEFAULT_MODEL_REASONING
DEFAULT_MODEL_QUERY_REPAIR = DEFAULT_MODEL_QUERY_WRITER

PROJECT_ROOT = Path(__file__).resolve().parent.parent
UI_ENV_PATH = PROJECT_ROOT / "config" / "ui.env"


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT.resolve()))
    except Exception:
        return str(path)


def get_ollama_host() -> str:
    value = _get_config_value("OLLAMA_HOST", DEFAULT_OLLAMA_HOST)
    return str(value).strip().rstrip("/")


def get_edge_llm_enabled() -> bool:
    return str(_get_config_value("EDGE_LLM_ENABLED", "0")).strip() == "1"


def get_edge_llm_host() -> str:
    value = _get_config_value("EDGE_LLM_HOST", "")
    return str(value).strip().rstrip("/")


def get_edge_llm_model() -> str:
    return str(_get_config_value("EDGE_LLM_MODEL", "")).strip()


def get_edge_llm_role() -> str:
    return str(_get_config_value("EDGE_LLM_ROLE", DEFAULT_EDGE_LLM_ROLE)).strip() or DEFAULT_EDGE_LLM_ROLE


def get_edge_llm_timeout_sec() -> str:
    return str(_get_config_value("EDGE_LLM_TIMEOUT_SEC", DEFAULT_EDGE_LLM_TIMEOUT_SEC)).strip() or DEFAULT_EDGE_LLM_TIMEOUT_SEC


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
    explicit = str(os.getenv(name, "")).strip()
    if explicit:
        return explicit
    _lines, values = parse_env_file()
    if name in values:
        return values[name]
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
