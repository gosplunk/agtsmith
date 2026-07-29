#!/usr/bin/env python3
"""Load lab data layout/event YAML and environment configuration."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LAYOUT_PATH = PROJECT_ROOT / "config" / "lab_data_layout.yaml"
DEFAULT_EVENTS_PATH = PROJECT_ROOT / "config" / "lab_data_events.yaml"
DEFAULT_UI_ENV = PROJECT_ROOT / "config" / "ui.env"
VERIFY_MANIFEST_PATH = PROJECT_ROOT / "artifacts" / "spl_autonomy" / "lab_data" / "verify_latest.json"


def _require_yaml() -> Any:
    if yaml is None:
        raise RuntimeError("PyYAML required: pip install PyYAML")
    return yaml


def load_yaml(path: Path) -> dict[str, Any]:
    payload = _require_yaml().safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"yaml_root_must_be_mapping:{path}")
    return payload


def load_ui_env(path: Path | None = None) -> dict[str, str]:
    env_path = path or DEFAULT_UI_ENV
    out: dict[str, str] = {}
    if not env_path.is_file():
        return out
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        out[key.strip()] = value.strip()
    return out


def load_layout_config(path: Path | None = None) -> dict[str, Any]:
    return load_yaml(path or DEFAULT_LAYOUT_PATH)


def load_event_catalog(path: Path | None = None) -> dict[str, Any]:
    return load_yaml(path or DEFAULT_EVENTS_PATH)


def detect_layout_from_profile(profile: dict[str, Any]) -> str:
    index_names = {
        str(row.get("index", "")).strip().lower()
        for row in profile.get("indexes", [])
        if isinstance(row, dict) and str(row.get("index", "")).strip()
    }
    if {"soc_linux", "soc_windows"}.issubset(index_names):
        return "multi_index_ideal"
    if "linux" in index_names and "botsv3" in index_names:
        return "existing_lab"
    if "agtsmith_test" in index_names:
        return "minimal_ci"
    return "minimal_ci"


def resolve_layout_name(
    layout: str | None,
    *,
    profile_path: Path | None = None,
    ui_env: dict[str, str] | None = None,
) -> str:
    if layout and layout.strip():
        return layout.strip()
    env = ui_env or load_ui_env()
    from_env = str(env.get("LAB_DATA_LAYOUT", "")).strip()
    if from_env:
        return from_env
    if profile_path and profile_path.is_file():
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        if isinstance(profile, dict):
            return detect_layout_from_profile(profile)
    return "existing_lab"


def get_layout(layout_name: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = config or load_layout_config()
    layouts = cfg.get("layouts", {})
    if not isinstance(layouts, dict):
        raise ValueError("layouts_missing")
    layout = layouts.get(layout_name)
    if not isinstance(layout, dict):
        raise KeyError(f"unknown_layout:{layout_name}")
    return layout


def resolve_domain_target(layout_name: str, domain: str, config: dict[str, Any] | None = None) -> dict[str, str]:
    layout = get_layout(layout_name, config)
    indexes = layout.get("indexes", {})
    if not isinstance(indexes, dict):
        raise ValueError("layout_indexes_missing")
    target = indexes.get(domain)
    if not isinstance(target, dict):
        raise KeyError(f"unknown_domain:{domain}")
    index = str(target.get("index", "")).strip()
    sourcetype = str(target.get("sourcetype", "")).strip()
    if not index or not sourcetype:
        raise ValueError(f"incomplete_domain_target:{domain}")
    return {"index": index, "sourcetype": sourcetype}


def layout_index_names(layout_name: str, config: dict[str, Any] | None = None) -> set[str]:
    layout = get_layout(layout_name, config)
    indexes = layout.get("indexes", {})
    names: set[str] = set()
    if isinstance(indexes, dict):
        for target in indexes.values():
            if isinstance(target, dict):
                idx = str(target.get("index", "")).strip()
                if idx:
                    names.add(idx)
    provision = layout.get("provision_indexes", [])
    if isinstance(provision, list):
        for idx in provision:
            token = str(idx).strip()
            if token:
                names.add(token)
    return names


def format_verify_query(template: str, *, index: str, sourcetype: str) -> str:
    return template.format(index=index, sourcetype=sourcetype)


def write_verify_manifest(payload: dict[str, Any], path: Path | None = None) -> Path:
    out_path = path or VERIFY_MANIFEST_PATH
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out_path


def read_verify_manifest(path: Path | None = None) -> dict[str, Any] | None:
    out_path = path or VERIFY_MANIFEST_PATH
    if not out_path.is_file():
        return None
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else None


def env_truthy(name: str, ui_env: dict[str, str] | None = None) -> bool:
    env = ui_env if ui_env is not None else load_ui_env()
    return str(env.get(name, os.environ.get(name, ""))).strip().lower() in {"1", "true", "yes", "on"}


def apache_time_token() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")


def substitute_fields(template: str, fields: dict[str, list[str]], rng: Any) -> str:
    out = template
    for key, values in fields.items():
        if not values:
            continue
        out = out.replace("{" + key + "}", str(rng.choice(values)))
    out = out.replace("{time}", apache_time_token())
    return out
