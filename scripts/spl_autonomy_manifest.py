#!/usr/bin/env python3
"""Shared manifest stamping for SPL autonomy loop artifacts."""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runtime_config import DEFAULT_MODEL_ASSIGNMENTS, MODEL_ASSIGNMENT_KEYS, MODEL_PULL_EXTRA_KEYS, parse_env_file

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENV_PROFILE_PATH = PROJECT_ROOT / "artifacts" / "environment" / "environment_profile_latest.json"
DEFAULT_SKILLPACK_PATH = PROJECT_ROOT / "artifacts" / "knowledge" / "spl_skillpack_latest.json"
LEGACY_ENV_PROFILE_PATH = PROJECT_ROOT / "docs" / "logs" / "environment_profile_latest.json"


def git_sha() -> str | None:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=PROJECT_ROOT,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        value = out.strip()
        return value or None
    except Exception:
        return None


def file_sha256(path: str | Path) -> str | None:
    p = Path(path)
    if not p.is_file():
        return None
    digest = hashlib.sha256()
    with p.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def model_tags() -> dict[str, str]:
    _lines, env_values = parse_env_file()
    tags: dict[str, str] = {}
    for key in (*MODEL_ASSIGNMENT_KEYS, *MODEL_PULL_EXTRA_KEYS):
        configured = str(env_values.get(key, "")).strip()
        tags[key] = configured or str(DEFAULT_MODEL_ASSIGNMENTS.get(key, "")).strip()
    return tags


def env_profile_hash(path: str | Path | None = None) -> str | None:
    candidate = Path(path) if path else DEFAULT_ENV_PROFILE_PATH
    if not candidate.is_file() and candidate == DEFAULT_ENV_PROFILE_PATH and LEGACY_ENV_PROFILE_PATH.is_file():
        candidate = LEGACY_ENV_PROFILE_PATH
    if not candidate.is_file():
        return None
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
    except Exception:
        return file_sha256(candidate)
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def skillpack_hash(path: str | Path | None = None) -> str | None:
    candidate = Path(path) if path else DEFAULT_SKILLPACK_PATH
    if not candidate.is_file():
        return None
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
    except Exception:
        return file_sha256(candidate)
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def build_manifest(
    *,
    env_profile_path: str | Path | None = None,
    skillpack_path: str | Path | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    env_path = Path(env_profile_path) if env_profile_path else DEFAULT_ENV_PROFILE_PATH
    if not env_path.is_file() and env_path == DEFAULT_ENV_PROFILE_PATH and LEGACY_ENV_PROFILE_PATH.is_file():
        env_path = LEGACY_ENV_PROFILE_PATH
    skill_path = Path(skillpack_path) if skillpack_path else DEFAULT_SKILLPACK_PATH
    manifest: dict[str, Any] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "git_sha": git_sha(),
        "model_tags": model_tags(),
        "env_profile_path": str(env_path.relative_to(PROJECT_ROOT)) if env_path.is_file() else str(env_path),
        "env_profile_hash": env_profile_hash(env_path),
        "skillpack_path": str(skill_path.relative_to(PROJECT_ROOT)) if skill_path.is_file() else str(skill_path),
        "skillpack_hash": skillpack_hash(skill_path),
    }
    if extra:
        manifest.update(extra)
    return manifest


def write_run_manifest(run_dir: str | Path, *, extra: dict[str, Any] | None = None) -> Path:
    """Write artifacts/spl_autonomy/runs/<timestamp>/manifest.json."""
    target = Path(run_dir)
    target.mkdir(parents=True, exist_ok=True)
    manifest = build_manifest(extra=extra)
    out_path = target / "manifest.json"
    out_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return out_path
