#!/usr/bin/env python3
"""Protect holdout content from training, retrieval, and improvement assets."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST_PATH = PROJECT_ROOT / "benchmarks" / "scenario_splits" / "manifest.json"

PROTECTED_TEXT_KEYS = frozenset(
    {
        "question",
        "reference_spl",
        "generated_spl",
        "canonical_spl",
        "finding",
        "failure",
        "failure_reason",
    }
)
PROTECTED_HASH_KEYS = frozenset(
    {
        "hash",
        "sha256",
        "question_sha256",
        "reference_spl_sha256",
        "generated_spl_sha256",
        "failure_sha256",
    }
)


class HoldoutLeakageError(ValueError):
    """Raised when protected holdout content reaches a learning asset."""


def normalize_protected_text(value: Any) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return re.sub(r"\s+", " ", text).strip()


def protected_sha256(value: Any) -> str:
    return hashlib.sha256(normalize_protected_text(value).encode("utf-8")).hexdigest()


def load_split_manifest(path: str | Path = DEFAULT_MANIFEST_PATH) -> dict[str, Any]:
    candidate = Path(path)
    if not candidate.is_file():
        return {"version": 1, "splits": {"train": [], "dev": [], "holdout": []}}
    payload = json.loads(candidate.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"split_manifest_must_be_object:{candidate}")
    return payload


def _load_json(path: Path) -> Any:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _manifest_paths(manifest: Mapping[str, Any], manifest_path: Path) -> list[Path]:
    configured = manifest.get("protected_sources", [])
    if not isinstance(configured, list):
        return []
    paths: list[Path] = []
    for value in configured:
        raw = str(value).strip()
        if not raw:
            continue
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = PROJECT_ROOT / candidate
        paths.append(candidate)
    return paths


def _case_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        rows = payload.get("cases", payload.get("results", []))
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def protected_material(
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
) -> dict[str, set[str]]:
    path = Path(manifest_path)
    manifest = load_split_manifest(path)
    splits = manifest.get("splits", {})
    holdout_ids = {
        str(value).strip()
        for value in (splits.get("holdout", []) if isinstance(splits, dict) else [])
        if str(value).strip()
    }
    fragments: set[str] = set()
    hashes: set[str] = set()
    for source in _manifest_paths(manifest, path):
        payload = _load_json(source)
        for row in _case_rows(payload):
            case_id = str(row.get("id", "")).strip()
            if holdout_ids and case_id and case_id not in holdout_ids:
                continue
            for key, value in row.items():
                key_name = str(key).casefold()
                if key_name in PROTECTED_TEXT_KEYS and str(value).strip():
                    normalized = normalize_protected_text(value)
                    if len(normalized) >= 12:
                        fragments.add(normalized)
                        hashes.add(protected_sha256(value))
                if key_name in PROTECTED_HASH_KEYS and str(value).strip():
                    hashes.add(str(value).strip().casefold())
    return {"ids": holdout_ids, "fragments": fragments, "hashes": hashes}


def _flatten_scalars(value: Any) -> Iterable[tuple[str, str]]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_name = str(key).casefold()
            if isinstance(item, (Mapping, list, tuple, set)):
                yield from _flatten_scalars(item)
            else:
                yield key_name, str(item or "")
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _flatten_scalars(item)
    else:
        yield "", str(value or "")


def holdout_leak_reasons(
    record: Any,
    *,
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
) -> list[str]:
    material = protected_material(manifest_path)
    reasons: set[str] = set()
    scalar_values: list[str] = []
    for key, raw in _flatten_scalars(record):
        value = str(raw).strip()
        normalized_value = normalize_protected_text(value)
        scalar_values.append(normalized_value)
        if key in {"id", "case_id", "source_case_id", "benchmark_case_id"} and value in material["ids"]:
            reasons.add(f"protected_holdout_id:{value}")
        if key in PROTECTED_HASH_KEYS and value.casefold() in material["hashes"]:
            reasons.add("protected_holdout_hash")
    normalized_record = " ".join(scalar_values)
    for digest in material["hashes"]:
        if digest and digest in normalized_record:
            reasons.add("protected_holdout_hash")
            break
    for fragment in material["fragments"]:
        if fragment and fragment in normalized_record:
            reasons.add(f"protected_holdout_content:{protected_sha256(fragment)[:12]}")
            break
    return sorted(reasons)


def is_holdout_record(
    record: Any,
    *,
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
) -> bool:
    return bool(holdout_leak_reasons(record, manifest_path=manifest_path))


def filter_holdout_records(
    records: Iterable[dict[str, Any]],
    *,
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    allowed: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for record in records:
        reasons = holdout_leak_reasons(record, manifest_path=manifest_path)
        if reasons:
            rejected.append({"record": record, "reasons": reasons})
        else:
            allowed.append(record)
    return allowed, rejected


def assert_no_holdout_leakage(
    payload: Any,
    *,
    asset_name: str,
    manifest_path: str | Path = DEFAULT_MANIFEST_PATH,
) -> None:
    reasons = holdout_leak_reasons(payload, manifest_path=manifest_path)
    if reasons:
        raise HoldoutLeakageError(f"{asset_name}:" + ",".join(reasons))
