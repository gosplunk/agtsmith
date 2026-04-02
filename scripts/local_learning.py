#!/usr/bin/env python3
"""Guarded local learning artifact storage."""

from __future__ import annotations

import hashlib
import os
import json
import re
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from environment_profile import load_environment_profile
from runtime_config import (
    DEFAULT_MODEL_QUERY_PLANNER,
    DEFAULT_MODEL_QUERY_WRITER,
    DEFAULT_MODEL_SECURITY_REVIEWER,
    get_ollama_host,
    parse_env_file,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS_ROOT = PROJECT_ROOT / "artifacts"
LEARNING_ROOT = ARTIFACTS_ROOT / "learning"
REGISTRY_PATH = LEARNING_ROOT / "local_learning_registry.json"
LEARNING_PROGRESS_PATH = LEARNING_ROOT / "local_learning_progress.json"
LEARNING_BENCHMARK_CACHE_PATH = LEARNING_ROOT / "local_learning_benchmark_cache.json"
QUERY_AUDIT_LOG = ARTIFACTS_ROOT / "audit" / "query_runs.jsonl"
ENV_PROFILE_PATH = ARTIFACTS_ROOT / "environment" / "environment_profile_latest.json"
WRITER_BENCHMARK_CASES = PROJECT_ROOT / "benchmarks" / "spl_cases.json"

ALLOWED_STATUSES = {"pending", "approved", "rejected", "stale"}
ALLOWED_KINDS = {
    "preferred_sources",
    "preferred_fields",
    "preferred_filters",
    "post_result_pivot_hint",
}
BROAD_INTENTS = {"failed_login_activity"}
INTENT_TO_DOMAIN = {
    "failed_login_activity": "cross_platform_auth",
    "linux_auth_failures": "linux_auth",
    "linux_privilege_escalation": "linux_auth",
    "windows_auth_failures": "windows_auth",
    "apache_access_top_ips": "apache_web",
}
EXPECTED_KIND_BY_DOMAIN = {
    "linux_auth": "preferred_sources",
    "windows_auth": "preferred_fields",
    "apache_web": "preferred_fields",
    "cross_platform_auth": "post_result_pivot_hint",
}
AUTO_STALE_PENDING_HOURS = 72
LEGACY_SOURCETYPE_TOKENS = ("too_small",)
LEARNING_MODEL_TIMEOUT_SECONDS = 15.0
MAX_LEARNING_AUDIT_ENTRIES = 20
MAX_LEARNING_AUDIT_BUNDLES = 8
MAX_LEARNING_AUDIT_BUNDLES_PER_INTENT = 2
MAX_LEARNING_BENCHMARK_CASES = 4
MAX_LEARNING_BENCHMARK_CASES_PER_INTENT = 1
DEFAULT_LEARNING_BENCHMARK_INTENTS = (
    "linux_auth_failures",
    "windows_auth_failures",
    "apache_access_top_ips",
    "failed_login_activity",
)
TIMEOUT_TOKENS = ("readtimeout", "timed out", "timeout")

_APPROVED_RECORD_OVERRIDE: list[dict[str, Any]] | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_timestamp(raw: str) -> datetime | None:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _is_legacy_sourcetype(value: str) -> bool:
    lower = str(value or "").strip().lower()
    return bool(lower) and any(token in lower for token in LEGACY_SOURCETYPE_TOKENS)


def _sanitize_learning_proposal(kind: str, proposal: Any) -> tuple[dict[str, Any], bool]:
    if not isinstance(proposal, dict):
        return {}, not isinstance(proposal, dict)
    cleaned = dict(proposal)
    changed = False
    if kind == "preferred_sources":
        sourcetypes = cleaned.get("preferred_sourcetypes", [])
        if isinstance(sourcetypes, list):
            filtered = [str(item).strip() for item in sourcetypes if str(item).strip() and not _is_legacy_sourcetype(str(item))]
            if filtered != sourcetypes:
                cleaned["preferred_sourcetypes"] = filtered
                changed = True
    return cleaned, changed


def _sanitize_learning_reason(reason: str) -> str:
    text = str(reason or "").strip()
    if not text:
        return ""
    cleaned = re.sub(r"\b[\w.-]*too_small[\w.-]*\b", "legacy truncated sourcetype", text, flags=re.IGNORECASE)
    return cleaned.strip()


def _runtime_models() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if str(v).strip()}
    _lines, file_values = parse_env_file()
    values = {**file_values, **env}
    return {
        "planner": str(values.get("OLLAMA_MODEL_QUERY_PLANNER", DEFAULT_MODEL_QUERY_PLANNER)).strip() or DEFAULT_MODEL_QUERY_PLANNER,
        "writer": str(values.get("OLLAMA_MODEL_QUERY_WRITER", DEFAULT_MODEL_QUERY_WRITER)).strip() or DEFAULT_MODEL_QUERY_WRITER,
        "reviewer": str(values.get("OLLAMA_MODEL_SECURITY_REVIEWER", DEFAULT_MODEL_SECURITY_REVIEWER)).strip() or DEFAULT_MODEL_SECURITY_REVIEWER,
    }


def _extract_json_object(text: str) -> dict[str, Any]:
    if not text:
        raise ValueError("empty_model_text")
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        obj = json.loads(cleaned)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", cleaned):
        start = match.start()
        try:
            obj, _end = decoder.raw_decode(cleaned[start:])
        except Exception:
            continue
        if isinstance(obj, dict):
            return obj
    raise ValueError("json_object_not_found")


def _call_ollama_json(*, model: str, system_prompt: str, user_payload: dict[str, Any], timeout: float = 120.0) -> dict[str, Any]:
    payload = {
        "model": model,
        "prompt": (
            f"{system_prompt}\n\n"
            "Return strict JSON only. No prose.\n\n"
            f"INPUT:\n{json.dumps(user_payload, indent=2)}"
        ),
        "stream": False,
        "think": False,
    }
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(f"{get_ollama_host()}/api/generate", json=payload)
        resp.raise_for_status()
        body = resp.json()
    raw = str(body.get("response") or "").strip()
    parsed = _extract_json_object(raw)
    parsed["_raw_text_preview"] = raw[:1000]
    return parsed


def _default_registry() -> dict[str, Any]:
    return {
        "version": 1,
        "updated_at": _utc_now(),
        "records": [],
    }


def ensure_learning_registry() -> Path:
    LEARNING_ROOT.mkdir(parents=True, exist_ok=True)
    if not REGISTRY_PATH.exists():
        REGISTRY_PATH.write_text(json.dumps(_default_registry(), indent=2), encoding="utf-8")
    return REGISTRY_PATH


def load_learning_registry() -> dict[str, Any]:
    ensure_learning_registry()
    try:
        raw = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    except Exception:
        raw = _default_registry()
    if not isinstance(raw, dict):
        raw = _default_registry()
    records = raw.get("records", [])
    if not isinstance(records, list):
        records = []
    normalized: list[dict[str, Any]] = []
    changed = False
    now = datetime.now(timezone.utc)
    for row in records:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status", "pending")).strip().lower() or "pending"
        kind = str(row.get("kind", "")).strip()
        proposal, proposal_changed = _sanitize_learning_proposal(kind, row.get("proposal"))
        reason = _sanitize_learning_reason(str(row.get("reason", "")).strip())
        if proposal_changed or reason != str(row.get("reason", "")).strip():
            changed = True
        created_at = str(row.get("created_at", "")).strip() or _utc_now()
        parsed_created = _parse_timestamp(created_at)
        if status == "pending" and parsed_created is not None:
            age_hours = (now - parsed_created).total_seconds() / 3600.0
            if age_hours >= AUTO_STALE_PENDING_HOURS:
                status = "stale"
                changed = True
        normalized.append(
            {
                "id": str(row.get("id", "")).strip(),
                "scope": str(row.get("scope", "local")).strip() or "local",
                "intent": str(row.get("intent", "")).strip(),
                "kind": kind,
                "proposal": proposal,
                "reason": reason,
                "supporting_question": str(row.get("supporting_question", "")).strip(),
                "supporting_spl": str(row.get("supporting_spl", "")).strip(),
                "supporting_result_excerpt": str(row.get("supporting_result_excerpt", "")).strip(),
                "environment_evidence": row.get("environment_evidence", {}),
                "created_at": created_at,
                "updated_at": str(row.get("updated_at", "")).strip() or _utc_now(),
                "status": status if status in ALLOWED_STATUSES else "pending",
            }
        )
    out = {
        "version": int(raw.get("version", 1) or 1),
        "updated_at": str(raw.get("updated_at", "")).strip() or _utc_now(),
        "records": normalized,
    }
    if changed:
        save_learning_registry(out)
        out["updated_at"] = _utc_now()
    return out


def save_learning_registry(data: dict[str, Any]) -> None:
    ensure_learning_registry()
    out = _default_registry()
    if isinstance(data, dict):
        out["version"] = int(data.get("version", 1) or 1)
        records = data.get("records", [])
        out["records"] = records if isinstance(records, list) else []
    out["updated_at"] = _utc_now()
    REGISTRY_PATH.write_text(json.dumps(out, indent=2), encoding="utf-8")


def load_learning_progress() -> dict[str, Any]:
    LEARNING_ROOT.mkdir(parents=True, exist_ok=True)
    if not LEARNING_PROGRESS_PATH.exists():
        return {}
    try:
        raw = json.loads(LEARNING_PROGRESS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}


def save_learning_progress(data: dict[str, Any]) -> None:
    LEARNING_ROOT.mkdir(parents=True, exist_ok=True)
    payload = data if isinstance(data, dict) else {}
    LEARNING_PROGRESS_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _load_learning_benchmark_cache() -> dict[str, Any]:
    LEARNING_ROOT.mkdir(parents=True, exist_ok=True)
    if not LEARNING_BENCHMARK_CACHE_PATH.exists():
        return {"entries": {}}
    try:
        raw = json.loads(LEARNING_BENCHMARK_CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"entries": {}}
    if not isinstance(raw, dict):
        return {"entries": {}}
    entries = raw.get("entries", {})
    if not isinstance(entries, dict):
        entries = {}
    return {"entries": entries}


def _save_learning_benchmark_cache(data: dict[str, Any]) -> None:
    LEARNING_ROOT.mkdir(parents=True, exist_ok=True)
    entries = data.get("entries", {}) if isinstance(data, dict) else {}
    if not isinstance(entries, dict):
        entries = {}
    payload = {"updated_at": _utc_now(), "entries": entries}
    LEARNING_BENCHMARK_CACHE_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _approved_record_signature(records: list[dict[str, Any]]) -> str:
    normalized = []
    for row in records:
        if not isinstance(row, dict):
            continue
        normalized.append(
            {
                "id": str(row.get("id", "")).strip(),
                "intent": str(row.get("intent", "")).strip(),
                "kind": str(row.get("kind", "")).strip(),
                "proposal": row.get("proposal", {}),
                "status": str(row.get("status", "")).strip(),
            }
        )
    raw = json.dumps(sorted(normalized, key=lambda item: item["id"]), sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _learning_record_fingerprint(row: dict[str, Any]) -> str:
    intent = str(row.get("intent", "")).strip()
    kind = str(row.get("kind", "")).strip()
    proposal, _ = _sanitize_learning_proposal(kind, row.get("proposal", {}))
    raw = json.dumps(
        {
            "intent": intent,
            "kind": kind,
            "proposal": proposal,
        },
        sort_keys=True,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def update_learning_progress_history(snapshot: dict[str, Any]) -> dict[str, Any]:
    current = load_learning_progress()
    history = current.get("history", []) if isinstance(current.get("history"), list) else []
    run_summary = {
        "timestamp_utc": str(snapshot.get("timestamp_utc", "")).strip() or _utc_now(),
        "baseline_avg_score": float(((snapshot.get("comparison", {}) or {}).get("baseline_avg_score", 0.0)) or 0.0),
        "current_avg_score": float(((snapshot.get("comparison", {}) or {}).get("current_avg_score", 0.0)) or 0.0),
        "avg_score_delta": float(((snapshot.get("comparison", {}) or {}).get("avg_score_delta", 0.0)) or 0.0),
        "baseline_pass_rate_pct": float(((snapshot.get("comparison", {}) or {}).get("baseline_pass_rate_pct", 0.0)) or 0.0),
        "current_pass_rate_pct": float(((snapshot.get("comparison", {}) or {}).get("current_pass_rate_pct", 0.0)) or 0.0),
        "pass_rate_delta_pct": float(((snapshot.get("comparison", {}) or {}).get("pass_rate_delta_pct", 0.0)) or 0.0),
        "factory_baseline_avg_score": float(((snapshot.get("overall_learning_level", {}) or {}).get("baseline_avg_score", 0.0)) or 0.0),
        "current_learning_level_avg_score": float(((snapshot.get("overall_learning_level", {}) or {}).get("current_avg_score", 0.0)) or 0.0),
        "factory_to_current_avg_delta": float(((snapshot.get("overall_learning_level", {}) or {}).get("avg_score_delta", 0.0)) or 0.0),
        "run_duration_sec": float(snapshot.get("run_duration_sec", 0.0) or 0.0),
        "selected_candidate_count": int(snapshot.get("selected_candidate_count", 0) or 0),
        "generated_candidate_count": int(snapshot.get("generated_candidate_count", 0) or 0),
    }
    history.append(run_summary)
    history = history[-12:]
    best = max(history, key=lambda item: (float(item.get("current_avg_score", 0.0)), float(item.get("current_pass_rate_pct", 0.0))), default=run_summary)
    payload = dict(snapshot)
    payload["history"] = history
    payload["best_run"] = best
    save_learning_progress(payload)
    return payload


def learning_registry_summary() -> dict[str, Any]:
    data = load_learning_registry()
    counts = {key: 0 for key in sorted(ALLOWED_STATUSES)}
    latest: list[dict[str, Any]] = []
    for row in data.get("records", []):
        status = str(row.get("status", "pending"))
        if status in counts:
            counts[status] += 1
        latest.append(
            {
                "id": row.get("id", ""),
                "intent": row.get("intent", ""),
                "kind": row.get("kind", ""),
                "status": status,
                "created_at": row.get("created_at", ""),
                "reason": row.get("reason", ""),
                "proposal": row.get("proposal", {}),
                "supporting_question": row.get("supporting_question", ""),
            }
        )
    latest.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
    return {
        "path": str(REGISTRY_PATH),
        "version": data.get("version", 1),
        "updated_at": data.get("updated_at", ""),
        "counts": counts,
        "latest": latest[:6],
    }


def approved_learning_records() -> list[dict[str, Any]]:
    if _APPROVED_RECORD_OVERRIDE is not None:
        return [row for row in _APPROVED_RECORD_OVERRIDE if isinstance(row, dict)]
    data = load_learning_registry()
    rows = data.get("records", [])
    if not isinstance(rows, list):
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("status", "")).strip().lower() != "approved":
            continue
        kind = str(row.get("kind", "")).strip()
        if kind not in ALLOWED_KINDS:
            continue
        out.append(row)
    return out


def _approved_learning_state_summary(records: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    rows = [row for row in (records if records is not None else approved_learning_records()) if isinstance(row, dict)]
    intents = sorted({str(row.get("intent", "")).strip() for row in rows if str(row.get("intent", "")).strip()})
    kinds = sorted({str(row.get("kind", "")).strip() for row in rows if str(row.get("kind", "")).strip()})
    return {
        "approved_count": len(rows),
        "active": bool(rows),
        "intents": intents,
        "kinds": kinds,
    }


@contextmanager
def learning_record_override(records: list[dict[str, Any]] | None):
    global _APPROVED_RECORD_OVERRIDE
    previous = _APPROVED_RECORD_OVERRIDE
    _APPROVED_RECORD_OVERRIDE = [row for row in (records or []) if isinstance(row, dict)]
    try:
        yield
    finally:
        _APPROVED_RECORD_OVERRIDE = previous


@contextmanager
def _learning_benchmark_timeout_override(module: Any, timeout: float):
    original = getattr(module, "_call_ollama_json", None)
    if not callable(original):
        yield
        return

    def _wrapped_call_ollama_json(*, model: str, system_prompt: str, user_payload: dict[str, Any], timeout: float = 180.0) -> dict[str, Any]:
        bounded_timeout = min(float(timeout or LEARNING_MODEL_TIMEOUT_SECONDS), float(LEARNING_MODEL_TIMEOUT_SECONDS))
        return original(
            model=model,
            system_prompt=system_prompt,
            user_payload=user_payload,
            timeout=bounded_timeout,
        )

    setattr(module, "_call_ollama_json", _wrapped_call_ollama_json)
    try:
        yield
    finally:
        setattr(module, "_call_ollama_json", original)


def _stable_id(intent: str, kind: str, proposal: Any) -> str:
    raw = json.dumps({"intent": intent, "kind": kind, "proposal": proposal}, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _candidate(
    *,
    intent: str,
    kind: str,
    proposal: Any,
    reason: str,
    supporting_question: str = "",
    supporting_spl: str = "",
    supporting_result_excerpt: str = "",
    environment_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = _utc_now()
    clean_kind = str(kind).strip()
    clean_proposal, _ = _sanitize_learning_proposal(clean_kind, proposal)
    clean_reason = _sanitize_learning_reason(reason)
    return {
        "id": _stable_id(intent, clean_kind, clean_proposal),
        "scope": "local",
        "intent": intent,
        "kind": clean_kind,
        "proposal": clean_proposal,
        "reason": clean_reason,
        "supporting_question": supporting_question,
        "supporting_spl": supporting_spl,
        "supporting_result_excerpt": supporting_result_excerpt,
        "environment_evidence": environment_evidence or {},
        "created_at": now,
        "updated_at": now,
        "status": "pending",
    }


def _load_query_audit(limit: int = MAX_LEARNING_AUDIT_ENTRIES) -> list[dict[str, Any]]:
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


def _recent_rows_positive(entry: dict[str, Any]) -> bool:
    rows = entry.get("rows_returned")
    try:
        return int(rows) > 0
    except Exception:
        return False


def _support_excerpt(entry: dict[str, Any]) -> str:
    parts: list[str] = []
    preview = entry.get("spl_results_preview")
    if isinstance(preview, list) and preview:
        try:
            parts.append(json.dumps(preview[:2], sort_keys=True)[:500])
        except Exception:
            pass
    rows = entry.get("rows_returned")
    if rows is not None:
        parts.append(f"rows_returned={rows}")
    return "\n".join(part for part in parts if part).strip()


def _build_learning_evidence(profile: dict[str, Any], audit: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    st_to_indexes = profile.get("sourcetype_to_indexes", {}) if isinstance(profile, dict) else {}
    indexes = profile.get("indexes", []) if isinstance(indexes := profile.get("indexes", []), list) else []
    linux_sourcetypes: set[str] = set()
    for row in indexes:
        if not isinstance(row, dict) or str(row.get("index", "")).strip() != "linux":
            continue
        for st in row.get("sourcetypes", []):
            st_name = str(st).strip()
            if st_name:
                linux_sourcetypes.add(st_name)
    auth_sourcetypes = [
        st for st in sorted(linux_sourcetypes)
        if any(tok in st.lower() for tok in ("auth", "secure", "syslog"))
    ]
    if auth_sourcetypes:
        evidence.append(
            {
                "bundle_id": "linux_auth_environment",
                "domain": "linux_auth",
                "candidate_intents": ["linux_auth_failures", "linux_privilege_escalation"],
                "environment_evidence": {
                    "preferred_index": "linux",
                    "preferred_sources": ["/var/log/auth.log", "/var/log/secure"],
                    "preferred_sourcetypes": auth_sourcetypes,
                    "sourcetype_to_indexes": {st: st_to_indexes.get(st, []) for st in auth_sourcetypes},
                },
                "reason": "Linux auth-like sourcetypes are present in the environment profile.",
            }
        )
    if "access_combined" in linux_sourcetypes:
        evidence.append(
            {
                "bundle_id": "apache_access_environment",
                "domain": "apache_web",
                "candidate_intents": ["apache_access_top_ips"],
                "environment_evidence": {
                    "preferred_index": "linux",
                    "preferred_sourcetype": "access_combined",
                    "available_fields": ["clientip", "status", "method", "useragent", "uri_path"],
                },
                "reason": "Apache-style access logs are present in the environment profile.",
            }
        )
    windows_indexes = set(st_to_indexes.get("XmlWinEventLog", [])) if isinstance(st_to_indexes, dict) else set()
    if windows_indexes:
        evidence.append(
            {
                "bundle_id": "windows_auth_environment",
                "domain": "windows_auth",
                "candidate_intents": ["windows_auth_failures"],
                "environment_evidence": {
                    "preferred_indexes": sorted(windows_indexes),
                    "preferred_sourcetype": "XmlWinEventLog",
                    "available_fields": ["host", "user_name", "src_ip", "EventCode"],
                },
                "reason": "Windows XML event logs are present in the environment profile.",
            }
        )
    if auth_sourcetypes and windows_indexes:
        evidence.append(
            {
                "bundle_id": "cross_platform_auth_environment",
                "domain": "cross_platform_auth",
                "candidate_intents": ["failed_login_activity"],
                "environment_evidence": {
                    "available_platforms": ["linux", "windows"],
                    "linux_auth_sources": ["/var/log/auth.log", "/var/log/secure"],
                    "linux_auth_sourcetypes": auth_sourcetypes,
                    "windows_auth_indexes": sorted(windows_indexes),
                    "windows_auth_sourcetype": "XmlWinEventLog",
                },
                "reason": "Both Linux auth-style evidence and Windows XML event logs exist here; broad failed-login questions should remember to pivot across both platforms.",
            }
        )
    seen_audit_keys: set[str] = set()
    per_intent_counts: dict[str, int] = {}
    added_audit_bundles = 0
    for entry in audit:
        if not isinstance(entry, dict) or not _recent_rows_positive(entry):
            continue
        intent = str(entry.get("intent", "")).strip()
        query = str(entry.get("query", "")).strip()
        question = str(entry.get("question", "")).strip()
        if not intent or not query:
            continue
        stable_key = hashlib.sha256(f"{intent}\n{query}".encode("utf-8")).hexdigest()[:16]
        if stable_key in seen_audit_keys:
            continue
        if added_audit_bundles >= MAX_LEARNING_AUDIT_BUNDLES:
            break
        if int(per_intent_counts.get(intent, 0)) >= MAX_LEARNING_AUDIT_BUNDLES_PER_INTENT:
            continue
        domain = INTENT_TO_DOMAIN.get(intent, "general")
        evidence.append(
            {
                "bundle_id": f"audit_{intent}_{hashlib.sha256(query.encode('utf-8')).hexdigest()[:10]}",
                "domain": domain,
                "candidate_intents": [intent],
                "environment_evidence": {
                    "supporting_query": query[:900],
                    "rows_returned": entry.get("rows_returned"),
                },
                "supporting_question": question,
                "supporting_spl": query[:900],
                "supporting_result_excerpt": _support_excerpt(entry),
                "reason": "A recent successful local investigation returned evidence for this intent.",
            }
        )
        seen_audit_keys.add(stable_key)
        per_intent_counts[intent] = int(per_intent_counts.get(intent, 0)) + 1
        added_audit_bundles += 1
    return evidence


def _environment_bundle_reason(bundle: dict[str, Any]) -> str:
    domain = str(bundle.get("domain", "")).strip()
    if domain == "linux_auth":
        return "Environment-backed Linux auth sources and sourcetypes were detected in Data Domains."
    if domain == "windows_auth":
        return "Environment-backed Windows authentication fields were detected in Data Domains."
    if domain == "apache_web":
        return "Environment-backed Apache web fields were detected in Data Domains."
    if domain == "cross_platform_auth":
        return "Environment-backed Linux and Windows authentication coverage supports a cross-platform pivot hint."
    return "Environment-backed local evidence supports this guarded learning hint."


def _deterministic_environment_candidate(bundle: dict[str, Any]) -> dict[str, Any] | None:
    if not _is_environment_bundle(bundle):
        return None
    intents = [str(item).strip() for item in bundle.get("candidate_intents", []) if str(item).strip()]
    if not intents:
        return None
    expected_kind = _expected_kind(bundle)
    proposal = _bundle_expected_proposal(bundle)
    if not expected_kind or not proposal:
        return None
    return {
        "action": "propose_candidate",
        "intent": intents[0],
        "kind": expected_kind,
        "proposal": proposal,
        "reason": _environment_bundle_reason(bundle),
        "confidence": 0.9,
        "bundle_id": str(bundle.get("bundle_id", "")).strip(),
    }


def _normalize_learning_candidate(raw: dict[str, Any], bundle: dict[str, Any]) -> dict[str, Any]:
    proposal = raw.get("proposal", {})
    if not isinstance(proposal, dict):
        proposal = {}
    return {
        "action": str(raw.get("action", "reject_learning")).strip() or "reject_learning",
        "intent": str(raw.get("intent", "")).strip(),
        "kind": str(raw.get("kind", "")).strip(),
        "proposal": proposal,
        "reason": str(raw.get("reason", "")).strip(),
        "alternate_intent": str(raw.get("alternate_intent", "")).strip(),
        "alternate_kind": str(raw.get("alternate_kind", "")).strip(),
        "alternate_proposal": raw.get("alternate_proposal", {}) if isinstance(raw.get("alternate_proposal", {}), dict) else {},
        "confidence": raw.get("confidence", 0.5),
        "bundle_id": str(bundle.get("bundle_id", "")).strip(),
    }


def _expected_kind(bundle: dict[str, Any]) -> str:
    return EXPECTED_KIND_BY_DOMAIN.get(str(bundle.get("domain", "")).strip(), "")


def _bundle_expected_proposal(bundle: dict[str, Any]) -> dict[str, Any]:
    env = bundle.get("environment_evidence", {}) if isinstance(bundle.get("environment_evidence", {}), dict) else {}
    domain = str(bundle.get("domain", "")).strip()
    if domain == "linux_auth":
        return {
            "preferred_index": str(env.get("preferred_index", "")).strip() or "linux",
            "preferred_sources": _proposal_values(env, "preferred_sources"),
            "preferred_sourcetypes": _proposal_values(env, "preferred_sourcetypes"),
        }
    if domain == "windows_auth":
        return {
            "preferred_fields": _proposal_values(env, "available_fields"),
        }
    if domain == "apache_web":
        return {
            "preferred_fields": _proposal_values(env, "available_fields"),
        }
    if domain == "cross_platform_auth":
        return {
            "cross_platform_pivot_hint": "Consider analyzing logs from both Linux and Windows platforms for failed login activities."
        }
    return {}


def _normalize_proposal_for_bundle(bundle: dict[str, Any], kind: str, proposal: dict[str, Any]) -> dict[str, Any]:
    env = bundle.get("environment_evidence", {}) if isinstance(bundle.get("environment_evidence", {}), dict) else {}
    normalized: dict[str, Any] = {}
    kind = str(kind).strip()
    if kind == "preferred_sources":
        preferred_sources = _proposal_values(proposal, "preferred_sources") or _proposal_values(proposal, "sources")
        preferred_sourcetypes = _proposal_values(proposal, "preferred_sourcetypes") or _proposal_values(proposal, "sourcetypes")
        preferred_index = str(proposal.get("preferred_index", env.get("preferred_index", ""))).strip()
        if preferred_index:
            normalized["preferred_index"] = preferred_index
        if preferred_sources:
            normalized["preferred_sources"] = preferred_sources
        if preferred_sourcetypes:
            normalized["preferred_sourcetypes"] = preferred_sourcetypes
        return normalized
    if kind == "preferred_fields":
        preferred_fields = _proposal_values(proposal, "preferred_fields") or _proposal_values(proposal, "fields")
        if preferred_fields:
            normalized["preferred_fields"] = preferred_fields
        return normalized
    if kind == "preferred_filters":
        filters = proposal.get("preferred_filters", proposal.get("filters", []))
        if isinstance(filters, list) and filters:
            normalized["preferred_filters"] = filters
        return normalized
    if kind == "post_result_pivot_hint":
        hint = str(proposal.get("cross_platform_pivot_hint", proposal.get("pivot_hint", ""))).strip()
        if hint:
            normalized["cross_platform_pivot_hint"] = hint
        return normalized
    return normalized


def _finalize_candidate_for_bundle(bundle: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    expected_kind = _expected_kind(bundle)
    intent = str(candidate.get("intent", "")).strip()
    kind = str(candidate.get("kind", "")).strip()
    proposal = candidate.get("proposal", {}) if isinstance(candidate.get("proposal", {}), dict) else {}
    if expected_kind:
        kind = expected_kind
    proposal = _normalize_proposal_for_bundle(bundle, kind, proposal)
    if not proposal:
        proposal = _bundle_expected_proposal(bundle)
    proposal, _ = _sanitize_learning_proposal(kind, proposal)
    return {
        **candidate,
        "intent": intent,
        "kind": kind,
        "proposal": proposal,
    }


def _planner_decision(bundle: dict[str, Any], models: dict[str, str]) -> dict[str, Any]:
    system = (
        "You are the learning planner in a guarded local-learning workflow for A.G.E.N.T. Smith. "
        "Decide whether the supplied local environment evidence justifies a typed learning suggestion. "
        "Allowed actions: propose_candidate, propose_alternate, reject_learning. "
        "Allowed kinds: preferred_sources, preferred_fields, preferred_filters, post_result_pivot_hint. "
        "You may only target intents listed in candidate_intents for this bundle. "
        "Do not overfit broad cross-platform intents to one platform. "
        "If the target intent is broad, prefer reject_learning or a cross-platform pivot hint instead of a platform-exclusive source memory. "
        "Return JSON keys: action, intent, kind, reason, confidence, alternate_intent, alternate_kind, alternate_proposal."
    )
    payload = {
        "bundle": bundle,
        "broad_intents": sorted(BROAD_INTENTS),
        "allowed_kinds": sorted(ALLOWED_KINDS),
        "intent_domains": INTENT_TO_DOMAIN,
    }
    try:
        return _normalize_learning_candidate(
            _call_ollama_json(
                model=models["planner"],
                system_prompt=system,
                user_payload=payload,
                timeout=LEARNING_MODEL_TIMEOUT_SECONDS,
            ),
            bundle,
        )
    except Exception as exc:
        return {
            "action": "reject_learning",
            "intent": "",
            "kind": "",
            "proposal": {},
            "reason": f"learning_planner_exception:{type(exc).__name__}:{exc}",
            "alternate_intent": "",
            "alternate_kind": "",
            "alternate_proposal": {},
            "confidence": 0.0,
            "bundle_id": str(bundle.get("bundle_id", "")).strip(),
        }


def _writer_candidate(bundle: dict[str, Any], planner: dict[str, Any], models: dict[str, str]) -> dict[str, Any]:
    if planner.get("action") == "reject_learning":
        return planner
    if bundle.get("domain") == "cross_platform_auth":
        default_hint = {
            "cross_platform_pivot_hint": "Consider analyzing logs from both Linux and Windows platforms for failed login activities."
        }
    else:
        default_hint = {}
    system = (
        "You are the learning writer in a guarded local-learning workflow for A.G.E.N.T. Smith. "
        "Draft one typed learning candidate from the supplied local evidence and planner decision. "
        "Only use allowed kinds. Only reference facts present in the evidence bundle. "
        "You may only target intents listed in candidate_intents for this bundle. "
        "If action is propose_alternate, write the alternate candidate instead of the rejected primary one. "
        "When the bundle domain is cross_platform_auth and the intent is failed_login_activity, "
        "the proposal must include a non-empty cross_platform_pivot_hint string. "
        "Return JSON keys: action, intent, kind, proposal, reason, confidence."
    )
    payload = {
        "bundle": bundle,
        "planner_decision": planner,
        "allowed_kinds": sorted(ALLOWED_KINDS),
        "default_hint": default_hint,
    }
    try:
        raw = _call_ollama_json(
            model=models["writer"],
            system_prompt=system,
            user_payload=payload,
            timeout=LEARNING_MODEL_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        return {
            "action": "reject_learning",
            "intent": "",
            "kind": "",
            "proposal": {},
            "reason": f"learning_writer_exception:{type(exc).__name__}:{exc}",
            "confidence": 0.0,
            "bundle_id": planner.get("bundle_id", ""),
        }
    candidate = {
        "action": str(raw.get("action", planner.get("action", "reject_learning"))).strip() or "reject_learning",
        "intent": str(raw.get("intent", planner.get("alternate_intent") if planner.get("action") == "propose_alternate" else planner.get("intent", ""))).strip(),
        "kind": str(raw.get("kind", planner.get("alternate_kind") if planner.get("action") == "propose_alternate" else planner.get("kind", ""))).strip(),
        "proposal": raw.get("proposal", default_hint) if isinstance(raw.get("proposal", default_hint), dict) else default_hint,
        "reason": str(raw.get("reason", planner.get("reason", ""))).strip(),
        "confidence": raw.get("confidence", planner.get("confidence", 0.5)),
        "bundle_id": planner.get("bundle_id", ""),
    }
    return _finalize_candidate_for_bundle(bundle, candidate)


def _review_candidate(bundle: dict[str, Any], planner: dict[str, Any], writer: dict[str, Any], models: dict[str, str]) -> dict[str, Any]:
    if writer.get("action") == "reject_learning":
        return {"approved": False, "reason": writer.get("reason", "rejected"), "candidate": writer}
    candidate_intents = set(bundle.get("candidate_intents", []))
    writer_intent = str(writer.get("intent", "")).strip()
    if writer_intent in candidate_intents and writer_intent not in BROAD_INTENTS:
        return {"approved": True, "reason": str(writer.get("reason", "")).strip(), "candidate": writer}
    system = (
        "You are the reviewer in a guarded local-learning workflow for A.G.E.N.T. Smith. "
        "Reject over-broad memories, especially when a broad cross-platform intent is being narrowed to one platform. "
        "Do not reject a candidate simply because it is platform-specific when the bundle itself is platform-specific and the candidate intent is explicitly allowed for that bundle. "
        "If the candidate is close but wrongly scoped, you may revise it to a safer alternate. "
        "You may only target intents listed in candidate_intents for this bundle. "
        "Return JSON keys: approved, reason, revised_intent, revised_kind, revised_proposal, confidence."
    )
    payload = {
        "bundle": bundle,
        "planner_decision": planner,
        "writer_candidate": writer,
        "broad_intents": sorted(BROAD_INTENTS),
        "allowed_kinds": sorted(ALLOWED_KINDS),
        "intent_domains": INTENT_TO_DOMAIN,
    }
    try:
        raw = _call_ollama_json(
            model=models["reviewer"],
            system_prompt=system,
            user_payload=payload,
            timeout=LEARNING_MODEL_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        return {"approved": False, "reason": f"learning_reviewer_exception:{type(exc).__name__}:{exc}", "candidate": writer}
    candidate = {
        "action": "propose_candidate",
        "intent": str(raw.get("revised_intent", writer.get("intent", ""))).strip(),
        "kind": str(raw.get("revised_kind", writer.get("kind", ""))).strip(),
        "proposal": raw.get("revised_proposal", writer.get("proposal", {})) if isinstance(raw.get("revised_proposal", writer.get("proposal", {})), dict) else writer.get("proposal", {}),
        "reason": str(raw.get("reason", writer.get("reason", ""))).strip(),
        "confidence": raw.get("confidence", writer.get("confidence", 0.5)),
        "bundle_id": writer.get("bundle_id", ""),
    }
    return {"approved": bool(raw.get("approved", False)), "reason": str(raw.get("reason", "")).strip(), "candidate": _finalize_candidate_for_bundle(bundle, candidate)}


def _proposal_values(proposal: dict[str, Any], key: str) -> list[str]:
    values = proposal.get(key, [])
    if isinstance(values, str):
        values = [values]
    if isinstance(values, list):
        cleaned = [str(item).strip() for item in values if str(item).strip()]
        if "sourcetype" in str(key).lower():
            cleaned = [item for item in cleaned if not _is_legacy_sourcetype(item)]
        return cleaned
    return []


def _reason_has_timeout(reason: str) -> bool:
    text = str(reason or "").strip().lower()
    return any(token in text for token in TIMEOUT_TOKENS)


def _is_environment_bundle(bundle: dict[str, Any]) -> bool:
    return str(bundle.get("bundle_id", "")).strip().endswith("_environment")


def _fallback_candidate_for_bundle(bundle: dict[str, Any], reason: str) -> dict[str, Any] | None:
    if not _is_environment_bundle(bundle):
        return None
    expected_kind = _expected_kind(bundle)
    proposal = _bundle_expected_proposal(bundle)
    intents = [str(item).strip() for item in bundle.get("candidate_intents", []) if str(item).strip()]
    if not expected_kind or not proposal or not intents:
        return None
    return {
        "action": "propose_candidate",
        "intent": intents[0],
        "kind": expected_kind,
        "proposal": proposal,
        "reason": (
            "Deterministic fallback from environment evidence after remote model timeout. "
            f"Original reviewer path: {reason}"
        ),
        "confidence": 0.55,
        "bundle_id": str(bundle.get("bundle_id", "")).strip(),
    }


def _record_as_approved(row: dict[str, Any]) -> dict[str, Any]:
    approved = dict(row)
    approved["status"] = "approved"
    return approved


def _load_writer_benchmark_cases(target_intents: list[str]) -> list[dict[str, Any]]:
    if not WRITER_BENCHMARK_CASES.exists():
        return []
    try:
        raw = json.loads(WRITER_BENCHMARK_CASES.read_text(encoding="utf-8"))
    except Exception:
        return []
    rows = raw if isinstance(raw, list) else []
    allow = {str(item).strip() for item in target_intents if str(item).strip()}
    per_intent: dict[str, int] = {}
    selected: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        intent = str(row.get("expected_intent", "")).strip()
        if intent not in allow:
            continue
        if int(per_intent.get(intent, 0)) >= MAX_LEARNING_BENCHMARK_CASES_PER_INTENT:
            continue
        selected.append(row)
        per_intent[intent] = int(per_intent.get(intent, 0)) + 1
        if len(selected) >= MAX_LEARNING_BENCHMARK_CASES:
            break
    return selected


def _extract_query_shape(query: str) -> str:
    lower = str(query or "").lower()
    if "| table " in lower:
        return "table"
    if "| timechart " in lower:
        return "timechart"
    if "earliest(_time)" in lower or "first_seen" in lower:
        return "first_seen"
    if "| stats " in lower:
        return "stats"
    return "unknown"


def _score_writer_case(case: dict[str, Any], *, actual_intent: str, query_args: dict[str, Any], policy_ok: bool, policy_reason: str) -> dict[str, Any]:
    from intent_field_contracts import validate_query_for_intent

    query = str(query_args.get("query", "")).strip()
    lower = query.lower()
    findings: list[str] = []
    score = 0
    contract_ok, contract_reason = validate_query_for_intent(actual_intent, query_args)
    expected_intent = str(case.get("expected_intent", "")).strip()
    required_terms = [str(item).strip() for item in case.get("required_query_terms", []) if str(item).strip()]
    forbidden_terms = [str(item).strip() for item in case.get("forbidden_query_terms", []) if str(item).strip()]
    preferred_indexes = [str(item).strip() for item in case.get("preferred_indexes", []) if str(item).strip()]
    preferred_sourcetypes = [str(item).strip() for item in case.get("preferred_sourcetypes", []) if str(item).strip()]
    expected_shape = str(case.get("expected_shape", "")).strip()
    expected_earliest = str(case.get("expected_earliest_time", "")).strip()
    expected_latest = str(case.get("expected_latest_time", "")).strip()

    if actual_intent == expected_intent:
        score += 25
    else:
        findings.append(f"intent_mismatch:{actual_intent}->{expected_intent}")

    if policy_ok:
        score += 20
    else:
        findings.append(f"policy_fail:{policy_reason}")

    if required_terms:
        hits = sum(1 for term in required_terms if term.lower() in lower)
        score += int((hits / len(required_terms)) * 20)
        if hits < len(required_terms):
            findings.append(f"required_query_terms:{hits}/{len(required_terms)}")
    else:
        score += 20

    forbidden_present = [term for term in forbidden_terms if term.lower() in lower]
    if forbidden_present:
        findings.append("forbidden_terms_present:" + ",".join(forbidden_present))
    else:
        score += 10

    if preferred_indexes:
        hits = sum(1 for term in preferred_indexes if term.lower() in lower)
        score += int((hits / len(preferred_indexes)) * 5)
        if hits < len(preferred_indexes):
            findings.append("preferred_indexes_missing")
    else:
        score += 5

    if preferred_sourcetypes:
        hits = sum(1 for term in preferred_sourcetypes if term.lower() in lower)
        score += int((hits / len(preferred_sourcetypes)) * 5)
        if hits < len(preferred_sourcetypes):
            findings.append("preferred_sourcetypes_missing")
    else:
        score += 5

    actual_shape = _extract_query_shape(query)
    if actual_shape == expected_shape:
        score += 10
    else:
        findings.append(f"shape_mismatch:{actual_shape}->{expected_shape}")

    if contract_ok:
        score += 5
    else:
        findings.append(f"intent_contract_fail:{contract_reason}")

    if expected_earliest:
        if str(query_args.get("earliest_time", "")).strip() == expected_earliest:
            score += 5
        else:
            findings.append("time_mismatch_earliest")
    if expected_latest:
        if str(query_args.get("latest_time", "")).strip() == expected_latest:
            score += 5
        else:
            findings.append("time_mismatch_latest")

    return {
        "score": max(0, min(100, score)),
        "findings": findings,
        "failure_class": findings[0] if findings else "pass",
        "query_shape": actual_shape,
        "query": query,
    }


def _filter_snapshot(snapshot: dict[str, Any], target_intents: list[str]) -> dict[str, Any]:
    allow = {str(item).strip() for item in target_intents if str(item).strip()}
    rows = [
        row for row in snapshot.get("results", [])
        if isinstance(row, dict) and str(row.get("expected_intent", "")).strip() in allow
    ]
    scores = [int(row.get("score", 0) or 0) for row in rows]
    avg_score = round(sum(scores) / max(1, len(scores)), 2) if rows else 0.0
    pass_rate_pct = round((sum(1 for score in scores if score >= 85) / max(1, len(scores))) * 100, 2) if rows else 0.0
    return {
        "label": str(snapshot.get("label", "")).strip(),
        "timestamp_utc": str(snapshot.get("timestamp_utc", "")).strip() or _utc_now(),
        "case_count": len(rows),
        "target_intents": sorted(allow),
        "avg_score": avg_score,
        "pass_rate_pct": pass_rate_pct,
        "results": rows,
    }


def _candidate_writer_target_intents(candidate: dict[str, Any], benchmark_target_intents: list[str]) -> list[str]:
    intent = str(candidate.get("intent", "")).strip()
    kind = str(candidate.get("kind", "")).strip()
    if not intent or kind not in {"preferred_sources", "preferred_fields", "preferred_filters"}:
        return []
    allow = {str(item).strip() for item in benchmark_target_intents if str(item).strip()}
    impacted = {intent}
    domain = INTENT_TO_DOMAIN.get(intent, "")
    if domain:
        impacted.update(key for key, value in INTENT_TO_DOMAIN.items() if value == domain)
    if domain in {"linux_auth", "windows_auth"}:
        impacted.add("failed_login_activity")
    return sorted(item for item in impacted if item in allow)


def _run_writer_quality_snapshot(
    *,
    target_intents: list[str],
    approved_records: list[dict[str, Any]],
    label: str,
    progress_cb: callable | None = None,
    start_pct: int = 82,
    end_pct: int = 90,
    phase: str = "benchmarking_cases",
    cache_metrics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    import langgraph_multi_model_soc as mm
    from query_policy import validate_query_args

    cases = _load_writer_benchmark_cases(target_intents)
    models = _runtime_models()
    case_ids = [str(case.get("id", "")).strip() for case in cases if isinstance(case, dict)]
    cache_key = json.dumps(
        {
            "target_intents": sorted(str(item).strip() for item in target_intents if str(item).strip()),
            "approved_signature": _approved_record_signature(approved_records),
            "case_ids": case_ids,
            "planner_model": models.get("planner", ""),
            "writer_model": models.get("writer", ""),
        },
        sort_keys=True,
    )
    cache_hash = hashlib.sha256(cache_key.encode("utf-8")).hexdigest()
    cache = _load_learning_benchmark_cache()
    cached_entry = (cache.get("entries", {}) or {}).get(cache_hash) if isinstance(cache, dict) else None
    if isinstance(cached_entry, dict):
        snapshot = dict(cached_entry)
        snapshot["label"] = label
        snapshot["timestamp_utc"] = _utc_now()
        snapshot["cached"] = True
        if isinstance(cache_metrics, dict):
            cache_metrics["hits"] = int(cache_metrics.get("hits", 0) or 0) + 1
            labels = cache_metrics.setdefault("labels", [])
            if isinstance(labels, list):
                labels.append(f"{label}:hit")
        return snapshot
    if isinstance(cache_metrics, dict):
        cache_metrics["misses"] = int(cache_metrics.get("misses", 0) or 0) + 1
        labels = cache_metrics.setdefault("labels", [])
        if isinstance(labels, list):
            labels.append(f"{label}:miss")

    rows: list[dict[str, Any]] = []
    total = max(1, len(cases))
    with learning_record_override(approved_records), _learning_benchmark_timeout_override(mm, LEARNING_MODEL_TIMEOUT_SECONDS):
        for idx, case in enumerate(cases, start=1):
            if progress_cb:
                pct = start_pct + int((idx - 1) / total * max(1, end_pct - start_pct))
                progress_cb(
                    f"Benchmarking {label} case {idx}/{total}: {str(case.get('id', '')).strip() or 'case'}",
                    pct,
                    phase,
                )
            question = str(case.get("question", "")).strip()
            planner_state = mm.planner_node({"question": question})
            writer_state = mm.writer_node({"question": question, "planner_output": planner_state.get("planner_output", {})})
            writer_output = writer_state.get("writer_output", {}) or {}
            actual_intent = str(writer_output.get("intent", "")).strip() or "unknown"
            query_args = writer_output.get("tool_args", {}) if isinstance(writer_output.get("tool_args", {}), dict) else {}
            policy_ok, policy_reason = validate_query_args(query_args, question=question)
            scored = _score_writer_case(case, actual_intent=actual_intent, query_args=query_args, policy_ok=policy_ok, policy_reason=policy_reason)
            rows.append(
                {
                    "id": str(case.get("id", "")).strip(),
                    "question": question,
                    "expected_intent": str(case.get("expected_intent", "")).strip(),
                    "actual_intent": actual_intent,
                    "score": int(scored["score"]),
                    "query": scored["query"],
                    "query_shape": scored["query_shape"],
                    "findings": scored["findings"],
                    "failure_class": scored["failure_class"],
                }
            )
    scores = [int(row["score"]) for row in rows]
    avg_score = round(sum(scores) / max(1, len(scores)), 2) if rows else 0.0
    pass_rate_pct = round((sum(1 for score in scores if score >= 85) / max(1, len(scores))) * 100, 2) if rows else 0.0
    snapshot = {
        "label": label,
        "timestamp_utc": _utc_now(),
        "case_count": len(rows),
        "target_intents": target_intents,
        "avg_score": avg_score,
        "pass_rate_pct": pass_rate_pct,
        "results": rows,
        "cached": False,
    }
    _store_writer_quality_snapshot_cache(
        target_intents=target_intents,
        approved_records=approved_records,
        snapshot=snapshot,
    )
    return snapshot


def _store_writer_quality_snapshot_cache(
    *,
    target_intents: list[str],
    approved_records: list[dict[str, Any]],
    snapshot: dict[str, Any],
) -> None:
    cases = _load_writer_benchmark_cases(target_intents)
    models = _runtime_models()
    case_ids = [str(case.get("id", "")).strip() for case in cases if isinstance(case, dict)]
    cache_key = json.dumps(
        {
            "target_intents": sorted(str(item).strip() for item in target_intents if str(item).strip()),
            "approved_signature": _approved_record_signature(approved_records),
            "case_ids": case_ids,
            "planner_model": models.get("planner", ""),
            "writer_model": models.get("writer", ""),
        },
        sort_keys=True,
    )
    cache_hash = hashlib.sha256(cache_key.encode("utf-8")).hexdigest()
    cache = _load_learning_benchmark_cache()
    entries = cache.get("entries", {}) if isinstance(cache, dict) else {}
    if not isinstance(entries, dict):
        entries = {}
    entries[cache_hash] = {
        "label": str(snapshot.get("label", "")).strip(),
        "timestamp_utc": str(snapshot.get("timestamp_utc", "")).strip() or _utc_now(),
        "case_count": int(snapshot.get("case_count", 0) or 0),
        "target_intents": list(snapshot.get("target_intents", target_intents)),
        "avg_score": float(snapshot.get("avg_score", 0.0) or 0.0),
        "pass_rate_pct": float(snapshot.get("pass_rate_pct", 0.0) or 0.0),
        "results": list(snapshot.get("results", [])),
    }
    ordered = list(entries.items())[-64:]
    _save_learning_benchmark_cache({"entries": dict(ordered)})


def _compare_writer_snapshots(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    previous_results = {str(row.get("id", "")): row for row in previous.get("results", []) if isinstance(row, dict)}
    changed_cases: list[dict[str, Any]] = []
    improved = 0
    regressed = 0
    for row in current.get("results", []):
        if not isinstance(row, dict):
            continue
        prev = previous_results.get(str(row.get("id", "")))
        if not isinstance(prev, dict):
            continue
        previous_score = int(prev.get("score", 0) or 0)
        current_score = int(row.get("score", 0) or 0)
        if previous_score == current_score:
            continue
        delta = current_score - previous_score
        changed_cases.append(
            {
                "id": str(row.get("id", "")).strip(),
                "previous_score": previous_score,
                "current_score": current_score,
                "delta": delta,
            }
        )
        if delta > 0:
            improved += 1
        elif delta < 0:
            regressed += 1
    return {
        "baseline_avg_score": float(previous.get("avg_score", 0.0) or 0.0),
        "current_avg_score": float(current.get("avg_score", 0.0) or 0.0),
        "avg_score_delta": round(float(current.get("avg_score", 0.0) or 0.0) - float(previous.get("avg_score", 0.0) or 0.0), 2),
        "baseline_pass_rate_pct": float(previous.get("pass_rate_pct", 0.0) or 0.0),
        "current_pass_rate_pct": float(current.get("pass_rate_pct", 0.0) or 0.0),
        "pass_rate_delta_pct": round(float(current.get("pass_rate_pct", 0.0) or 0.0) - float(previous.get("pass_rate_pct", 0.0) or 0.0), 2),
        "improved_case_count": improved,
        "regressed_case_count": regressed,
        "changed_cases": sorted(changed_cases, key=lambda item: item["delta"], reverse=True),
    }


def _snapshot_targets_match(snapshot: dict[str, Any], target_intents: list[str]) -> bool:
    snap_targets = {str(item).strip() for item in snapshot.get("target_intents", []) if str(item).strip()}
    wanted = {str(item).strip() for item in target_intents if str(item).strip()}
    return bool(snap_targets) and snap_targets == wanted


def _snapshot_tuple(snapshot: dict[str, Any]) -> tuple[float, float, int]:
    return (
        float(snapshot.get("avg_score", 0.0) or 0.0),
        float(snapshot.get("pass_rate_pct", 0.0) or 0.0),
        int(snapshot.get("case_count", 0) or 0),
    )


def _select_improving_candidates(
    *,
    candidates: list[dict[str, Any]],
    approved_records: list[dict[str, Any]],
    target_intents: list[str],
    baseline_snapshot: dict[str, Any],
    progress_cb: callable | None = None,
    log_cb: callable | None = None,
    cache_metrics: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    baseline = baseline_snapshot
    selected: list[dict[str, Any]] = []
    approved_fingerprints = {_learning_record_fingerprint(row) for row in approved_records if isinstance(row, dict)}
    seen_candidate_fingerprints: set[str] = set()
    total = max(1, len(candidates))
    for idx, row in enumerate(candidates, start=1):
        if progress_cb:
            progress_cb(f"Benchmarking learning candidate {idx}/{total} against SPL-writing cases...", 82 + int((idx / total) * 10), "benchmarking_candidates")
        fingerprint = _learning_record_fingerprint(row)
        if fingerprint in approved_fingerprints:
            row["benchmark_impact"] = {
                "avg_score_delta": 0.0,
                "pass_rate_delta_pct": 0.0,
                "improved_case_count": 0,
                "regressed_case_count": 0,
                "writer_scope": "already_approved",
            }
            row["selection_reason"] = "already_approved"
            if log_cb:
                log_cb(
                    f"[learning] skipped candidate intent={row.get('intent')} kind={row.get('kind')} "
                    "reason=already_approved"
                )
            continue
        if fingerprint in seen_candidate_fingerprints:
            row["benchmark_impact"] = {
                "avg_score_delta": 0.0,
                "pass_rate_delta_pct": 0.0,
                "improved_case_count": 0,
                "regressed_case_count": 0,
                "writer_scope": "duplicate_candidate",
            }
            row["selection_reason"] = "duplicate_candidate"
            if log_cb:
                log_cb(
                    f"[learning] skipped candidate intent={row.get('intent')} kind={row.get('kind')} "
                    "reason=duplicate_candidate"
                )
            continue
        seen_candidate_fingerprints.add(fingerprint)
        relevant_intents = _candidate_writer_target_intents(row, target_intents)
        row["benchmark_scope_intents"] = relevant_intents
        if not relevant_intents:
            row["benchmark_impact"] = {
                "baseline_avg_score": 0.0,
                "trial_avg_score": 0.0,
                "avg_score_delta": 0.0,
                "trial_pass_rate_pct": 0.0,
                "pass_rate_delta_pct": 0.0,
                "improved_case_count": 0,
                "regressed_case_count": 0,
                "writer_scope": "non_writer_hint",
            }
            row["selection_reason"] = "non_writer_hint"
            if log_cb:
                log_cb(
                    f"[learning] skipped candidate intent={row.get('intent')} kind={row.get('kind')} "
                    "reason=does_not_directly_change_spl_writer"
                )
            continue
        trial_records = approved_records + [_record_as_approved(item) for item in selected] + [_record_as_approved(row)]
        current_records = approved_records + [_record_as_approved(item) for item in selected]
        current_subset = _run_writer_quality_snapshot(
            target_intents=relevant_intents,
            approved_records=current_records,
            label=f"current_{idx}",
            progress_cb=None,
            cache_metrics=cache_metrics,
        ) if selected else _filter_snapshot(baseline, relevant_intents)
        trial = _run_writer_quality_snapshot(
            target_intents=relevant_intents,
            approved_records=trial_records,
            label=f"trial_{idx}",
            progress_cb=progress_cb,
            start_pct=88 + int(((idx - 1) / total) * 4),
            end_pct=88 + int((idx / total) * 4),
            phase="benchmarking_candidates",
            cache_metrics=cache_metrics,
        )
        delta = _compare_writer_snapshots(current_subset, trial)
        row["benchmark_impact"] = {
            "baseline_avg_score": float(current_subset.get("avg_score", 0.0) or 0.0),
            "trial_avg_score": float(trial.get("avg_score", 0.0) or 0.0),
            "avg_score_delta": float(delta.get("avg_score_delta", 0.0) or 0.0),
            "trial_pass_rate_pct": float(trial.get("pass_rate_pct", 0.0) or 0.0),
            "pass_rate_delta_pct": float(delta.get("pass_rate_delta_pct", 0.0) or 0.0),
            "improved_case_count": int(delta.get("improved_case_count", 0) or 0),
            "regressed_case_count": int(delta.get("regressed_case_count", 0) or 0),
            "writer_scope": ",".join(relevant_intents),
        }
        if _snapshot_tuple(trial) > _snapshot_tuple(current_subset):
            selected.append(row)
            row["selection_reason"] = "improved_writer_quality"
            if log_cb:
                log_cb(
                    f"[learning] kept candidate intent={row.get('intent')} kind={row.get('kind')} "
                    f"avg_delta={row['benchmark_impact']['avg_score_delta']} pass_delta={row['benchmark_impact']['pass_rate_delta_pct']}"
                )
        elif log_cb:
            row["selection_reason"] = "no_gain"
            log_cb(
                f"[learning] skipped candidate intent={row.get('intent')} kind={row.get('kind')} "
                f"avg_delta={row['benchmark_impact']['avg_score_delta']} pass_delta={row['benchmark_impact']['pass_rate_delta_pct']}"
            )
    final_snapshot = _run_writer_quality_snapshot(
        target_intents=target_intents,
        approved_records=approved_records + [_record_as_approved(item) for item in selected],
        label="selected_final",
        progress_cb=progress_cb,
        start_pct=92,
        end_pct=96,
        phase="benchmarking_candidates",
        cache_metrics=cache_metrics,
    )
    if _snapshot_tuple(final_snapshot) < _snapshot_tuple(baseline):
        if log_cb:
            log_cb("[learning] selected candidates regressed the full benchmark; discarding them")
        return [], baseline, baseline
    return selected, baseline, final_snapshot


def _deterministic_validate_learning(bundle: dict[str, Any], candidate: dict[str, Any]) -> tuple[bool, str]:
    candidate = _finalize_candidate_for_bundle(bundle, candidate)
    intent = str(candidate.get("intent", "")).strip()
    kind = str(candidate.get("kind", "")).strip()
    proposal = candidate.get("proposal", {})
    if not intent or not kind or kind not in ALLOWED_KINDS or not isinstance(proposal, dict):
        return False, "invalid_intent_or_kind"
    if not proposal:
        return False, "empty_proposal"
    if intent not in set(bundle.get("candidate_intents", [])):
        return False, "intent_not_supported"
    if intent in BROAD_INTENTS and kind == "preferred_sources":
        if _proposal_values(proposal, "preferred_sources") or _proposal_values(proposal, "preferred_sourcetypes"):
            return False, "broad_intent_cannot_take_platform_exclusive_sources"
    if bundle.get("domain") == "cross_platform_auth" and intent == "failed_login_activity" and kind == "post_result_pivot_hint":
        hint = str(proposal.get("cross_platform_pivot_hint", "")).strip()
        if not hint:
            return False, "empty_cross_platform_pivot_hint"
    if bundle.get("domain") == "windows_auth" and kind != "preferred_fields":
        return False, "windows_auth_must_learn_fields"
    if bundle.get("domain") == "apache_web" and kind != "preferred_fields":
        return False, "apache_web_must_learn_fields"
    if bundle.get("domain") == "linux_auth" and kind != "preferred_sources":
        return False, "linux_auth_must_learn_sources"
    env = bundle.get("environment_evidence", {})
    allowed_sources = set(_proposal_values(env, "preferred_sources"))
    allowed_sourcetypes = set(_proposal_values(env, "preferred_sourcetypes"))
    allowed_fields = set(_proposal_values(env, "available_fields"))
    proposal_sources = set(_proposal_values(proposal, "preferred_sources"))
    proposal_sourcetypes = set(_proposal_values(proposal, "preferred_sourcetypes"))
    proposal_fields = set(_proposal_values(proposal, "preferred_fields"))
    if proposal_sources and allowed_sources and not proposal_sources.issubset(allowed_sources):
        return False, "proposal_references_unknown_sources"
    if proposal_sourcetypes and allowed_sourcetypes and not proposal_sourcetypes.issubset(allowed_sourcetypes):
        return False, "proposal_references_unknown_sourcetypes"
    if proposal_fields and allowed_fields and not proposal_fields.issubset(allowed_fields):
        return False, "proposal_references_unknown_fields"
    return True, "ok"


def _upsert_candidates(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    registry = load_learning_registry()
    records = registry.get("records", [])
    if not isinstance(records, list):
        records = []
    by_id: dict[str, dict[str, Any]] = {}
    for row in records:
        if isinstance(row, dict) and str(row.get("id", "")).strip():
            by_id[str(row["id"])] = row
    created = 0
    proposed_ids: set[str] = set()
    for row in candidates:
        rec_id = str(row.get("id", "")).strip()
        if not rec_id:
            continue
        proposed_ids.add(rec_id)
        existing = by_id.get(rec_id)
        if existing:
            existing["updated_at"] = _utc_now()
            for key in ("reason", "supporting_question", "supporting_spl", "supporting_result_excerpt", "environment_evidence"):
                if row.get(key):
                    existing[key] = row.get(key)
        else:
            by_id[rec_id] = row
            created += 1
    stale_marked = 0
    for rec_id, row in by_id.items():
        if rec_id in proposed_ids:
            continue
        if str(row.get("status", "")).strip().lower() != "pending":
            continue
        row["status"] = "stale"
        row["updated_at"] = _utc_now()
        stale_marked += 1
    registry["records"] = list(by_id.values())
    save_learning_registry(registry)
    return {"created": created, "stale_marked": stale_marked, "total": len(registry["records"])}


def set_learning_record_status(record_id: str, status: str) -> bool:
    status_l = str(status or "").strip().lower()
    if status_l not in ALLOWED_STATUSES:
        return False
    registry = load_learning_registry()
    changed = False
    for row in registry.get("records", []):
        if not isinstance(row, dict):
            continue
        if str(row.get("id", "")).strip() != str(record_id).strip():
            continue
        row["status"] = status_l
        row["updated_at"] = _utc_now()
        changed = True
        break
    if changed:
        save_learning_registry(registry)
    return changed


def generate_self_learn_candidates(
    progress_cb: callable | None = None,
    log_cb: callable | None = None,
) -> dict[str, Any]:
    run_started = time.time()
    profile = load_environment_profile(ENV_PROFILE_PATH)
    audit = _load_query_audit(MAX_LEARNING_AUDIT_ENTRIES)
    bundles = _build_learning_evidence(profile, audit)
    models = _runtime_models()
    approved_records = approved_learning_records()
    approved_state = _approved_learning_state_summary(approved_records)
    candidates: list[dict[str, Any]] = []
    considered = 0
    total = max(1, len(bundles))
    timeout_warning_count = 0
    cache_metrics: dict[str, Any] = {"hits": 0, "misses": 0, "labels": []}
    deterministic_covered_intents: set[str] = set()

    def _progress(detail: str, pct: int, phase: str) -> None:
        if progress_cb:
            try:
                progress_cb(detail, pct, phase)
            except Exception:
                pass

    def _log(line: str) -> None:
        if log_cb:
            try:
                log_cb(line)
            except Exception:
                pass

    _progress("Collecting local evidence for guarded learning...", 8, "collecting_evidence")
    _log(f"[learning] evidence bundles discovered: {len(bundles)}")
    for bundle in bundles:
        considered += 1
        start_pct = 12 + int(((considered - 1) / total) * 72)
        end_pct = 12 + int((considered / total) * 72)
        _progress(
            f"Reviewing bundle {considered}/{total}: {bundle.get('bundle_id', 'bundle')}",
            start_pct,
            "reviewing_bundle",
        )
        _log(f"[learning] bundle {considered}/{total}: {bundle.get('bundle_id', 'bundle')} domain={bundle.get('domain', 'unknown')}")
        bundle_intents = {
            str(item).strip() for item in bundle.get("candidate_intents", [])
            if str(item).strip()
        }
        if not _is_environment_bundle(bundle) and bundle_intents and bundle_intents.issubset(deterministic_covered_intents):
            _progress(
                f"Skipping redundant audit bundle {bundle.get('bundle_id', 'bundle')}",
                end_pct,
                "reviewing_bundle",
            )
            _log(
                f"[learning] skipped audit bundle {bundle.get('bundle_id', 'bundle')} "
                "reason=covered_by_environment_bundle"
            )
            continue
        deterministic_candidate = _deterministic_environment_candidate(bundle)
        if deterministic_candidate:
            ok, reason = _deterministic_validate_learning(bundle, deterministic_candidate)
            if ok:
                deterministic_covered_intents.add(str(deterministic_candidate.get("intent", "")).strip())
                candidates.append(
                    _candidate(
                        intent=str(deterministic_candidate.get("intent", "")).strip(),
                        kind=str(deterministic_candidate.get("kind", "")).strip(),
                        proposal=deterministic_candidate.get("proposal", {}),
                        reason=str(deterministic_candidate.get("reason", reason)).strip() or reason,
                        supporting_question=str(bundle.get("supporting_question", "")).strip(),
                        supporting_spl=str(bundle.get("supporting_spl", "")).strip(),
                        supporting_result_excerpt=str(bundle.get("supporting_result_excerpt", "")).strip(),
                        environment_evidence=bundle.get("environment_evidence", {}),
                    )
                )
                _progress(
                    f"Accepted deterministic candidate for {deterministic_candidate.get('intent', 'unknown_intent')}",
                    end_pct,
                    "candidate_accepted",
                )
                _log(
                    f"[learning] deterministic candidate intent={deterministic_candidate.get('intent')} "
                    f"kind={deterministic_candidate.get('kind')}"
                )
                continue
            _log(f"[learning] deterministic environment candidate rejected: {reason}")
        planner = _planner_decision(bundle, models)
        _log(f"[learning] planner action={planner.get('action')} intent={planner.get('intent')} kind={planner.get('kind')}")
        fallback_candidate = None
        planner_reason = str(planner.get("reason", "")).strip()
        if planner.get("action") == "reject_learning" and _reason_has_timeout(planner_reason):
            timeout_warning_count += 1
            fallback_candidate = _fallback_candidate_for_bundle(bundle, planner_reason)
            if fallback_candidate:
                _log(f"[learning] planner timeout fallback used for bundle: {bundle.get('bundle_id', 'bundle')}")
                review = {"approved": True, "reason": planner_reason, "candidate": fallback_candidate}
                candidate = fallback_candidate
            else:
                _log(f"[learning] planner timeout without safe fallback: {planner_reason}")
                continue
        elif planner.get("action") == "reject_learning":
            _log(f"[learning] planner rejected bundle immediately: {planner_reason or 'rejected'}")
            continue
        else:
            writer = _writer_candidate(bundle, planner, models)
            _log(f"[learning] writer action={writer.get('action')} intent={writer.get('intent')} kind={writer.get('kind')}")
            review = _review_candidate(bundle, planner, writer, models)
            candidate = review.get("candidate", {}) if isinstance(review, dict) else {}
            review_reason = review.get("reason", "rejected") if isinstance(review, dict) else "rejected"
            if (not review.get("approved", False) or not isinstance(candidate, dict)) and _reason_has_timeout(review_reason):
                timeout_warning_count += 1
                fallback_candidate = _fallback_candidate_for_bundle(bundle, review_reason)
                if fallback_candidate:
                    candidate = fallback_candidate
                    review = {"approved": True, "reason": review_reason, "candidate": candidate}
                    _log(f"[learning] reviewer timeout fallback used for bundle: {bundle.get('bundle_id', 'bundle')}")
            if not review.get("approved", False) or not isinstance(candidate, dict):
                _log(f"[learning] reviewer rejected bundle: {review_reason}")
                continue
        ok, reason = _deterministic_validate_learning(bundle, candidate)
        if not ok:
            _log(f"[learning] deterministic validation rejected candidate: {reason}")
            continue
        candidates.append(
            _candidate(
                intent=str(candidate.get("intent", "")).strip(),
                kind=str(candidate.get("kind", "")).strip(),
                proposal=candidate.get("proposal", {}),
                reason=str(review.get("reason", candidate.get("reason", reason))).strip() or reason,
                supporting_question=str(bundle.get("supporting_question", "")).strip(),
                supporting_spl=str(bundle.get("supporting_spl", "")).strip(),
                supporting_result_excerpt=str(bundle.get("supporting_result_excerpt", "")).strip(),
                environment_evidence=bundle.get("environment_evidence", {}),
            )
        )
        _progress(
            f"Accepted candidate for {candidate.get('intent', 'unknown_intent')}",
            end_pct,
            "candidate_accepted",
        )
        _log(f"[learning] accepted candidate intent={candidate.get('intent')} kind={candidate.get('kind')}")
    target_intents = sorted({
        *DEFAULT_LEARNING_BENCHMARK_INTENTS,
        *[str(row.get("intent", "")).strip() for row in approved_records if str(row.get("intent", "")).strip()],
        *[str(row.get("intent", "")).strip() for row in candidates if str(row.get("intent", "")).strip()],
    })
    prior_progress = load_learning_progress()
    cached_factory = prior_progress.get("factory_baseline", {}) if isinstance(prior_progress.get("factory_baseline", {}), dict) else {}
    if _snapshot_targets_match(cached_factory, target_intents):
        factory_baseline = cached_factory
    else:
        _progress("Benchmarking factory baseline for SPL writing...", 74, "benchmarking_factory")
        factory_baseline = _run_writer_quality_snapshot(
            target_intents=target_intents,
            approved_records=[],
            label="factory_baseline",
            progress_cb=_progress,
            start_pct=74,
            end_pct=80,
            phase="benchmarking_factory",
            cache_metrics=cache_metrics,
        )
    if approved_records:
        _progress("Benchmarking current learned state for SPL writing...", 82, "benchmarking_baseline")
        baseline_snapshot = _run_writer_quality_snapshot(
            target_intents=target_intents,
            approved_records=approved_records,
            label="baseline",
            progress_cb=_progress,
            start_pct=82,
            end_pct=88,
            phase="benchmarking_baseline",
            cache_metrics=cache_metrics,
        )
    else:
        baseline_snapshot = dict(factory_baseline)
        baseline_snapshot["label"] = "baseline"
    selected_candidates, baseline_snapshot, final_snapshot = _select_improving_candidates(
        candidates=candidates,
        approved_records=approved_records,
        target_intents=target_intents,
        baseline_snapshot=baseline_snapshot,
        progress_cb=_progress,
        log_cb=_log,
        cache_metrics=cache_metrics,
    )
    comparison = _compare_writer_snapshots(baseline_snapshot, final_snapshot)
    overall_learning_level = _compare_writer_snapshots(factory_baseline, final_snapshot)
    run_duration_sec = round(time.time() - run_started, 2)
    skipped_duplicates = sum(1 for row in candidates if str(row.get("selection_reason", "")).strip() == "duplicate_candidate")
    skipped_approved = sum(1 for row in candidates if str(row.get("selection_reason", "")).strip() == "already_approved")
    skipped_non_writer = sum(1 for row in candidates if str(row.get("selection_reason", "")).strip() == "non_writer_hint")
    skipped_no_gain = sum(1 for row in candidates if str(row.get("selection_reason", "")).strip() == "no_gain")
    progress_payload = {
        "timestamp_utc": _utc_now(),
        "target_intents": target_intents,
        "factory_baseline": factory_baseline,
        "baseline": baseline_snapshot,
        "latest": final_snapshot,
        "comparison": comparison,
        "overall_learning_level": overall_learning_level,
        "run_duration_sec": run_duration_sec,
        "approved_learning_state": approved_state,
        "cache_metrics": {
            "hits": int(cache_metrics.get("hits", 0) or 0),
            "misses": int(cache_metrics.get("misses", 0) or 0),
            "labels": list(cache_metrics.get("labels", []))[-16:],
        },
        "candidate_filtering": {
            "skipped_duplicate_count": skipped_duplicates,
            "skipped_already_approved_count": skipped_approved,
            "skipped_non_writer_count": skipped_non_writer,
            "skipped_no_gain_count": skipped_no_gain,
        },
        "selected_candidate_count": len(selected_candidates),
        "generated_candidate_count": len(candidates),
        "selected_candidates": [
            {
                "intent": str(row.get("intent", "")).strip(),
                "kind": str(row.get("kind", "")).strip(),
                "proposal": row.get("proposal", {}),
                "benchmark_impact": row.get("benchmark_impact", {}),
                "selection_reason": str(row.get("selection_reason", "")).strip(),
            }
            for row in selected_candidates
        ],
        "timeout_warnings": timeout_warning_count,
    }
    progress_payload = update_learning_progress_history(progress_payload)
    _progress("Writing guarded learning registry updates...", 92, "writing_registry")
    outcome = _upsert_candidates(selected_candidates)
    _log(
        f"[learning] complete created={outcome.get('created', 0)} "
        f"stale_marked={outcome.get('stale_marked', 0)} considered={considered} "
        f"writer_avg_delta={comparison.get('avg_score_delta', 0.0)}"
    )
    if timeout_warning_count > 0:
        _log(f"[learning] warning remote_model_timeout_count={timeout_warning_count}")
    _progress("Guarded local learning run complete.", 100, "complete")
    return {
        "created": outcome.get("created", 0),
        "stale_marked": outcome.get("stale_marked", 0),
        "considered": considered,
        "generated": len(candidates),
        "selected": len(selected_candidates),
        "timeout_warnings": timeout_warning_count,
        "improvement": progress_payload,
        "registry": learning_registry_summary(),
    }
