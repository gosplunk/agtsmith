#!/usr/bin/env python3
"""Guarded local learning artifact storage."""

from __future__ import annotations

import hashlib
import os
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from environment_profile import load_environment_profile
from runtime_config import get_ollama_host, parse_env_file

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS_ROOT = PROJECT_ROOT / "artifacts"
LEARNING_ROOT = ARTIFACTS_ROOT / "learning"
REGISTRY_PATH = LEARNING_ROOT / "local_learning_registry.json"
QUERY_AUDIT_LOG = ARTIFACTS_ROOT / "audit" / "query_runs.jsonl"
ENV_PROFILE_PATH = ARTIFACTS_ROOT / "environment" / "environment_profile_latest.json"

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
DEFAULT_MODEL_QUERY_PLANNER = "hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
DEFAULT_MODEL_QUERY_WRITER = "deepseek-coder-v2:lite"
DEFAULT_MODEL_SECURITY_REVIEWER = DEFAULT_MODEL_QUERY_PLANNER

EXPECTED_KIND_BY_DOMAIN = {
    "linux_auth": "preferred_sources",
    "windows_auth": "preferred_fields",
    "apache_web": "preferred_fields",
    "cross_platform_auth": "post_result_pivot_hint",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    for row in records:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status", "pending")).strip().lower() or "pending"
        kind = str(row.get("kind", "")).strip()
        normalized.append(
            {
                "id": str(row.get("id", "")).strip(),
                "scope": str(row.get("scope", "local")).strip() or "local",
                "intent": str(row.get("intent", "")).strip(),
                "kind": kind,
                "proposal": row.get("proposal"),
                "reason": str(row.get("reason", "")).strip(),
                "supporting_question": str(row.get("supporting_question", "")).strip(),
                "supporting_spl": str(row.get("supporting_spl", "")).strip(),
                "supporting_result_excerpt": str(row.get("supporting_result_excerpt", "")).strip(),
                "environment_evidence": row.get("environment_evidence", {}),
                "created_at": str(row.get("created_at", "")).strip() or _utc_now(),
                "updated_at": str(row.get("updated_at", "")).strip() or _utc_now(),
                "status": status if status in ALLOWED_STATUSES else "pending",
            }
        )
    return {
        "version": int(raw.get("version", 1) or 1),
        "updated_at": str(raw.get("updated_at", "")).strip() or _utc_now(),
        "records": normalized,
    }


def save_learning_registry(data: dict[str, Any]) -> None:
    ensure_learning_registry()
    out = _default_registry()
    if isinstance(data, dict):
        out["version"] = int(data.get("version", 1) or 1)
        records = data.get("records", [])
        out["records"] = records if isinstance(records, list) else []
    out["updated_at"] = _utc_now()
    REGISTRY_PATH.write_text(json.dumps(out, indent=2), encoding="utf-8")


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
    return {
        "id": _stable_id(intent, kind, proposal),
        "scope": "local",
        "intent": intent,
        "kind": kind,
        "proposal": proposal,
        "reason": reason,
        "supporting_question": supporting_question,
        "supporting_spl": supporting_spl,
        "supporting_result_excerpt": supporting_result_excerpt,
        "environment_evidence": environment_evidence or {},
        "created_at": now,
        "updated_at": now,
        "status": "pending",
    }


def _load_query_audit(limit: int = 60) -> list[dict[str, Any]]:
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
    for entry in audit:
        if not isinstance(entry, dict) or not _recent_rows_positive(entry):
            continue
        intent = str(entry.get("intent", "")).strip()
        query = str(entry.get("query", "")).strip()
        question = str(entry.get("question", "")).strip()
        if not intent or not query:
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
    return evidence


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
        return _normalize_learning_candidate(_call_ollama_json(model=models["planner"], system_prompt=system, user_payload=payload), bundle)
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
        raw = _call_ollama_json(model=models["writer"], system_prompt=system, user_payload=payload)
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
        raw = _call_ollama_json(model=models["reviewer"], system_prompt=system, user_payload=payload)
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
        return [values]
    if isinstance(values, list):
        return [str(item).strip() for item in values if str(item).strip()]
    return []


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
    profile = load_environment_profile(ENV_PROFILE_PATH)
    audit = _load_query_audit(60)
    bundles = _build_learning_evidence(profile, audit)
    models = _runtime_models()
    candidates: list[dict[str, Any]] = []
    considered = 0
    total = max(1, len(bundles))

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
        planner = _planner_decision(bundle, models)
        _log(f"[learning] planner action={planner.get('action')} intent={planner.get('intent')} kind={planner.get('kind')}")
        writer = _writer_candidate(bundle, planner, models)
        _log(f"[learning] writer action={writer.get('action')} intent={writer.get('intent')} kind={writer.get('kind')}")
        review = _review_candidate(bundle, planner, writer, models)
        candidate = review.get("candidate", {}) if isinstance(review, dict) else {}
        if not review.get("approved", False) or not isinstance(candidate, dict):
            _log(f"[learning] reviewer rejected bundle: {review.get('reason', 'rejected') if isinstance(review, dict) else 'rejected'}")
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
    _progress("Writing guarded learning registry updates...", 92, "writing_registry")
    outcome = _upsert_candidates(candidates)
    _log(
        f"[learning] complete created={outcome.get('created', 0)} "
        f"stale_marked={outcome.get('stale_marked', 0)} considered={considered}"
    )
    _progress("Guarded local learning run complete.", 100, "complete")
    return {
        "created": outcome.get("created", 0),
        "stale_marked": outcome.get("stale_marked", 0),
        "considered": considered,
        "registry": learning_registry_summary(),
    }
