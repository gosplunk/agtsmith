#!/usr/bin/env python3
"""Load Tier-1 Windows Security and Sysmon event code catalog for RAG and reviewers."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = PROJECT_ROOT / "config" / "windows_event_code_catalog.yaml"
RAG_DOC_PATH = PROJECT_ROOT / "docs" / "reference" / "rag_sources" / "windows_event_code_catalog.md"


def _load_yaml(path: Path) -> dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML required to load windows event code catalog")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


@lru_cache(maxsize=1)
def load_catalog() -> dict[str, Any]:
    if not CATALOG_PATH.is_file():
        return {"entries": [], "intent_index": {}}
    return _load_yaml(CATALOG_PATH)


def catalog_entries() -> list[dict[str, Any]]:
    raw = load_catalog().get("entries", [])
    return [row for row in raw if isinstance(row, dict)]


def lookup_by_intent(intent: str) -> dict[str, Any] | None:
    intent_name = str(intent or "").strip()
    if not intent_name:
        return None
    for entry in catalog_entries():
        if str(entry.get("intent", "")).strip() == intent_name:
            return entry
    if intent_name == "failed_login_activity":
        return lookup_by_intent("windows_auth_failures")
    return None


def lookup_by_event_code(code: str | int) -> dict[str, Any] | None:
    token = str(code or "").strip()
    if not token:
        return None
    for entry in catalog_entries():
        codes = [str(item).strip() for item in entry.get("event_codes", []) if str(item).strip()]
        if token in codes:
            return entry
    return None


def intents_for_question(question: str) -> list[str]:
    q = str(question or "").lower()
    matched: list[str] = []
    for entry in catalog_entries():
        intent = str(entry.get("intent", "")).strip()
        if not intent:
            continue
        name = str(entry.get("name", "")).lower()
        codes = [str(c) for c in entry.get("event_codes", [])]
        channel = str(entry.get("channel", "")).lower()
        tokens = [
            intent.replace("_", " "),
            name,
            f"eventcode {codes[0]}" if codes else "",
            f"event id {codes[0]}" if codes else "",
            f"eventid {codes[0]}" if codes else "",
            channel,
        ]
        if any(tok and tok in q for tok in tokens):
            matched.append(intent)
        elif codes and any(re.search(rf"\b{re.escape(code)}\b", q) for code in codes):
            matched.append(intent)
    if "failed logon" in q or "failed login" in q:
        if "windows_auth_failures" not in matched:
            matched.append("windows_auth_failures")
    if "sysmon" in q and "dns" in q and "windows_sysmon_dns_activity" not in matched:
        matched.append("windows_sysmon_dns_activity")
    if "sysmon" in q and "network" in q and "windows_sysmon_network_activity" not in matched:
        matched.append("windows_sysmon_network_activity")
    if "sysmon" in q and "process" in q and "windows_process_activity" not in matched:
        matched.append("windows_process_activity")
    return list(dict.fromkeys(matched))


def rag_tokens_for_intent(intent: str) -> set[str]:
    entry = lookup_by_intent(intent)
    tokens: set[str] = set()
    if not entry:
        return tokens
    tokens.add(str(entry.get("intent", "")).lower())
    for code in entry.get("event_codes", []):
        tokens.add(str(code).lower())
    tokens.update(str(field).lower() for field in entry.get("key_fields", []) if str(field).strip())
    channel = str(entry.get("channel", "")).strip().lower()
    if channel:
        tokens.add(channel)
        if "sysmon" in channel:
            tokens.update({"sysmon", "xmlwineventlog", "eventcode", "eventid"})
    tokens.update({"xmlwineventlog", "wineventlog", "windows"})
    return tokens


def build_event_code_rag_context(
    question: str,
    *,
    intent: str = "",
    max_entries: int = 3,
    max_chars: int = 1400,
) -> str:
    intents = []
    if str(intent or "").strip():
        intents.append(str(intent).strip())
    intents.extend(intents_for_question(question))
    intents = list(dict.fromkeys(intents))[: max(1, max_entries)]

    lines = ["[WINDOWS_EVENT_CODE_CATALOG]"]
    for intent_name in intents:
        entry = lookup_by_intent(intent_name)
        if not entry:
            continue
        codes = ", ".join(str(c) for c in entry.get("event_codes", []))
        fields = ", ".join(str(f) for f in entry.get("key_fields", [])[:8])
        anti = entry.get("anti_patterns", [])
        anti_text = "; ".join(str(a) for a in anti[:2]) if isinstance(anti, list) else ""
        lines.append(
            f"- intent={entry.get('intent')} codes={codes} name={entry.get('name')} "
            f"channel={entry.get('channel')} mitre={','.join(entry.get('mitre', []) or [])}"
        )
        lines.append(f"  filter={entry.get('spl_filter', '')}")
        lines.append(f"  key_fields={fields}")
        if anti_text:
            lines.append(f"  anti_patterns={anti_text}")
    text = "\n".join(lines).strip()
    if len(text) > max_chars:
        return text[: max_chars - 3].rstrip() + "..."
    return text


def build_event_code_reviewer_context(
    *,
    question: str = "",
    intent: str = "",
    query: str = "",
    max_chars: int = 900,
) -> dict[str, Any]:
    intent_name = str(intent or "").strip()
    entry = lookup_by_intent(intent_name)
    if entry is None and query:
        for match in re.finditer(r"(?:EventCode|EventID)\s*=\s*(\d+)", query, flags=re.IGNORECASE):
            entry = lookup_by_event_code(match.group(1))
            if entry:
                break
    if entry is None:
        for candidate in intents_for_question(question):
            entry = lookup_by_intent(candidate)
            if entry:
                break
    if entry is None:
        return {}
    payload = {
        "event_code": entry.get("event_codes", [""])[0],
        "event_name": entry.get("name", ""),
        "channel": entry.get("channel", ""),
        "intent": entry.get("intent", ""),
        "mitre_techniques": entry.get("mitre", []),
        "expected_key_fields": entry.get("key_fields", []),
        "spl_filter": entry.get("spl_filter", ""),
        "anti_patterns": entry.get("anti_patterns", []),
    }
    text = json.dumps(payload, sort_keys=True)
    if len(text) > max_chars:
        payload["anti_patterns"] = list(payload.get("anti_patterns", []))[:1]
    return payload


def benchmark_cases_from_catalog() -> list[str]:
    cases: list[str] = []
    for entry in catalog_entries():
        case = str(entry.get("lab_benchmark_case", "")).strip()
        if case:
            cases.append(case)
    return cases
