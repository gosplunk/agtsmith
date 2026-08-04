#!/usr/bin/env python3
"""Structural SPL validation beyond policy checks."""

from __future__ import annotations

import re
from typing import Any

from environment_profile import load_environment_profile
from sourcetype_cards import load_cards


def _profile_sourcetypes(profile: dict[str, Any]) -> set[str]:
    st_to_idx = profile.get("sourcetype_to_indexes", {}) if isinstance(profile, dict) else {}
    if not isinstance(st_to_idx, dict):
        return set()
    return {str(k).strip().lower() for k in st_to_idx.keys() if str(k).strip()}


def _card_sourcetypes() -> set[str]:
    return {str(c.get("sourcetype", "")).strip().lower() for c in load_cards() if str(c.get("sourcetype", "")).strip()}


def extract_sourcetypes(query: str) -> list[str]:
    found: list[str] = []
    for m in re.finditer(r'sourcetype="([^"]+)"', query, re.I):
        found.append(m.group(1))
    for m in re.finditer(r"sourcetype=([^\s|\"')\],]+)", query, re.I):
        found.append(m.group(1).strip('"'))
    return found


def validate_structure(
    query: str,
    *,
    intent: str = "",
    question: str = "",
    profile: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    text = " ".join(str(query or "").split())
    if not text:
        return False, "empty_query"
    if not text.lower().startswith("search "):
        return False, "must_start_with_search"
    lowered = text.lower()
    if re.search(r"\b(collect|sendalert|outputlookup|delete)\b", lowered):
        return False, "blocked_command"
    if "xmlwineventlog" in lowered and any(x in lowered for x in ("auth.log", "linux_secure", "syslog")):
        cross_platform = intent.lower() in {
            "failed_login_activity",
            "cross_platform_auth_failures",
        } or ("windows" in question.lower() and "linux" in question.lower()) or "| append" in lowered
        if not cross_platform:
            return False, "platform_mix_windows_linux"
    sourcetypes = extract_sourcetypes(text)
    profile = profile if isinstance(profile, dict) else load_environment_profile()
    known = _profile_sourcetypes(profile) | _card_sourcetypes()
    if sourcetypes and known:
        for st in sourcetypes:
            if st.lower() not in known:
                return False, f"invented_sourcetype:{st}"
    if intent.lower() in {"failed_logins", "authentication_failures"}:
        if "xmlwineventlog" in lowered and "eventcode=4625" not in lowered.replace(" ", ""):
            return False, "windows_failed_login_missing_eventcode"
        if any(x in lowered for x in ("auth.log", "linux_secure")) and "failed" not in lowered and "invalid" not in lowered:
            return False, "linux_failed_login_missing_filter"
    if "botsv3" in lowered or "botsv3" in question.lower():
        if "sourcetype=" not in lowered and intent not in {"index_inventory", "sourcetype_inventory"}:
            return False, "botsv3_missing_sourcetype_scope"
    if "| stats" in lowered and " by " not in lowered and intent in {"top_sources", "sourcetype_inventory", "index_inventory"}:
        return False, "inventory_intent_missing_by_clause"
    return True, "structure_ok"


def structure_score_penalty(query: str, *, intent: str = "", question: str = "") -> float:
    ok, reason = validate_structure(query, intent=intent, question=question)
    if ok:
        return 0.0
    if reason.startswith("invented_sourcetype"):
        return 25.0
    if reason.startswith("platform_mix"):
        return 20.0
    if reason.startswith("botsv3"):
        return 15.0
    return 10.0
