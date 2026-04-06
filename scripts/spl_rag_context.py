#!/usr/bin/env python3
"""Lightweight SPL RAG context builder for planner/repair prompts.

This module is intentionally simple and deterministic for lab use.
It retrieves concise snippets from curated local docs and filters out
write/mutation-oriented commands that violate read-only policy.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from environment_profile import build_environment_context, build_tag_context
from local_learning import approved_learning_records
from question_intelligence import build_question_profile_text, infer_question_dimensions

RAG_SOURCES: tuple[str, ...] = (
    "docs/reference/rag_sources/agtsmith_spl_authoring_playbook.md",
    "docs/reference/rag_sources/spl_quick_reference.md",
    "docs/reference/rag_sources/search_commands_rex.md",
    "docs/reference/rag_sources/search_commands_timechart.md",
    "docs/reference/rag_sources/search_commands_datamodel.md",
    "docs/reference/rag_sources/search_commands_tstats.md",
    "docs/reference/rag_sources/search_commands_eventcode_4688.md",
    "docs/reference/rag_sources/security_correlation_searches.md",
    "docs/reference/rag_sources/escu_correlation_searches.md",
    "docs/reference/rag_sources/ioc_threat_hunting_example.md",
    "docs/reference/spl_gold_standard_queries.md",
    "docs/reference/spl_research_notes.md",
)
SKILLPACK_PATH = Path("artifacts/knowledge/spl_skillpack_latest.json")

FORBIDDEN_SNIPPET_TERMS = (
    "| collect",
    "| sendalert",
    "| outputlookup",
    "| delete",
    "| script",
    "| rest",
)

QUESTION_HINTS: dict[str, tuple[str, ...]] = {
    "failed_login": ("failed", "authentication", "user", "stats", "auth"),
    "linux_auth": ("linux", "/var/log/auth.log", "/var/log/secure", "failed password", "auth", "stats"),
    "linux_priv": ("/var/log/auth.log", "/var/log/secure", "sudo", "su", "failed", "stats"),
    "apache_access": ("access_combined", "clientip", "status", "web", "stats"),
    "apache_404": ("access_combined", "404", "timechart", "status", "web"),
    "powershell": ("eventcode=4688", "powershell", "process_command_line", "encodedcommand"),
    "indexes": ("index", "stats", "metadata"),
}


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _build_skillpack_context(question: str, *, max_intents: int = 3, max_domains: int = 3, max_chars: int = 1200) -> str:
    if not SKILLPACK_PATH.exists():
        return ""
    try:
        data = json.loads(SKILLPACK_PATH.read_text(encoding="utf-8"))
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    q = (question or "").lower()
    tokens = {t for t in re.findall(r"[a-z0-9_]{3,}", q)}
    dims = infer_question_dimensions(question)
    platforms = set(dims.get("platforms", []))
    activities = set(dims.get("activities", []))
    shapes = set(dims.get("shapes", []))
    lines: list[str] = ["[SPL_SKILLPACK]"]
    lines.append("Gold intent skills and discovered domain skills for constrained SPL drafting.")

    intents = data.get("gold_intent_skills", [])
    scored_intents: list[tuple[int, dict]] = []
    if isinstance(intents, list):
        for row in intents:
            if not isinstance(row, dict):
                continue
            score = 0
            intent = str(row.get("intent", "")).lower()
            if intent and intent in q:
                score += 3
            tags = {str(x).strip().lower() for x in row.get("tags", []) if str(x).strip()}
            if tags & platforms:
                score += 6
            if tags & activities:
                score += 6
            if tags & shapes:
                score += 3
            if "linux" in platforms and "windows" in tags:
                score -= 5
            if "windows" in platforms and "linux" in tags:
                score -= 5
            if "web" in platforms and "web" not in tags and "apache" in intent:
                score -= 3
            kws = row.get("keywords", [])
            if isinstance(kws, list):
                for kw in kws:
                    kw_l = str(kw).lower()
                    if kw_l and kw_l in q:
                        score += 2
                    for tok in tokens:
                        if tok in kw_l:
                            score += 1
            scored_intents.append((score, row))
    scored_intents.sort(key=lambda x: x[0], reverse=True)
    for score, row in scored_intents[:max(1, max_intents)]:
        lines.append(
            f"- intent={row.get('intent','')} relevance={score} "
            f"tags={','.join(str(x).strip() for x in row.get('tags', []) if str(x).strip())} "
            f"query={str(row.get('gold_query','')).strip()}"
        )

    domains = data.get("domain_skills", [])
    scored_domains: list[tuple[int, dict]] = []
    if isinstance(domains, list):
        for row in domains:
            if not isinstance(row, dict):
                continue
            score = 0
            idx = str(row.get("index", "")).lower()
            if idx and idx in q:
                score += 4
            sts = row.get("sourcetypes", [])
            if isinstance(sts, list):
                for strow in sts:
                    if not isinstance(strow, dict):
                        continue
                    st = str(strow.get("sourcetype", "")).lower()
                    if st and st in q:
                        score += 2
            if score > 0:
                scored_domains.append((score, row))
    scored_domains.sort(key=lambda x: x[0], reverse=True)
    for score, row in scored_domains[:max_domains]:
        idx = str(row.get("index", ""))
        st_names: list[str] = []
        field_lines: list[str] = []
        for st in row.get("sourcetypes", [])[:5] if isinstance(row.get("sourcetypes", []), list) else []:
            if isinstance(st, dict):
                n = str(st.get("sourcetype", "")).strip()
                if n:
                    st_names.append(n)
                    field_examples = st.get("known_field_examples", [])
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
                            field_lines.append(f"  - {n} fields={'; '.join(preview_parts)}")
                            continue
                    known_fields = st.get("known_fields", [])
                    if isinstance(known_fields, list) and known_fields:
                        field_lines.append(f"  - {n} fields={', '.join(str(x).strip() for x in known_fields[:8] if str(x).strip())}")
        if st_names:
            lines.append(f"- domain index={idx} relevance={score} sourcetypes={', '.join(st_names)}")
            lines.extend(field_lines[:5])
    text = "\n".join(lines)
    if len(text) > max_chars:
        text = text[:max_chars]
    return text


def _build_authoring_guidance(question: str, *, max_chars: int = 1200) -> str:
    if not SKILLPACK_PATH.exists():
        return ""
    try:
        data = json.loads(SKILLPACK_PATH.read_text(encoding="utf-8"))
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    q = (question or "").lower()
    tokens = {t for t in re.findall(r"[a-z0-9_]{3,}", q)}
    guidance_rows = data.get("authoring_guidance", [])
    if not isinstance(guidance_rows, list):
        return ""
    scored: list[tuple[int, dict]] = []
    for row in guidance_rows:
        if not isinstance(row, dict):
            continue
        score = 0
        intent = str(row.get("intent", "")).lower()
        if intent and intent in q:
            score += 5
        for token in row.get("match_tokens", []):
            token_l = str(token).lower().strip()
            if token_l and token_l in q:
                score += 3
            elif token_l and token_l in tokens:
                score += 1
        if score > 0:
            scored.append((score, row))
    scored.sort(key=lambda x: x[0], reverse=True)
    if not scored:
        return ""
    lines = ["[AUTHORING_GUIDANCE]"]
    for score, row in scored[:3]:
        lines.append(
            f"- intent={row.get('intent','')} relevance={score} "
            f"preferred_index={row.get('preferred_index','')} "
            f"preferred_sourcetypes={', '.join(str(x).strip() for x in row.get('preferred_sourcetypes', []) if str(x).strip())}"
        )
        preferred_fields = row.get("preferred_fields", [])
        if isinstance(preferred_fields, list) and preferred_fields:
            lines.append(f"  preferred_fields={', '.join(str(x).strip() for x in preferred_fields if str(x).strip())}")
        query_shape = str(row.get("preferred_query_shape", "")).strip()
        if query_shape:
            lines.append(f"  preferred_query_shape={query_shape}")
        anti_patterns = row.get("anti_patterns", [])
        if isinstance(anti_patterns, list) and anti_patterns:
            lines.append(f"  anti_patterns={'; '.join(str(x).strip() for x in anti_patterns if str(x).strip())}")
    text = "\n".join(lines)
    if len(text) > max_chars:
        text = text[:max_chars]
    return text


def _build_local_learning_context(question: str, *, max_chars: int = 700) -> str:
    q = (question or "").lower()
    tokens = {t for t in re.findall(r"[a-z0-9_]{3,}", q)}
    rows = approved_learning_records()
    if not rows:
        return ""
    scored: list[tuple[int, dict]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        score = 0
        intent = str(row.get("intent", "")).strip().lower()
        if intent and intent in q:
            score += 8
        reason = str(row.get("reason", "")).lower()
        proposal = row.get("proposal")
        proposal_text = json.dumps(proposal, sort_keys=True) if isinstance(proposal, (dict, list)) else str(proposal or "")
        blob = f"{intent} {reason} {proposal_text}".lower()
        for tok in tokens:
            if tok in blob:
                score += 1
        if score > 0:
            scored.append((score, row))
    if not scored:
        return ""
    scored.sort(key=lambda x: x[0], reverse=True)
    lines = ["[LOCAL_LEARNING_APPROVED]", "Use these approved optimization assets and local hints only when they agree with discovered environment facts."]
    for score, row in scored[:4]:
        kind = str(row.get("kind", "")).strip()
        proposal = row.get("proposal", {}) if isinstance(row.get("proposal", {}), dict) else {}
        if kind == "spl_pattern_asset":
            lines.append(
                f"- intent={row.get('intent','')} kind=spl_pattern_asset relevance={score} "
                f"query_template={json.dumps(str(proposal.get('query_template', '')).strip())}"
            )
            required_fields = proposal.get("required_fields", [])
            if isinstance(required_fields, list) and required_fields:
                lines.append(f"  required_fields={', '.join(str(x).strip() for x in required_fields if str(x).strip())}")
            required_sources = proposal.get("required_sources", [])
            if isinstance(required_sources, list) and required_sources:
                lines.append(f"  required_sources={', '.join(str(x).strip() for x in required_sources if str(x).strip())}")
            required_sourcetypes = proposal.get("required_sourcetypes", [])
            if isinstance(required_sourcetypes, list) and required_sourcetypes:
                lines.append(f"  required_sourcetypes={', '.join(str(x).strip() for x in required_sourcetypes if str(x).strip())}")
            use_when = str(proposal.get("use_when", "")).strip()
            if use_when:
                lines.append(f"  use_when={use_when}")
            why = str(proposal.get("why", "")).strip()
            if why:
                lines.append(f"  why={why}")
        else:
            lines.append(
                f"- intent={row.get('intent','')} kind={kind} relevance={score} proposal={json.dumps(proposal, sort_keys=True)}"
            )
        reason = str(row.get("reason", "")).strip()
        if reason:
            lines.append(f"  reason={reason}")
    text = "\n".join(lines)
    if len(text) > max_chars:
        text = text[:max_chars]
    return text


def _question_hints(question: str) -> list[str]:
    q = question.lower()
    hints = {"search", "stats"}
    for key, vals in QUESTION_HINTS.items():
        if key in q:
            hints.update(v.lower() for v in vals)
    for token in re.findall(r"[a-z0-9_]{3,}", q):
        hints.add(token)
    return sorted(hints)


def _sanitize_snippet(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        ll = line.lower()
        if any(term in ll for term in FORBIDDEN_SNIPPET_TERMS):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def _extract_spl_blocks(text: str) -> list[str]:
    blocks = re.findall(r"```spl\s*([\s\S]*?)```", text, flags=re.IGNORECASE)
    cleaned: list[str] = []
    for block in blocks:
        b = _sanitize_snippet(block.strip())
        if b:
            cleaned.append(b)
    return cleaned


def _best_lines(text: str, hints: list[str], max_chars: int = 700) -> str:
    lines = text.splitlines()
    scored: list[tuple[int, int]] = []
    for i, line in enumerate(lines):
        ll = line.lower()
        score = sum(1 for h in hints if h in ll)
        if score > 0:
            scored.append((score, i))
    if not scored:
        return _sanitize_snippet(text[:max_chars])

    scored.sort(reverse=True)
    selected: list[str] = []
    used: set[int] = set()
    for _score, idx in scored[:6]:
        start = max(0, idx - 1)
        end = min(len(lines), idx + 2)
        for j in range(start, end):
            if j not in used:
                selected.append(lines[j])
                used.add(j)
        if len("\n".join(selected)) >= max_chars:
            break
    return _sanitize_snippet("\n".join(selected)[:max_chars])


def build_spl_rag_context(question: str, *, max_sources: int = 3, max_chars: int = 1600) -> str:
    hints = _question_hints(question)
    ranked: list[tuple[int, str, str]] = []
    for src in RAG_SOURCES:
        text = _read_text(src)
        if not text:
            continue
        lowered = text.lower()
        score = sum(1 for h in hints if h in lowered)
        spl_blocks = _extract_spl_blocks(text)
        block = spl_blocks[0] if spl_blocks else ""
        lines = _best_lines(text, hints)
        snippet = (block + "\n" + lines).strip() if block else lines
        if snippet:
            ranked.append((score, src, snippet))

    ranked.sort(key=lambda x: x[0], reverse=True)
    chosen = ranked[:max(1, max_sources)]
    parts: list[str] = []
    for _score, src, snippet in chosen:
        parts.append(f"[SOURCE:{src}]\n{snippet}")

    constraints = (
        "[ENV_CONSTRAINTS]\n"
        "- Read-only only. Never use collect/sendalert/outputlookup/delete/drop.\n"
        "- Query must start with 'search '.\n"
        "- earliest_time and latest_time are required.\n"
        "- row_limit must be <= 200.\n"
        "- In this MCP environment, avoid tstats with 'by'. Use datamodel ... flat | stats ... by ... instead.\n"
        "- Use discovered index/sourcetype combos from ENVIRONMENT_PROFILE when available.\n"
        "- Prefer CIM-aligned tags/eventtypes when present in CIM_TAG_PROFILE for the asked use case.\n"
        "- Unless the question explicitly asks for Splunk internal context, exclude internal indexes by default (use NOT index=_*).\n"
    )
    env_ctx = build_environment_context(question, max_chars=max(400, int(max_chars * 0.5)))
    tag_ctx = build_tag_context(question, max_chars=max(300, int(max_chars * 0.35)))
    skill_ctx = _build_skillpack_context(question, max_chars=max(300, int(max_chars * 0.35)))
    authoring_ctx = _build_authoring_guidance(question, max_chars=max(320, int(max_chars * 0.35)))
    local_learning_ctx = _build_local_learning_context(question, max_chars=max(260, int(max_chars * 0.25)))
    question_profile = build_question_profile_text(question)
    reserve = len(constraints) + 2
    if env_ctx:
        reserve += len(env_ctx) + 2
    if tag_ctx:
        reserve += len(tag_ctx) + 2
    if skill_ctx:
        reserve += len(skill_ctx) + 2
    if authoring_ctx:
        reserve += len(authoring_ctx) + 2
    if local_learning_ctx:
        reserve += len(local_learning_ctx) + 2
    if question_profile:
        reserve += len(question_profile) + 2
    budget = max(200, max_chars - reserve)
    merged_sources = "\n\n".join(parts)
    if len(merged_sources) > budget:
        merged_sources = merged_sources[:budget]
    segments = [
        question_profile.strip(),
        merged_sources.strip(),
        env_ctx.strip(),
        tag_ctx.strip(),
        skill_ctx.strip(),
        authoring_ctx.strip(),
        local_learning_ctx.strip(),
        constraints.strip(),
    ]
    return "\n\n".join(seg for seg in segments if seg).strip()
