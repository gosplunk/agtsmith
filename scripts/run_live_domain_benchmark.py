#!/usr/bin/env python3
"""Run profile-driven live-domain SPL benchmark: gold vs agtsmith pipeline."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from environment_profile import (
    PROFILE_PATH_DEFAULT,
    _fallback_domains_from_profile,
    apply_environment_query_constraints,
    attach_semantics,
    load_environment_profile,
    resolve_authoritative_domains_for_question,
)
from query_templates import TEMPLATES
from intent_field_contracts import validate_platform_sourcetype_coherence
from minimal_question_to_answer import (
    map_question_to_template,
    run_splunk_query_args,
    template_to_query_args,
)
from query_policy import validate_query_args
from spl_autonomy_manifest import build_manifest

try:
    from lab_data.config import read_verify_manifest
except ImportError:  # pragma: no cover
    read_verify_manifest = None  # type: ignore

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BENCHMARK_PATH = PROJECT_ROOT / "benchmarks" / "live_domain_benchmark.json"
DEFAULT_OUT_ROOT = PROJECT_ROOT / "artifacts" / "spl_autonomy" / "live_benchmark"
DEFAULT_EARLIEST_TIME = "-7d"
EARLIEST_TIME_CHOICES = ("-24h", "-7d")
MANIFEST_CASE_ALIASES = {
    "failed_logons_phrasing_24h": "linux_auth_failures_24h",
    "stream_dns_overview_24h": "botsv3_stream_dns_all_time",
    "windows_sysmon_network_30d": "windows_sysmon_network_3_24h",
}

_INDEX_RE = re.compile(r"\bindex=(?P<idx>[^\s\)|]+)", re.IGNORECASE)
_SOURCETYPE_RE = re.compile(r"\bsourcetype=(?P<st>[^\s\)|]+)", re.IGNORECASE)


@dataclass(frozen=True)
class BenchmarkCase:
    id: str
    theme: str
    question: str
    intent: str
    profile_domain_hints: dict[str, Any]
    expected_shape: str
    required_terms: tuple[str, ...]
    forbidden_patterns: tuple[str, ...]
    allow_zero_rows: bool
    min_rows: int
    skip_if_no_windows_domain: bool = False
    skip_if_no_cloud_domain: bool = False
    expected_min_rows_from_manifest: bool = False


CASE_TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "linux_auth_failures_24h",
        "theme": "auth",
        "question": "Show failed SSH login attempts on Linux hosts in the last 24 hours. Identify the top source IPs, usernames targeted, and ports used.",
        "intent": "linux_auth_failures",
        "profile_domain_hints": {
            "platform": "linux",
            "use_cases": ["linux_auth_failures"],
            "preferred_sourcetypes": ["auth.log", "linux_secure"],
        },
        "expected_shape": "stats",
        "required_terms": ["Failed password", "Invalid user", "stats", "src_ip", "user"],
        "forbidden_patterns": [r"index=\*", "index=windows", "index=botsv3", r"\b4625\b"],
        "allow_zero_rows": False,
        "min_rows": 1,
    },
    {
        "id": "apache_access_top_ips_24h",
        "theme": "web",
        "question": "What are the top source IPs hitting our web servers in the last 24 hours?",
        "intent": "apache_access_top_ips",
        "profile_domain_hints": {
            "platform": "web",
            "use_cases": ["apache_access_top_ips"],
            "preferred_sourcetypes": ["access_combined", "apache:access"],
        },
        "expected_shape": "stats",
        "required_terms": ["access_combined", "clientip", "stats", "status"],
        "forbidden_patterns": [r"index=\*", "index=linux"],
        "allow_zero_rows": False,
        "min_rows": 1,
    },
    {
        "id": "linux_privilege_escalation_24h",
        "theme": "linux_priv",
        "question": "Show sudo and privilege escalation activity on Linux hosts in the last 24 hours",
        "intent": "linux_privilege_escalation_activity",
        "profile_domain_hints": {
            "platform": "linux",
            "use_cases": ["linux_privilege_escalation_activity"],
            "preferred_sourcetypes": ["auth.log", "linux_secure", "linux_audit"],
        },
        "expected_shape": "table",
        "required_terms": ["sudo", "table", "actor", "target_user"],
        "forbidden_patterns": [r"index=\*", "index=windows", "index=botsv3"],
        "allow_zero_rows": False,
        "min_rows": 1,
    },
    {
        "id": "windows_failed_logon_4625_24h",
        "theme": "windows_auth",
        "question": "Show Windows failed logon events (EventCode 4625) in the last 24 hours",
        "intent": "windows_auth_failures",
        "profile_domain_hints": {
            "platform": "windows",
            "use_cases": ["windows_auth_failures"],
            "preferred_sourcetypes": ["xmlwineventlog", "WinEventLog", "xmlwineventlog:security"],
        },
        "expected_shape": "table",
        "required_terms": ["4625", "EventCode", "TargetUserName", "src_ip"],
        "forbidden_patterns": [r"index=\*", "index=linux", "linux_secure"],
        "allow_zero_rows": True,
        "min_rows": 0,
        "skip_if_no_windows_domain": True,
    },
    {
        "id": "apache_404_spike_24h",
        "theme": "web_404",
        "question": "Show 404 spike from Apache access logs in the last 24 hours",
        "intent": "apache_404_spike",
        "profile_domain_hints": {
            "platform": "web",
            "use_cases": ["apache_404_spike"],
            "preferred_sourcetypes": ["access_combined", "apache:access"],
        },
        "expected_shape": "timechart",
        "required_terms": ["access_combined", "404", "timechart"],
        "forbidden_patterns": [r"index=\*", "index=linux"],
        "allow_zero_rows": True,
        "min_rows": 0,
    },
]


def _row_to_case(row: dict[str, Any]) -> BenchmarkCase:
    hints = row.get("profile_domain_hints", {})
    if not isinstance(hints, dict):
        hints = {}
    return BenchmarkCase(
        id=str(row["id"]),
        theme=str(row.get("theme", "")),
        question=str(row["question"]),
        intent=str(row["intent"]),
        profile_domain_hints=hints,
        expected_shape=str(row.get("expected_shape", "stats")),
        required_terms=tuple(row.get("required_terms", [])),
        forbidden_patterns=tuple(row.get("forbidden_patterns", [])),
        allow_zero_rows=bool(row.get("allow_zero_rows", False)),
        min_rows=int(row.get("min_rows", 0)),
        expected_min_rows_from_manifest=bool(row.get("expected_min_rows_from_manifest", False)),
        skip_if_no_windows_domain=bool(row.get("skip_if_no_windows_domain", False)),
        skip_if_no_cloud_domain=bool(row.get("skip_if_no_cloud_domain", False)),
    )


def _profile_supports_case(case: BenchmarkCase, profile_path: Path) -> bool:
    if case.skip_if_no_windows_domain and not _windows_domain_available(profile_path):
        return False
    try:
        _, primary = _resolve_case_domain(case, profile_path)
        return primary is not None
    except Exception:
        return False


def _generate_cases_from_profile(profile_path: Path) -> list[BenchmarkCase]:
    """Build portable benchmark cases from in-code templates, filtered by live profile domains."""
    return [case for template in CASE_TEMPLATES if _profile_supports_case((case := _row_to_case(template)), profile_path)]


def _load_cases(path: Path, *, profile_path: Path | None = None, prefer_runtime: bool = False) -> list[BenchmarkCase]:
    if prefer_runtime and profile_path is not None:
        generated = _generate_cases_from_profile(profile_path)
        if generated:
            return generated
    payload = json.loads(path.read_text(encoding="utf-8"))
    if prefer_runtime and profile_path is not None and bool(payload.get("render_gold_at_runtime", False)):
        generated = _generate_cases_from_profile(profile_path)
        if generated:
            return generated
    cases: list[BenchmarkCase] = []
    for row in payload.get("cases", []):
        cases.append(_row_to_case(row))
    return cases


def _pick_sourcetype(sourcetypes: list[str], *candidates: str) -> str:
    normalized = {st.lower(): st for st in sourcetypes}
    for candidate in candidates:
        key = candidate.lower()
        if key in normalized:
            return normalized[key]
    for st in sourcetypes:
        st_l = st.lower()
        for candidate in candidates:
            if candidate.lower() in st_l:
                return st
    return sourcetypes[0] if sourcetypes else ""


def _resolve_case_domain(case: BenchmarkCase, profile_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    profile = attach_semantics(load_environment_profile(profile_path))
    domains = resolve_authoritative_domains_for_question(case.question, case.intent, profile_path=profile_path)
    hints = case.profile_domain_hints
    preferred = [str(item) for item in hints.get("preferred_sourcetypes", []) if str(item).strip()]
    platform = str(hints.get("platform", "")).strip()
    hinted_primary = (
        _fallback_domain_from_profile(
            profile,
            platform=platform,
            preferred_sourcetypes=preferred,
        )
        if preferred
        else None
    )
    primary = hinted_primary or (domains[0] if domains else None)
    if hinted_primary and not any(
        str(item.get("index", "")).strip()
        == str(hinted_primary.get("index", "")).strip()
        for item in domains
        if isinstance(item, dict)
    ):
        domains = [hinted_primary, *domains]
    if primary is None:
        if not preferred:
            fallback_domains = _fallback_domains_from_profile(profile, case.intent, case.question, max_domains=1)
            primary = fallback_domains[0] if fallback_domains else None
        if primary:
            domains = [primary]
    return domains, primary


def _fallback_domain_from_profile(profile: dict[str, Any], *, platform: str, preferred_sourcetypes: list[str]) -> dict[str, Any] | None:
    st_to_indexes = profile.get("sourcetype_to_indexes", {})
    if not isinstance(st_to_indexes, dict):
        return None
    platform_l = platform.lower()

    def _index_affinity(index_name: str) -> int:
        index_l = index_name.lower()
        score = 0
        if platform_l and index_l == platform_l:
            score += 100
        elif platform_l and platform_l in index_l:
            score += 50
        if platform_l == "web" and any(
            token in index_l for token in ("web", "http", "apache")
        ):
            score += 50
        if index_l.startswith("agtsmith_test"):
            score -= 10
        if index_l.startswith("_") and platform_l != "internal":
            score -= 100
        return score

    for st in preferred_sourcetypes:
        indexes = st_to_indexes.get(st) or st_to_indexes.get(st.lower())
        if not indexes:
            for key, idxs in st_to_indexes.items():
                if key.lower() == st.lower():
                    indexes = idxs
                    break
        if not indexes:
            continue
        candidate_indexes = [
            str(item).strip() for item in indexes if str(item).strip()
        ]
        if not candidate_indexes:
            continue
        idx = max(candidate_indexes, key=_index_affinity)
        if not idx:
            continue
        index_row = next((row for row in profile.get("indexes", []) if isinstance(row, dict) and row.get("index") == idx), None)
        sourcetypes = [str(item).strip() for item in (index_row or {}).get("sourcetypes", []) if str(item).strip()]
        return {"index": idx, "sourcetypes": sourcetypes or [st], "styles": [platform] if platform else [], "source": "profile_fallback"}
    return None


def _windows_domain_available(profile_path: Path) -> bool:
    profile = load_environment_profile(profile_path)
    st_to_indexes = profile.get("sourcetype_to_indexes", {})
    if not isinstance(st_to_indexes, dict):
        return False
    for st in ("xmlwineventlog", "WinEventLog", "xmlwineventlog:security", "wineventlog:security"):
        if st in st_to_indexes or any(k.lower() == st.lower() for k in st_to_indexes):
            return True
    return False


def _cloud_domain_available(profile_path: Path) -> bool:
    profile = load_environment_profile(profile_path)
    if not isinstance(profile, dict):
        return False
    index_names = {
        str(row.get("index", "")).strip().lower()
        for row in profile.get("indexes", [])
        if isinstance(row, dict) and str(row.get("index", "")).strip()
    }
    if {"aws_prod", "o365_prod"}.issubset(index_names):
        return True
    st_to_indexes = profile.get("sourcetype_to_indexes", {})
    if not isinstance(st_to_indexes, dict):
        return False
    for st in ("aws:cloudtrail", "o365:management:activity"):
        if st in st_to_indexes or any(k.lower() == st.lower() for k in st_to_indexes):
            return True
    return False


def render_gold_spl(case: BenchmarkCase, profile_path: Path) -> tuple[str, dict[str, Any]]:
    """Render profile-resolved gold SPL for a benchmark case."""
    domains, primary = _resolve_case_domain(case, profile_path)
    if not primary:
        raise ValueError(f"no_domain_for_case:{case.id}")

    index = str(primary.get("index", "")).strip()
    sourcetypes = [str(st).strip() for st in primary.get("sourcetypes", []) if str(st).strip()]
    meta = {
        "resolved_domains": domains,
        "primary_index": index,
        "primary_sourcetypes": sourcetypes,
        "render_source": primary.get("source", "resolve_authoritative_domains"),
    }

    intent = case.intent
    if intent == "linux_auth_failures":
        auth_st = _pick_sourcetype(sourcetypes, "auth.log", "linux_secure", "secure")
        query = (
            f'search index={index} sourcetype={auth_st} '
            '("Failed password" OR "authentication failure" OR "Invalid user" OR "Connection closed by invalid user" OR "FAILED SU") '
            '| rex field=_raw "(?i)Failed password for (?:invalid user )?(?<user>[^ ]+)" '
            '| rex field=_raw "(?i)user=(?<pam_user>[^\\s;]+)" '
            '| rex field=_raw "(?i)from (?<failed_src_ip>\\d{1,3}(?:\\.\\d{1,3}){3}) port (?<failed_port>\\d+)" '
            '| rex field=_raw "(?i)rhost=(?<rhost>[^\\s;]+)" '
            '| eval user=coalesce(user,pam_user,username,account) '
            '| eval src_ip=coalesce(src_ip,failed_src_ip,rhost,src,ip,"local") '
            '| eval port=coalesce(port,failed_port,lport) '
            '| stats count by host user src_ip port | sort - count'
        )
    elif intent == "apache_access_top_ips":
        web_st = _pick_sourcetype(sourcetypes, "access_combined", "apache:access", "stream:http")
        query = (
            f"search index={index} sourcetype={web_st} "
            '| rex field=_raw "^(?<clientip>\\S+) \\S+ \\S+ \\[[^\\]]+\\] \\"(?<method>[A-Z]+) (?<uri_path>\\S+) [^\\"]+\\" (?<status>\\d{3})" '
            "| stats count by clientip status method | sort - count"
        )
    elif intent == "linux_privilege_escalation":
        auth_st = _pick_sourcetype(sourcetypes, "auth.log", "linux_secure", "linux_audit")
        query = (
            f'search index={index} sourcetype={auth_st} '
            '(("pam_unix(sudo:auth): authentication failure" OR "pam_unix(su:auth): authentication failure" OR "conversation failed") '
            'OR (("sudo:" OR "su:") ("authentication failure" OR "incorrect password" OR "incorrect password attempts" OR "failed"))) '
            '| rex field=_raw "\\s(?<process_name>sudo|su)(?:\\[[^\\]]+\\])?:" '
            '| rex field=_raw "(?i)sudo:\\s+(?<sudo_actor>[A-Za-z0-9_.-]+)\\s+:" '
            '| rex field=_raw "(?i)logname=(?<logname_user>[^\\s;]+)" '
            '| rex field=_raw "(?i)ruser=(?<ruser>[^\\s;]+)" '
            '| rex field=_raw "(?i)\\buser=(?<auth_user>[^\\s;]+)" '
            '| rex field=_raw "(?i)tty=(?<tty_value>[^\\s;]+)" '
            '| rex field=_raw "(?i)rhost=(?<src_ip>[^\\s;]+)" '
            '| eval actor=coalesce(sudo_actor,logname_user,ruser,auth_user,user,account,uid,user_name) '
            '| eval tty=coalesce(tty_value,tty) '
            '| eval src_ip=if(isnull(src_ip) OR len(trim(src_ip))=0, "local", src_ip) '
            '| stats count by host process_name actor tty src_ip sourcetype | sort - count'
        )
    elif intent == "windows_auth_failures":
        win_st = _pick_sourcetype(sourcetypes, "xmlwineventlog:security", "xmlwineventlog", "WinEventLog", "XmlWinEventLog")
        query = (
            f"search index={index} (sourcetype={win_st} OR sourcetype=XmlWinEventLog OR sourcetype=xmlwineventlog OR sourcetype=WinEventLog) "
            '(EventCode=4625 OR EventID=4625 OR "An account failed to log on") '
            "| eval src_ip=coalesce(Source_Network_Address,IpAddress,src,src_ip,clientip,ip) "
            "| eval user_name=coalesce(TargetUserName,SubjectUserName,Account_Name,user,username,Caller_User_Name) "
            "| table _time index host user_name src_ip EventCode EventID TargetUserName IpAddress"
        )
    elif intent == "apache_404_spike":
        web_st = _pick_sourcetype(sourcetypes, "access_combined", "apache:access")
        query = (
            f"search index={index} sourcetype={web_st} "
            '| rex field=_raw "^(?<clientip>\\S+) \\S+ \\S+ \\[[^\\]]+\\] \\"(?<method>[A-Z]+) (?<uri_path>\\S+) [^\\"]+\\" (?<status>\\d{3})" '
            "| search status=404 "
            "| timechart span=1h count by host limit=10"
        )
    else:
        template = next((item for item in TEMPLATES if item.intent == intent), None)
        if template is None:
            raise ValueError(f"unsupported_gold_intent:{intent}")
        query = apply_environment_query_constraints(
            case.question,
            intent,
            template.query,
            profile_path=profile_path,
        )
        meta["render_source"] = "query_template_with_profile_constraints"

    return query.strip(), meta


def _extract_indexes(query: str) -> set[str]:
    return {match.group("idx").strip().lower() for match in _INDEX_RE.finditer(query or "")}


def _extract_sourcetypes(query: str) -> set[str]:
    values: set[str] = set()
    for match in _SOURCETYPE_RE.finditer(query or ""):
        raw = match.group("st").strip().strip('"').strip("'")
        if raw:
            values.add(raw.lower())
    return values


def _extract_shape(query: str) -> str:
    lower = (query or "").lower()
    if "| table " in lower:
        return "table"
    if "| timechart " in lower:
        return "timechart"
    if "| stats " in lower:
        return "stats"
    return "unknown"


def _term_hits(query: str, terms: tuple[str, ...]) -> tuple[int, list[str]]:
    lower = (query or "").lower()
    hits = [term for term in terms if term.lower() in lower]
    missing = [term for term in terms if term.lower() not in lower]
    return len(hits), missing


def _forbidden_hits(query: str, patterns: tuple[str, ...]) -> list[str]:
    hits: list[str] = []
    for pattern in patterns:
        if re.search(pattern, query or "", flags=re.IGNORECASE):
            hits.append(pattern)
    return hits


def _rows_from_structured(structured: dict[str, Any] | None) -> int:
    if not isinstance(structured, dict):
        return 0
    total = structured.get("total_rows")
    if isinstance(total, int):
        return total
    results = structured.get("results", [])
    if isinstance(results, list):
        return len(results)
    return 0


def _execute_query(query_args: dict[str, Any], *, intent: str, skip_mcp: bool) -> tuple[dict[str, Any] | None, str]:
    if skip_mcp:
        return None, "mcp_skipped"
    try:
        run = run_splunk_query_args(query_args, intent=intent, summary_hint="live domain benchmark")
        structured = run.get("structured", {})
        return structured if isinstance(structured, dict) else {}, ""
    except Exception as exc:
        return None, f"{type(exc).__name__}:{exc}"


def _score_comparison(
    case: BenchmarkCase,
    *,
    gold_query: str,
    agtsmith_query: str,
    gold_rows: int,
    agtsmith_rows: int,
    gold_error: str,
    agtsmith_error: str,
    agtsmith_intent: str,
    policy_ok: bool,
) -> dict[str, Any]:
    gold_indexes = _extract_indexes(gold_query)
    agtsmith_indexes = _extract_indexes(agtsmith_query)
    index_overlap = gold_indexes & agtsmith_indexes
    index_match = bool(gold_indexes) and gold_indexes == agtsmith_indexes
    index_partial = bool(index_overlap) and not index_match

    coherent, coherence_reason = validate_platform_sourcetype_coherence(agtsmith_query, agtsmith_intent)
    gold_terms_hit, gold_terms_missing = _term_hits(gold_query, case.required_terms)
    agtsmith_terms_hit, agtsmith_terms_missing = _term_hits(agtsmith_query, case.required_terms)
    required_terms_present = agtsmith_terms_hit == len(case.required_terms) if case.required_terms else True
    forbidden = _forbidden_hits(agtsmith_query, case.forbidden_patterns)

    score = 0
    findings: list[str] = []

    if agtsmith_intent == case.intent:
        score += 15
    else:
        findings.append(f"intent_mismatch:{agtsmith_intent}->{case.intent}")

    if index_match:
        score += 25
    elif index_partial:
        score += 12
        findings.append(f"index_partial:{sorted(index_overlap)} vs gold {sorted(gold_indexes)}")
    else:
        findings.append(f"index_mismatch:gold={sorted(gold_indexes)} agtsmith={sorted(agtsmith_indexes)}")

    if coherent:
        score += 15
    else:
        findings.append(f"sourcetype_coherence:{coherence_reason}")

    if required_terms_present:
        score += 15
    else:
        findings.append(f"required_terms_missing:{agtsmith_terms_missing}")

    if not forbidden:
        score += 10
    else:
        findings.append(f"forbidden_patterns:{forbidden}")

    if policy_ok:
        score += 5
    else:
        findings.append("policy_fail")

    shape = _extract_shape(agtsmith_query)
    if shape == case.expected_shape:
        score += 5
    else:
        findings.append(f"shape_mismatch:{shape}->{case.expected_shape}")

    if not agtsmith_error:
        if agtsmith_rows >= case.min_rows:
            score += 10
        elif case.allow_zero_rows and agtsmith_rows == 0:
            score += 5
            findings.append("zero_rows_allowed")
        else:
            findings.append(f"row_count_low:{agtsmith_rows}<{case.min_rows}")
    else:
        findings.append(f"agtsmith_execution_error:{agtsmith_error}")

    if not gold_error and gold_rows >= case.min_rows:
        score += 5
    elif gold_error:
        findings.append(f"gold_execution_error:{gold_error}")

    if gold_rows > 0 and agtsmith_rows > 0:
        ratio = min(agtsmith_rows, gold_rows) / max(agtsmith_rows, gold_rows)
        if ratio >= 0.5:
            score += 5
        else:
            findings.append(f"row_count_divergence:gold={gold_rows} agtsmith={agtsmith_rows}")

    return {
        "score": max(0, min(100, score)),
        "index_match": index_match,
        "index_partial": index_partial,
        "gold_indexes": sorted(gold_indexes),
        "agtsmith_indexes": sorted(agtsmith_indexes),
        "gold_sourcetypes": sorted(_extract_sourcetypes(gold_query)),
        "agtsmith_sourcetypes": sorted(_extract_sourcetypes(agtsmith_query)),
        "sourcetype_coherence_ok": coherent,
        "sourcetype_coherence_reason": coherence_reason,
        "required_terms_present": required_terms_present,
        "required_terms_hit": agtsmith_terms_hit,
        "required_terms_total": len(case.required_terms),
        "forbidden_patterns_present": forbidden,
        "gold_rows_returned": gold_rows,
        "agtsmith_rows_returned": agtsmith_rows,
        "gold_terms_hit": gold_terms_hit,
        "gold_terms_missing": gold_terms_missing,
        "findings": findings,
    }


def _manifest_expectations(manifest: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not manifest:
        return {}
    raw = manifest.get("benchmark_case_expectations", {})
    if not isinstance(raw, dict):
        return {}
    return {str(k): v for k, v in raw.items() if isinstance(v, dict)}


def _manifest_blocks_case(case: BenchmarkCase, expectations: dict[str, dict[str, Any]]) -> tuple[bool, str]:
    if not case.expected_min_rows_from_manifest:
        return False, ""
    lookup_id = MANIFEST_CASE_ALIASES.get(case.id, case.id)
    entry = expectations.get(lookup_id)
    if entry is None:
        return True, "lab_data_manifest_missing_case"
    if entry.get("ok") is False:
        actual = entry.get("actual_rows")
        min_rows = entry.get("min_rows", case.min_rows)
        return True, f"lab_data_manifest_insufficient:{actual}<{min_rows}"
    return False, ""


def _build_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines = [
        "# Live Domain SPL Benchmark",
        "",
        f"- Timestamp (UTC): `{report.get('timestamp_utc', '')}`",
        f"- Profile: `{report.get('profile_path', '')}`",
        f"- Cases: `{report.get('case_count', 0)}` (completed `{report.get('completed_count', 0)}`, skipped `{report.get('skipped_count', 0)}`)",
        f"- Average score: `{summary.get('avg_score', 0)}`",
        f"- Pass rate (>=85): `{summary.get('pass_rate_pct', 0)}%`",
        "",
        "## Gap table",
        "",
        "| Case | Score | Index match | Coherence | Gold rows | Agtsmith rows | Key finding |",
        "|------|-------|-------------|-----------|-----------|---------------|-------------|",
    ]
    for row in report.get("results", []):
        if row.get("status") != "completed":
            status = row.get("status", "unknown")
            lines.append(
                f"| {row.get('id', '')} | — | — | — | — | — | `{status}`: {row.get('skip_reason') or row.get('error', '')} |"
            )
            continue
        cmp = row.get("comparison", {})
        findings = cmp.get("findings", [])
        key = findings[0] if findings else "pass"
        idx = "yes" if cmp.get("index_match") else "partial" if cmp.get("index_partial") else "no"
        coh = "yes" if cmp.get("sourcetype_coherence_ok") else "no"
        lines.append(
            f"| {row['id']} | {cmp.get('score', 0)} | {idx} | {coh} | "
            f"{cmp.get('gold_rows_returned', 0)} | {cmp.get('agtsmith_rows_returned', 0)} | {key} |"
        )
    lines.extend(["", "## Cases"])
    for row in report.get("results", []):
        lines.append(f"### {row.get('id', 'unknown')}")
        lines.append(f"- question: {row.get('question', '')}")
        if row.get("status") != "completed":
            lines.append(f"- status: `{row.get('status')}`")
            if row.get("skip_reason"):
                lines.append(f"- skip_reason: `{row['skip_reason']}`")
            lines.append("")
            continue
        cmp = row.get("comparison", {})
        lines.append(f"- intent: `{row.get('intent')}` (agtsmith=`{row.get('agtsmith_intent')}`)")
        lines.append(f"- score: `{cmp.get('score', 0)}`")
        lines.append(f"- gold indexes: `{cmp.get('gold_indexes', [])}`")
        lines.append(f"- agtsmith indexes: `{cmp.get('agtsmith_indexes', [])}`")
        lines.append(f"- gold sourcetypes: `{cmp.get('gold_sourcetypes', [])}`")
        lines.append(f"- agtsmith sourcetypes: `{cmp.get('agtsmith_sourcetypes', [])}`")
        lines.append("")
        lines.append("**Gold SPL**")
        lines.append("```spl")
        lines.append(str(row.get("gold_spl_rendered", "")))
        lines.append("```")
        lines.append("")
        lines.append("**Agtsmith SPL**")
        lines.append("```spl")
        lines.append(str(row.get("agtsmith_spl", "")))
        lines.append("```")
        if cmp.get("findings"):
            lines.append("- findings:")
            for finding in cmp["findings"]:
                lines.append(f"  - `{finding}`")
        lines.append("")
    smoke = report.get("failed_logons_smoke")
    if isinstance(smoke, dict):
        lines.extend(["## Failed logons smoke (P0 hotfix)", ""])
        lines.append(f"- question: `{smoke.get('question', '')}`")
        lines.append(f"- agtsmith intent: `{smoke.get('agtsmith_intent', '')}`")
        lines.append(f"- index_match: `{smoke.get('index_match', False)}`")
        lines.append(f"- no_4625: `{smoke.get('no_4625', False)}`")
        lines.append("")
        lines.append("**Gold SPL**")
        lines.append("```spl")
        lines.append(str(smoke.get("gold_spl", "")))
        lines.append("```")
        lines.append("")
        lines.append("**Agtsmith SPL**")
        lines.append("```spl")
        lines.append(str(smoke.get("agtsmith_spl", "")))
        lines.append("```")
        lines.append("")
    return "\n".join(lines) + "\n"


def _failed_logons_smoke(profile_path: Path, *, skip_mcp: bool) -> dict[str, Any]:
    """One-off comparison for the P0 'Failed logons in the last 24 hours' routing fix."""
    question = "Failed logons in the last 24 hours"
    smoke_case = _row_to_case(
        {
            "id": "failed_logons_smoke",
            "theme": "auth",
            "question": question,
            "intent": "linux_auth_failures",
            "profile_domain_hints": {
                "platform": "linux",
                "use_cases": ["linux_auth_failures", "failed_login_activity"],
                "preferred_sourcetypes": ["auth.log", "linux_secure"],
            },
            "expected_shape": "stats",
            "required_terms": ["Failed password", "stats"],
            "forbidden_patterns": [r"\b4625\b", "index=windows"],
            "allow_zero_rows": True,
            "min_rows": 0,
        }
    )
    try:
        gold_query, _ = render_gold_spl(smoke_case, profile_path)
    except Exception as exc:
        return {"question": question, "error": f"gold_render_error:{exc}"}

    mapped = map_question_to_template(question, profile_path=profile_path)
    agtsmith_args = template_to_query_args(mapped, question, apply_environment=True, profile_path=profile_path)
    agtsmith_query = str(agtsmith_args.get("query", "")).strip()
    gold_indexes = _extract_indexes(gold_query)
    agtsmith_indexes = _extract_indexes(agtsmith_query)
    return {
        "question": question,
        "agtsmith_intent": mapped.intent,
        "gold_spl": gold_query,
        "agtsmith_spl": agtsmith_query,
        "index_match": gold_indexes == agtsmith_indexes and bool(gold_indexes),
        "gold_indexes": sorted(gold_indexes),
        "agtsmith_indexes": sorted(agtsmith_indexes),
        "no_4625": "4625" not in agtsmith_query,
        "no_append": "| append [" not in agtsmith_query.lower(),
        "coherent": validate_platform_sourcetype_coherence(agtsmith_query, mapped.intent)[0],
        "mcp_skipped": skip_mcp,
    }


def run_benchmark(
    *,
    benchmark_path: Path,
    profile_path: Path,
    out_root: Path,
    skip_mcp: bool = False,
    use_full_pipeline: bool = False,
    prefer_runtime_cases: bool = True,
    earliest_time: str = DEFAULT_EARLIEST_TIME,
) -> dict[str, Any]:
    cases = _load_cases(benchmark_path, profile_path=profile_path, prefer_runtime=prefer_runtime_cases)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = out_root / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)

    profile = load_environment_profile(profile_path)
    profile_meta = {
        "timestamp_utc": profile.get("timestamp_utc", ""),
        "source": profile.get("source", ""),
        "index_count": len(profile.get("indexes", [])),
    }

    verify_manifest = read_verify_manifest() if read_verify_manifest is not None else None
    manifest_expectations = _manifest_expectations(verify_manifest)

    results: list[dict[str, Any]] = []
    for idx, case in enumerate(cases, start=1):
        print(f"[live-benchmark] {idx}/{len(cases)} case={case.id}")
        row: dict[str, Any] = {"id": case.id, "theme": case.theme, "question": case.question, "intent": case.intent}

        if case.skip_if_no_windows_domain and not _windows_domain_available(profile_path):
            row["status"] = "skipped"
            row["skip_reason"] = "no_windows_domain_in_profile"
            results.append(row)
            continue

        if case.skip_if_no_cloud_domain and not _cloud_domain_available(profile_path):
            row["status"] = "skipped"
            row["skip_reason"] = "no_cloud_domain_in_profile"
            results.append(row)
            continue

        blocked, block_reason = _manifest_blocks_case(case, manifest_expectations)
        if blocked and not skip_mcp:
            row["status"] = "failed"
            row["failure_reason"] = block_reason
            row["comparison"] = {
                "score": 0,
                "findings": [block_reason],
                "gold_rows_returned": 0,
                "agtsmith_rows_returned": 0,
            }
            results.append(row)
            continue

        try:
            gold_query, gold_meta = render_gold_spl(case, profile_path)
        except Exception as exc:
            row["status"] = "error"
            row["error"] = f"gold_render_error:{type(exc).__name__}:{exc}"
            results.append(row)
            continue

        time_window = {"earliest_time": earliest_time, "latest_time": "now", "row_limit": 20}
        gold_args = {"query": gold_query, **time_window}

        if use_full_pipeline:
            from langgraph_multi_model_soc import run_multi_model_soc

            payload = run_multi_model_soc(case.question, write_artifact=False)
            result = payload.get("result", {}) if isinstance(payload, dict) else {}
            agtsmith_intent = str(result.get("intent", "")).strip() or case.intent
            agtsmith_args = result.get("query_args", {}) if isinstance(result.get("query_args"), dict) else {}
            policy_ok = str(result.get("validation_reason", "")).startswith("plan_valid")
            policy_reason = str(result.get("validation_reason", ""))
        else:
            mapped = map_question_to_template(case.question, profile_path=profile_path)
            agtsmith_intent = mapped.intent
            agtsmith_args = template_to_query_args(
                mapped,
                case.question,
                apply_environment=True,
                profile_path=profile_path,
            )
            policy_ok, policy_reason = validate_query_args(agtsmith_args, question=case.question)

        agtsmith_query = str(agtsmith_args.get("query", "")).strip()
        agtsmith_exec_args = {**agtsmith_args, **time_window}

        gold_structured, gold_error = _execute_query(gold_args, intent=case.intent, skip_mcp=skip_mcp)
        agtsmith_structured, agtsmith_error = _execute_query(
            agtsmith_exec_args, intent=agtsmith_intent, skip_mcp=skip_mcp
        )

        if not policy_ok and not skip_mcp:
            agtsmith_error = agtsmith_error or policy_reason

        comparison = _score_comparison(
            case,
            gold_query=gold_query,
            agtsmith_query=agtsmith_query,
            gold_rows=_rows_from_structured(gold_structured),
            agtsmith_rows=_rows_from_structured(agtsmith_structured),
            gold_error=gold_error,
            agtsmith_error=agtsmith_error,
            agtsmith_intent=agtsmith_intent,
            policy_ok=policy_ok,
        )

        row.update(
            {
                "status": "completed",
                "gold_spl_rendered": gold_query,
                "gold_domain_meta": gold_meta,
                "agtsmith_spl": agtsmith_query,
                "agtsmith_intent": agtsmith_intent,
                "policy_ok": policy_ok,
                "policy_reason": policy_reason,
                "gold_execution_error": gold_error,
                "agtsmith_execution_error": agtsmith_error,
                "comparison": comparison,
                "expected_shape": case.expected_shape,
            }
        )
        results.append(row)

    completed = [row for row in results if row.get("status") == "completed"]
    avg_score = round(sum(row["comparison"]["score"] for row in completed) / max(1, len(completed)), 1)
    report = {
        **build_manifest(extra={"benchmark_type": "live_domain", "skip_mcp": skip_mcp}),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "benchmark_path": str(benchmark_path),
        "profile_path": str(profile_path),
        "earliest_time": earliest_time,
        "profile_meta": profile_meta,
        "case_count": len(cases),
        "completed_count": len(completed),
        "skipped_count": sum(1 for row in results if row.get("status") == "skipped"),
        "error_count": sum(1 for row in results if row.get("status") == "error"),
        "summary": {
            "avg_score": avg_score,
            "pass_count": sum(1 for row in completed if row["comparison"]["score"] >= 85),
            "pass_rate_pct": round(100 * sum(1 for row in completed if row["comparison"]["score"] >= 85) / max(1, len(completed)), 1),
        },
        "results": results,
    }

    report["failed_logons_smoke"] = _failed_logons_smoke(profile_path, skip_mcp=skip_mcp)
    report["cases_source"] = "runtime_profile" if prefer_runtime_cases else "benchmark_json"

    report_path = out_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    report_md_path = out_dir / "report.md"
    report_md_path.write_text(_build_markdown(report), encoding="utf-8")

    rendered_cases = []
    for row in results:
        if row.get("status") != "completed":
            continue
        rendered_cases.append(
            {
                "id": row["id"],
                "question": row["question"],
                "intent": row["intent"],
                "profile_domain_hints": next(c.profile_domain_hints for c in cases if c.id == row["id"]),
                "gold_spl_rendered": row.get("gold_spl_rendered", ""),
                "expected_shape": row.get("expected_shape", ""),
                "comparison_score": row["comparison"]["score"],
            }
        )
    (out_dir / "rendered_benchmark.json").write_text(json.dumps({"cases": rendered_cases}, indent=2) + "\n", encoding="utf-8")

    print(f"[live-benchmark] report={report_path}")
    print(f"[live-benchmark] report_md={report_md_path}")
    print(f"[live-benchmark] avg_score={avg_score} completed={len(completed)}/{len(cases)}")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Run profile-driven live-domain SPL benchmark")
    parser.add_argument("--benchmark", default=str(DEFAULT_BENCHMARK_PATH))
    parser.add_argument("--profile", default=str(PROFILE_PATH_DEFAULT))
    parser.add_argument("--out-root", default=str(DEFAULT_OUT_ROOT))
    parser.add_argument("--skip-mcp", action="store_true", help="Skip MCP execution (offline compare only)")
    parser.add_argument("--use-full-pipeline", action="store_true", help="Use run_multi_model_soc instead of template path")
    parser.add_argument(
        "--cases-from-json",
        action="store_true",
        help="Load case list from benchmark JSON instead of runtime profile filtering (default: runtime)",
    )
    parser.add_argument(
        "--earliest-time",
        default=DEFAULT_EARLIEST_TIME,
        choices=list(EARLIEST_TIME_CHOICES),
        help="Splunk earliest_time for MCP execution (default: -7d; use -24h for an explicit one-day run)",
    )
    args = parser.parse_args()

    report = run_benchmark(
        benchmark_path=Path(args.benchmark),
        profile_path=Path(args.profile),
        out_root=Path(args.out_root),
        skip_mcp=args.skip_mcp,
        use_full_pipeline=args.use_full_pipeline,
        prefer_runtime_cases=not args.cases_from_json,
        earliest_time=args.earliest_time,
    )
    return 0 if report.get("error_count", 0) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
