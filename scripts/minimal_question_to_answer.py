#!/usr/bin/env python3
"""Minimal question -> Splunk MCP -> Ollama answer pipeline (lab).

Scope (intentionally small):
- Accept one question string
- Map to one safe, bounded Splunk query template
- Execute via MCP tools/call (splunk_run_query)
- Summarize structured results with Ollama HTTP API

This is an educational baseline, not production routing logic.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from typing import Any

import httpx
from botsv3_catalog import extract_explicit_botsv3_sourcetype
from question_intelligence import infer_question_dimensions, infer_time_window, score_template_for_question
from query_templates import DEFAULT_TEMPLATE, TEMPLATES, QueryTemplate
from runtime_config import get_ollama_host, get_runtime_secret, get_splunk_mcp_url

OLLAMA_HOST = get_ollama_host()
DEFAULT_OLLAMA_MODEL_PRIMARY = "hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
DEFAULT_OLLAMA_MODEL_REASONING = "hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL_PRIMARY", DEFAULT_OLLAMA_MODEL_PRIMARY)
OLLAMA_REASONING_MODEL = os.getenv("OLLAMA_MODEL_REASONING", DEFAULT_OLLAMA_MODEL_REASONING)

# LAB-ONLY / TEMPORARY / NOT PRODUCTION SAFE
LAB_BEARER_TOKEN_FALLBACK = "REPLACE_WITH_SPLUNK_MCP_BEARER_TOKEN"


def map_question_to_template(question: str) -> QueryTemplate:
    """Map a question to one safe query template.

    Template list is intentionally small and explicit for baseline lab behavior.
    """
    normalized = question.lower()
    dims = infer_question_dimensions(question)
    platforms = set(dims.get("platforms", []))
    activities = set(dims.get("activities", []))
    first_seen_priv_esc = any(
        tok in normalized
        for tok in (
            "first time privilege escalation",
            "first privilege escalation",
            "first seen privilege escalation",
            "first time sudo",
            "first seen sudo",
            "first time su",
            "first observed sudo",
            "first observed root session",
            "newly observed sudo",
            "new sudo behavior",
            "show new sudo behavior",
        )
    )
    failed_priv_esc = any(
        tok in normalized
        for tok in (
            "failed sudo",
            "sudo failure",
            "failed privilege escalation",
            "failed su",
            "privilege escalation attempts",
        )
    )
    priv_esc_activity = any(
        tok in normalized
        for tok in (
            "sudo behavior",
            "sudo activity",
            "su behavior",
            "su activity",
            "root session",
            "sudo sessions",
            "preserve context sudo",
        )
    )
    explicit_botsv3_sourcetype = extract_explicit_botsv3_sourcetype(question)
    explicit_botsv3_overview = explicit_botsv3_sourcetype and (
        "overview of sourcetype" in normalized or "show an overview of sourcetype" in normalized
    )
    if first_seen_priv_esc:
        for template in TEMPLATES:
            if template.intent == "linux_privilege_escalation_first_seen":
                return template
    if failed_priv_esc:
        for template in TEMPLATES:
            if template.intent == "linux_privilege_escalation":
                return template
    if priv_esc_activity:
        for template in TEMPLATES:
            if template.intent == "linux_privilege_escalation_activity":
                return template
    if "auth_success" in activities and platforms == {"linux"}:
        for template in TEMPLATES:
            if template.intent == "linux_successful_logins":
                return template
    if "auth_success" in activities and platforms == {"windows"}:
        for template in TEMPLATES:
            if template.intent == "windows_successful_logons":
                return template
    if platforms == {"windows", "linux"} and "auth_success" in activities:
        for template in TEMPLATES:
            if template.intent == "successful_login_activity":
                return template
    if platforms == {"windows", "linux"} and "auth_failure" in activities:
        for template in TEMPLATES:
            if template.intent == "failed_login_activity":
                return template
    if "windows" in platforms and "dns_activity" in activities and "sysmon" in normalized:
        for template in TEMPLATES:
            if template.intent == "windows_sysmon_dns_activity":
                return template
    if "windows" in platforms and "network_activity" in activities and "sysmon" in normalized:
        for template in TEMPLATES:
            if template.intent == "windows_sysmon_network_activity":
                return template
    if "windows" in platforms and "process_activity" in activities:
        for template in TEMPLATES:
            if template.intent == "windows_process_activity":
                return template
    if "apache" in normalized and any(tok in normalized for tok in ("logon attempt", "login attempt", "weird logon", "weird login", "failed login")):
        for template in TEMPLATES:
            if template.intent == "apache_access_top_ips":
                return template
    if explicit_botsv3_overview:
        for template in TEMPLATES:
            if template.intent == "botsv3_named_sourcetype_overview":
                return template
    best_template: QueryTemplate | None = None
    best_score: tuple[int, int, int] = (-999, 0, 0)
    for template in TEMPLATES:
        matched = [kw for kw in template.keywords if kw in normalized]
        family_score, _reasons = score_template_for_question(template, question)
        if family_score <= -20 and not matched:
            continue
        # Prefer question-family score first, then more keyword hits, then longer phrase.
        score = (
            family_score,
            len(matched),
            max((len(kw) for kw in matched), default=0),
        )
        if score > best_score:
            best_template = template
            best_score = score
    if best_template is not None:
        if "windows" in dims.get("platforms", []) and best_template.intent == "successful_login_activity":
            for template in TEMPLATES:
                if template.intent == "windows_successful_logons":
                    return template
        if "linux" in dims.get("platforms", []) and best_template.intent == "successful_login_activity":
            for template in TEMPLATES:
                if template.intent == "linux_successful_logins":
                    return template
        if "windows" in dims.get("platforms", []) and best_template.intent == "failed_login_activity":
            for template in TEMPLATES:
                if template.intent == "windows_auth_failures":
                    return template
        if "linux" in dims.get("platforms", []) and best_template.intent == "failed_login_activity":
            for template in TEMPLATES:
                if template.intent == "linux_auth_failures":
                    return template
    if best_template is not None:
        return best_template
    return DEFAULT_TEMPLATE


def _dynamic_query_for_question(template: QueryTemplate, question: str) -> str:
    dims = infer_question_dimensions(question)
    platforms = set(dims.get("platforms", []))
    activities = set(dims.get("activities", []))
    q = (question or "").lower()
    explicit_botsv3_sourcetype = extract_explicit_botsv3_sourcetype(question)

    if "auth_success" in activities and platforms == {"windows", "linux"}:
        return (
            "search ("
            "(index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
            "(\"Accepted password\" OR \"Accepted publickey\" OR \"Accepted keyboard-interactive/pam\" OR \"session opened for user\")) "
            "OR "
            "((index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog "
            "(EventCode=4624 OR EventID=4624 OR \"An account was successfully logged on\"))"
            ") "
            "| rex field=_raw \"(?i)Accepted (?:password|publickey|keyboard-interactive/pam) for (?<success_user>[^ ]+)\" "
            "| rex field=_raw \"(?i)from (?<success_src_ip>\\d{1,3}(?:\\.\\d{1,3}){3}) port (?<success_port>\\d+)\" "
            "| rex field=_raw \"(?i)session opened for user (?<session_user>[A-Za-z0-9_.-]+)\" "
            "| eval src_ip=coalesce(Source_Network_Address,IpAddress,src,src_ip,clientip,success_src_ip,ip) "
            "| eval src_ip=coalesce(src_ip,rhost,\"local\") "
            "| eval user_name=coalesce(TargetUserName,SubjectUserName,Account_Name,user,username,account,success_user,session_user) "
            "| eval port=coalesce(port,success_port,DestinationPort,dest_port) "
            "| stats count by index host source sourcetype user_name src_ip port | sort - count"
        )
    if "auth_failure" in activities and platforms == {"windows", "linux"}:
        return (
            "search ("
            "(index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
            "(\"Failed password\" OR \"authentication failure\" OR \"Invalid user\" OR \"Connection closed by invalid user\" OR \"FAILED SU\")) "
            "OR "
            "((index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog "
            "(EventCode=4625 OR EventID=4625 OR \"An account failed to log on\"))"
            ") "
            "| rex field=_raw \"(?i)Failed password for (?:invalid user )?(?<failed_user>[^ ]+)\" "
            "| rex field=_raw \"(?i)user=(?<pam_user>[^\\s;]+)\" "
            "| rex field=_raw \"(?i)from (?<failed_src_ip>\\d{1,3}(?:\\.\\d{1,3}){3}) port (?<failed_port>\\d+)\" "
            "| rex field=_raw \"(?i)rhost=(?<failed_rhost>[^\\s;]+)\" "
            "| eval src_ip=coalesce(Source_Network_Address,IpAddress,src,src_ip,clientip,rhost,ip) "
            "| eval src_ip=coalesce(src_ip,failed_src_ip,failed_rhost,\"local\") "
            "| eval user_name=coalesce(TargetUserName,SubjectUserName,Account_Name,user,username,account,failed_user,pam_user) "
            "| eval port=coalesce(port,failed_port) "
            "| stats count by index host source sourcetype user_name src_ip port | sort - count"
        )
    if template.intent == "linux_privilege_escalation":
        query = template.query
        if re.search(r"\bfailed sudo\b", q):
            query = query.replace(
                "((\"pam_unix(sudo:auth): authentication failure\" OR \"pam_unix(su:auth): authentication failure\" OR \"conversation failed\") OR ((\"sudo:\" OR \"su:\") (\"authentication failure\" OR \"incorrect password\" OR \"incorrect password attempts\" OR \"failed\")))",
                "((\"pam_unix(sudo:auth): authentication failure\" OR \"conversation failed\") OR (\"sudo:\" (\"authentication failure\" OR \"incorrect password\" OR \"incorrect password attempts\" OR \"failed\")))",
            )
        elif re.search(r"\bfailed su\b", q):
            query = query.replace(
                "((\"pam_unix(sudo:auth): authentication failure\" OR \"pam_unix(su:auth): authentication failure\" OR \"conversation failed\") OR ((\"sudo:\" OR \"su:\") (\"authentication failure\" OR \"incorrect password\" OR \"incorrect password attempts\" OR \"failed\")))",
                "(\"pam_unix(su:auth): authentication failure\" OR (\"su:\" (\"authentication failure\" OR \"incorrect password\" OR \"incorrect password attempts\" OR \"failed\")))",
            )
        return query
    if template.intent == "botsv3_named_sourcetype_overview" and explicit_botsv3_sourcetype:
        return template.query.replace("PLACEHOLDER_SOURCETYPE", explicit_botsv3_sourcetype)
    return template.query


def _apply_dataset_scope(query: str, question: str) -> str:
    q = (question or "").lower()
    if "botsv3" not in q:
        return query

    scoped = query
    replacements = (
        ("index=linux", "index=botsv3"),
        ("index=main", "index=botsv3"),
        ("index=* NOT index=_*", "index=botsv3"),
        ("(index=windows OR index=windows_sysmon)", "index=botsv3"),
    )
    for old, new in replacements:
        scoped = scoped.replace(old, new)
    return scoped


def _extract_explicit_hosts(question: str) -> list[str]:
    """Return obvious host tokens explicitly named in the analyst question."""
    q = (question or "").strip()
    if not q:
        return []
    patterns = (
        r"\bpidx\d+\b",
        r"\brpi\d+\b",
        r"\bsplunk[a-z0-9_-]+\b",
        r"\bip-\d+(?:-\d+){3}\b",
    )
    found: list[str] = []
    seen: set[str] = set()
    for pattern in patterns:
        for match in re.findall(pattern, q, flags=re.IGNORECASE):
            host = match.strip()
            host_l = host.lower()
            if host_l not in seen:
                seen.add(host_l)
                found.append(host)
    return found


def _apply_host_scope(query: str, question: str) -> str:
    hosts = _extract_explicit_hosts(question)
    if not hosts:
        return query
    host_clause = "host IN (" + ",".join(hosts) + ") "
    if "|" in query:
        head, tail = query.split("|", 1)
        return head.replace("search ", f"search {host_clause}", 1).rstrip() + " |" + tail
    return query.replace("search ", f"search {host_clause}", 1)


def _extract_explicit_user(question: str) -> str:
    q = (question or "").strip()
    if not q:
        return ""
    patterns = (
        r"\buser\s+([A-Za-z0-9_.-]+)\b",
        r"\busername\s+([A-Za-z0-9_.-]+)\b",
        r"\baccount\s+([A-Za-z0-9_.-]+)\b",
    )
    for pattern in patterns:
        match = re.search(pattern, q, flags=re.IGNORECASE)
        if match:
            candidate = match.group(1).strip()
            if candidate and candidate.lower() not in {"any", "all", "unknown"}:
                return candidate
    return ""


def _apply_user_scope(query: str, question: str) -> str:
    user_name = _extract_explicit_user(question)
    if not user_name:
        return query
    if '| search user_name="' in query.lower() or '| search user="' in query.lower():
        return query
    if "user_name" in query:
        return query.replace("| stats", f'| search user_name="{user_name}" | stats', 1)
    if " count by host user " in query or " by host user " in query:
        return query.replace("| stats", f'| search user="{user_name}" | stats', 1)
    if " count by host process_name actor " in query or " actor " in query:
        return query.replace("| stats", f'| search actor="{user_name}" | stats', 1)
    return query


def template_to_query_args(template: QueryTemplate, question: str = "", *, apply_environment: bool = True) -> dict[str, Any]:
    query = template.query
    if question:
        query = _dynamic_query_for_question(template, question)
        query = _apply_dataset_scope(query, question)
        query = _apply_host_scope(query, question)
        query = _apply_user_scope(query, question)
        if query and apply_environment:
            from environment_profile import apply_environment_query_constraints

            query = apply_environment_query_constraints(question, template.intent, query)
        earliest_time, latest_time = infer_time_window(
            question,
            default_earliest=template.earliest_time,
            default_latest=template.latest_time,
        )
    else:
        earliest_time, latest_time = template.earliest_time, template.latest_time
    return {
        "query": query,
        "earliest_time": earliest_time,
        "latest_time": latest_time,
        "row_limit": template.row_limit,
    }


def mcp_call(client: httpx.Client, headers: dict[str, str], payload: dict[str, Any]) -> tuple[int, Any]:
    resp = client.post(get_splunk_mcp_url(), headers=headers, json=payload)
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, (resp.text or "").strip()


def _mcp_headers() -> dict[str, str]:
    token = get_runtime_secret("SPLUNK_LAB_BEARER_TOKEN", LAB_BEARER_TOKEN_FALLBACK)
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
    }


def _mcp_initialize_payload() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "agtsmith-lab", "version": "0.1.0"},
        },
    }


def _run_mcp_tool(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    max_attempts: int = 3,
    retry_backoff_seconds: float = 1.25,
) -> tuple[dict[str, Any], dict[str, Any]]:
    headers = _mcp_headers()

    init_payload = {
        **_mcp_initialize_payload(),
        "id": 1,
    }

    tool_payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    }
    last_error = ""
    for attempt in range(1, max_attempts + 1):
        try:
            with httpx.Client(timeout=90.0, verify=False, follow_redirects=True) as client:
                init_status, init_body = mcp_call(client, headers, init_payload)
                tool_status, tool_body = mcp_call(client, headers, tool_payload)

            if init_status != 200:
                raise RuntimeError(f"MCP initialize failed with HTTP {init_status}: {init_body}")
            if tool_status != 200:
                raise RuntimeError(f"MCP tool call failed with HTTP {tool_status}: {tool_body}")
            if not isinstance(tool_body, dict):
                raise RuntimeError(f"MCP tool call returned non-JSON response: {tool_body}")
            if "error" in tool_body:
                raise RuntimeError(f"MCP JSON-RPC error: {tool_body['error']}")

            result = tool_body.get("result", {}) if isinstance(tool_body, dict) else {}
            structured = result.get("structuredContent", {}) if isinstance(result, dict) else {}
            return result, structured
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt < max_attempts:
                time.sleep(retry_backoff_seconds * attempt)
                continue
            break

    raise RuntimeError(
        f"MCP tool call failed after {max_attempts} attempts for {tool_name}: {last_error or 'unknown_error'}"
    )


def run_splunk_query(question: str) -> dict[str, Any]:
    template = map_question_to_template(question)
    query_args = template_to_query_args(template, question)
    return run_splunk_query_args(
        query_args,
        intent=template.intent,
        summary_hint=template.summary_hint,
    )


def run_splunk_query_args(
    query_args: dict[str, Any],
    *,
    intent: str = "custom_query",
    summary_hint: str = "Summarize key findings and suggest a next investigative check.",
) -> dict[str, Any]:
    result, structured = _run_mcp_tool("splunk_run_query", query_args)
    return {
        "intent": intent,
        "summary_hint": summary_hint,
        "mapped_query": query_args,
        "raw_result": result,
        "structured": structured,
    }


def run_splunk_get_indexes() -> dict[str, Any]:
    result, structured = _run_mcp_tool("splunk_get_indexes", {})
    return {
        "tool": "splunk_get_indexes",
        "mapped_query": {},
        "raw_result": result,
        "structured": structured,
    }


def run_splunk_get_info() -> dict[str, Any]:
    result, structured = _run_mcp_tool("splunk_get_info", {})
    return {
        "tool": "splunk_get_info",
        "mapped_query": {},
        "raw_result": result,
        "structured": structured,
    }


def run_splunk_get_metadata(metadata_args: dict[str, Any]) -> dict[str, Any]:
    result, structured = _run_mcp_tool("splunk_get_metadata", metadata_args)
    return {
        "tool": "splunk_get_metadata",
        "mapped_query": metadata_args,
        "raw_result": result,
        "structured": structured,
    }


def summarize_with_ollama(question: str, splunk_data: dict[str, Any]) -> str:
    rows = splunk_data.get("structured", {}).get("results", [])
    total_rows = splunk_data.get("structured", {}).get("total_rows")

    context = {
        "question": question,
        "intent": splunk_data.get("intent"),
        "summary_hint": splunk_data.get("summary_hint"),
        "query_used": splunk_data.get("mapped_query", {}),
        "total_rows": total_rows,
        "rows": rows,
    }

    prompt = (
        "You are a SOC analyst assistant in a lab. "
        "Summarize the query result in plain English in 4-6 bullet points. "
        "Include: what was queried, top findings, and one suggested next check.\n\n"
        f"DATA:\n{json.dumps(context, indent=2)}"
    )

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "think": False,
    }

    with httpx.Client(timeout=120.0) as client:
        resp = client.post(f"{OLLAMA_HOST}/api/generate", json=payload)
        resp.raise_for_status()
        body = resp.json()

    text = (body.get("response") or "").strip()
    if not text:
        raise RuntimeError(
            "Ollama summary returned empty text "
            f"(done={body.get('done')} done_reason={body.get('done_reason')})"
        )

    return text


def summarize_with_ollama_model(
    question: str,
    splunk_data: dict[str, Any],
    *,
    model: str | None = None,
    think: bool = False,
) -> str:
    rows = splunk_data.get("structured", {}).get("results", [])
    total_rows = splunk_data.get("structured", {}).get("total_rows")

    context = {
        "question": question,
        "intent": splunk_data.get("intent"),
        "summary_hint": splunk_data.get("summary_hint"),
        "query_used": splunk_data.get("mapped_query", {}),
        "total_rows": total_rows,
        "rows": rows,
    }
    prompt = (
        "You are a SOC analyst assistant in a lab. "
        "Summarize the query result in plain English in 4-6 bullet points. "
        "Include: what was queried, top findings, and one suggested next check.\n\n"
        f"DATA:\n{json.dumps(context, indent=2)}"
    )
    payload = {
        "model": model or OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "think": think,
    }
    with httpx.Client(timeout=120.0) as client:
        resp = client.post(f"{OLLAMA_HOST}/api/generate", json=payload)
        resp.raise_for_status()
        body = resp.json()
    text = (body.get("response") or "").strip()
    if not text:
        raise RuntimeError(
            "Ollama summary returned empty text "
            f"(done={body.get('done')} done_reason={body.get('done_reason')})"
        )
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.IGNORECASE | re.DOTALL)
    text = text.replace("<think>", "").replace("</think>", "").strip()
    markers = (
        "Here's a concise summary",
        "Here is a concise summary",
        "Based on the query result",
        "Summary of the query results",
    )
    lower = text.lower()
    for marker in markers:
        idx = lower.find(marker.lower())
        if idx > 0:
            text = text[idx:].strip()
            break
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description="Minimal question -> Splunk -> Ollama flow")
    parser.add_argument(
        "question",
        nargs="?",
        default="What sourcetypes generated the most _internal events in the last 24 hours?",
        help="Natural-language SOC question",
    )
    args = parser.parse_args()

    question = args.question

    print("=== Question ===")
    print(question)

    splunk_data = run_splunk_query(question)
    rows = splunk_data.get("structured", {}).get("results", [])
    total_rows = splunk_data.get("structured", {}).get("total_rows")

    print("\n=== Query Mapping ===")
    print(json.dumps(splunk_data.get("mapped_query", {}), indent=2))

    print("\n=== Retrieval Summary ===")
    print(f"rows_returned={len(rows) if isinstance(rows, list) else 'n/a'}")
    print(f"total_rows={total_rows}")

    summary = summarize_with_ollama(question, splunk_data)
    print("\n=== Ollama SOC Summary ===")
    print(summary)

    return 0


if __name__ == "__main__":
    sys.exit(main())
