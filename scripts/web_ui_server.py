#!/usr/bin/env python3
"""Local web UI for the SOC lab with docs portal and architecture view."""

from __future__ import annotations

import argparse
import base64
import html
import hashlib
import hmac
import json
import os
import queue
import re
import secrets
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from http.cookies import SimpleCookie
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

from langgraph_agentic_soc import run_agentic_investigation
from langgraph_case_state import bootstrap_graph_case_state, snapshot_graph_case_state
from langgraph_multi_model_soc import describe_multi_model_graph, run_multi_model_soc
from local_learning import (
    ensure_learning_registry,
    generate_self_learn_candidates,
    learning_registry_summary,
    load_learning_progress,
    set_learning_record_status,
)
from minimal_question_to_answer import (
    map_question_to_template,
    run_splunk_query_args,
    summarize_with_ollama_model,
    template_to_query_args,
)
from ollama_log_stream import (
    RemoteLogSourceRegistry,
    StreamParams,
    format_sse,
    get_remote_health_url,
    redact_secrets,
    role_allowed,
)
from environment_profile import suggest_domains_for_question
from runtime_config import (
    DEFAULT_MODEL_AGENTIC_CONTINUATION_REVIEWER,
    DEFAULT_MODEL_EVIDENCE_REVIEWER,
    DEFAULT_MODEL_FINAL_SUMMARY,
    DEFAULT_MODEL_PEER_REVIEWER,
    DEFAULT_MODEL_PEER_REVIEWER_2,
    DEFAULT_MODEL_QUERY_PLANNER,
    DEFAULT_MODEL_QUERY_REPAIR,
    DEFAULT_MODEL_QUERY_WRITER,
    DEFAULT_MODEL_SECURITY_REVIEWER,
    UI_ENV_PATH,
    display_path,
    get_edge_llm_enabled,
    get_edge_llm_host,
    get_edge_llm_model,
    get_edge_llm_role,
    get_edge_llm_timeout_sec,
    get_ollama_host,
    get_splunk_base_url,
    get_splunk_mcp_url,
    get_runtime_secret,
    parse_env_file,
    write_env_file,
)
from case_store import (
    build_case_timeline,
    case_store_backend,
    load_case,
    load_case_node,
    list_recent_cases,
    persist_case_result,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOCS_ROOT = PROJECT_ROOT / "docs"
ARTIFACTS_ROOT = PROJECT_ROOT / "artifacts"
VERSION_PATH = PROJECT_ROOT / "VERSION"
ENV_PROFILE_PATH = ARTIFACTS_ROOT / "environment" / "environment_profile_latest.json"
ENV_PROFILE_BOOTSTRAP_LOCK = ARTIFACTS_ROOT / "environment" / ".bootstrap.lock"
ENV_PROFILE_REFRESH_LOCK = ARTIFACTS_ROOT / "environment" / ".refresh.lock"
ENV_PROFILE_REFRESH_LOG = ARTIFACTS_ROOT / "environment" / "env_profile_refresh_web.log"
ENV_PROFILE_REFRESH_STATE = ARTIFACTS_ROOT / "environment" / "env_profile_refresh_status.json"
SPL_SKILLPACK_PATH = ARTIFACTS_ROOT / "knowledge" / "spl_skillpack_latest.json"
PERSONALIZATION_LOCK = ARTIFACTS_ROOT / "knowledge" / ".personalization.lock"
PERSONALIZATION_LOG = ARTIFACTS_ROOT / "knowledge" / "personalization_web.log"
PERSONALIZATION_STATE = ARTIFACTS_ROOT / "knowledge" / "personalization_status.json"
LOCAL_LEARNING_LOCK = ARTIFACTS_ROOT / "learning" / ".learning.lock"
LOCAL_LEARNING_LOG = ARTIFACTS_ROOT / "learning" / "local_learning_web.log"
LOCAL_LEARNING_STATE = ARTIFACTS_ROOT / "learning" / "local_learning_status.json"
LOCAL_LEARNING_STALE_SECONDS = 5 * 60
AUDIT_ROOT = ARTIFACTS_ROOT / "audit"
QUERY_AUDIT_LOG = AUDIT_ROOT / "query_runs.jsonl"
LOG_SOURCE_REGISTRY = RemoteLogSourceRegistry()
SESSION_COOKIE_NAME = "soc_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
SESSIONS: dict[str, dict[str, Any]] = {}
SESSIONS_LOCK = threading.Lock()
ALLOWED_APP_ROLES = {"admin", "ops", "analyst"}
EXPECTED_MODEL_KEYS = [
    "OLLAMA_MODEL_QUERY_PLANNER",
    "OLLAMA_MODEL_QUERY_WRITER",
    "OLLAMA_MODEL_QUERY_REPAIR",
    "OLLAMA_MODEL_EVIDENCE_REVIEWER",
    "OLLAMA_MODEL_SECURITY_REVIEWER",
    "OLLAMA_MODEL_PEER_REVIEWER",
    "OLLAMA_MODEL_PEER_REVIEWER_2",
    "OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER",
    "OLLAMA_MODEL_FINAL_SUMMARY",
]
DEFAULT_MODEL_ASSIGNMENTS = {
    "OLLAMA_MODEL_QUERY_PLANNER": DEFAULT_MODEL_QUERY_PLANNER,
    "OLLAMA_MODEL_QUERY_WRITER": DEFAULT_MODEL_QUERY_WRITER,
    "OLLAMA_MODEL_QUERY_REPAIR": DEFAULT_MODEL_QUERY_REPAIR,
    "OLLAMA_MODEL_EVIDENCE_REVIEWER": DEFAULT_MODEL_EVIDENCE_REVIEWER,
    "OLLAMA_MODEL_SECURITY_REVIEWER": DEFAULT_MODEL_SECURITY_REVIEWER,
    "OLLAMA_MODEL_PEER_REVIEWER": DEFAULT_MODEL_PEER_REVIEWER,
    "OLLAMA_MODEL_PEER_REVIEWER_2": DEFAULT_MODEL_PEER_REVIEWER_2,
    "OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER": DEFAULT_MODEL_AGENTIC_CONTINUATION_REVIEWER,
    "OLLAMA_MODEL_FINAL_SUMMARY": DEFAULT_MODEL_FINAL_SUMMARY,
}
EDGE_CONFIG_KEYS = [
    "EDGE_LLM_ENABLED",
    "EDGE_LLM_HOST",
    "EDGE_LLM_MODEL",
    "EDGE_LLM_ROLE",
    "EDGE_LLM_TIMEOUT_SEC",
]
CONFIG_EDITABLE_KEYS = [
    "OLLAMA_HOST",
    "SPLUNK_BASE_URL",
    "SPLUNK_MCP_URL",
    "SPLUNK_LAB_BEARER_TOKEN",
    "SOC_UI_AUTH_ENABLED",
    "SOC_UI_AUTH_USERNAME",
    "SOC_UI_AUTH_PASSWORD",
    "SOC_UI_AUTH_ROLE",
    *EDGE_CONFIG_KEYS,
    *EXPECTED_MODEL_KEYS,
]
DEFAULT_UI_PASSWORDS = {"changeme123!", "SplunkLab-Only-ChangeMe!"}
PASSWORD_HASH_PREFIX = "pbkdf2_sha256:"
LEGACY_PASSWORD_HASH_PREFIX = "pbkdf2_sha256$"


def _load_app_version() -> str:
    try:
        raw = VERSION_PATH.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return "0.0.0-dev"
    return raw or "0.0.0-dev"


APP_VERSION = _load_app_version()
APP_VERSION_LABEL = APP_VERSION if APP_VERSION.startswith("v") else f"v{APP_VERSION}"
TOKEN_MASK_SENTINEL = "__KEEP_EXISTING_SPLUNK_TOKEN__"
DEFAULT_MITRE_VALIDATOR_MODEL = "hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
_SPLUNK_WEB_BASE_CACHE: dict[str, str] = {}


def _mask_secret_display(value: str, visible_suffix: int = 4) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if len(raw) <= visible_suffix:
        return "*" * len(raw)
    masked_prefix = "*" * min(12, max(8, len(raw) - visible_suffix))
    return f"{masked_prefix}...{raw[-visible_suffix:]}"


def _resolve_config_value_for_merge(key: str, incoming: Any, current_values: dict[str, str]) -> str:
    value = str(incoming if incoming is not None else "").strip()
    if key == "SPLUNK_LAB_BEARER_TOKEN" and value == TOKEN_MASK_SENTINEL:
        return get_runtime_secret("SPLUNK_LAB_BEARER_TOKEN", "")
    return value


def _splunk_search_url_base() -> str:
    values = parse_env_file(UI_ENV_PATH)
    if isinstance(values, tuple):
        values = values[0]
    values = values if isinstance(values, dict) else {}
    explicit = str(values.get("SPLUNK_WEB_URL", "")).strip().rstrip("/")
    if explicit:
        return f"{explicit}/en-US/app/search/search"
    base = str(values.get("SPLUNK_BASE_URL", "")).strip().rstrip("/") or str(get_splunk_base_url()).strip().rstrip("/")
    if not base:
        return ""
    parsed = urlparse(base)
    if not parsed.hostname:
        return ""
    host = parsed.hostname
    cached = _SPLUNK_WEB_BASE_CACHE.get(host)
    if cached:
        return cached

    def _probe(candidate: str) -> bool:
        req = urllib.request.Request(
            f"{candidate}/en-US/account/login",
            headers={"User-Agent": "A.G.E.N.T.-Smith/1.2"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(
                req,
                timeout=3.0,
                context=ssl._create_unverified_context() if candidate.startswith("https://") else None,
            ) as resp:
                status = getattr(resp, "status", 200)
                return 200 <= int(status) < 500
        except urllib.error.HTTPError as exc:
            return 200 <= int(exc.code) < 500
        except Exception:
            return False

    candidates = [
        f"https://{host}:8000",
        f"http://{host}:8000",
    ]
    if parsed.scheme in {"http", "https"}:
        preferred = f"{parsed.scheme}://{host}:8000"
        candidates = [preferred] + [item for item in candidates if item != preferred]

    for candidate in candidates:
        if _probe(candidate):
            resolved = f"{candidate}/en-US/app/search/search"
            _SPLUNK_WEB_BASE_CACHE[host] = resolved
            return resolved
    return ""


def _extract_json_object(raw_text: str) -> dict[str, Any]:
    cleaned = str(raw_text or "").strip()
    if not cleaned:
        raise ValueError("empty_model_output")
    try:
        direct = json.loads(cleaned)
        if isinstance(direct, dict):
            return direct
    except Exception:
        pass
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", cleaned):
        try:
            obj, _end = decoder.raw_decode(cleaned[match.start() :])
        except Exception:
            continue
        if isinstance(obj, dict):
            return obj
    raise ValueError("json_object_not_found")


def _call_ollama_json(*, model: str, system_prompt: str, user_payload: dict[str, Any], timeout: float = 90.0) -> dict[str, Any]:
    ollama_host = str(get_ollama_host()).strip().rstrip("/")
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
    req = urllib.request.Request(
        f"{ollama_host}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    raw = str(body.get("response") or "").strip()
    parsed = _extract_json_object(raw)
    parsed["_raw_text_preview"] = raw[:1200]
    return parsed


def _mitre_validator_model() -> str:
    parsed = parse_env_file(UI_ENV_PATH)
    values = parsed[0] if isinstance(parsed, tuple) else parsed
    if not isinstance(values, dict):
        values = {}
    preferred = str(values.get("OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER", "")).strip()
    if preferred:
        return preferred
    fallback = str(values.get("OLLAMA_MODEL_FINAL_SUMMARY", "")).strip()
    return fallback or DEFAULT_MITRE_VALIDATOR_MODEL


def _mitre_attack_validate(result: dict[str, Any], bundle: dict[str, Any]) -> dict[str, Any]:
    techniques = bundle.get("techniques", []) if isinstance(bundle.get("techniques"), list) else []
    if not techniques:
        return {"status": "skipped", "reason": "no_deterministic_mapping"}
    model = _mitre_validator_model()
    summary = str(result.get("summary", "")).strip()
    question = str(result.get("question") or result.get("root_question") or "").strip()
    intent = str(result.get("intent", "")).strip()
    evidence = result.get("evidence", {}) if isinstance(result.get("evidence"), dict) else {}
    top_entities = evidence.get("top_entities", []) if isinstance(evidence.get("top_entities"), list) else []
    key_findings = []
    evidence_reviewer = result.get("evidence_reviewer", {}) if isinstance(result.get("evidence_reviewer"), dict) else {}
    evidence_output = evidence_reviewer.get("output", {}) if isinstance(evidence_reviewer.get("output"), dict) else {}
    if isinstance(evidence_output.get("key_findings"), list):
        key_findings = [str(item).strip() for item in evidence_output.get("key_findings", [])[:6] if str(item).strip()]
    payload = {
        "question": question,
        "intent": intent,
        "summary": summary,
        "deterministic_bundle": bundle,
        "evidence_key_findings": key_findings,
        "top_entities": top_entities[:5],
    }
    system = (
        "You are a MITRE ATT&CK validation reviewer for a Splunk SOC investigation. "
        "Review the deterministic ATT&CK mapping and judge whether it matches the evidence. "
        "Do not invent unsupported claims. If uncertain, stay conservative. "
        "Return JSON with keys: agreement, confidence, rationale, kill_chain_context, "
        "validated_techniques, alternate_techniques. "
        "agreement must be one of: agree, partial, disagree. "
        "validated_techniques and alternate_techniques must be arrays of objects with keys: tactic, technique, technique_id, why."
    )
    try:
        raw = _call_ollama_json(model=model, system_prompt=system, user_payload=payload)
    except Exception as exc:
        return {
            "status": "unavailable",
            "model": model,
            "reason": f"{type(exc).__name__}: {exc}",
        }
    validated = raw.get("validated_techniques", [])
    alternates = raw.get("alternate_techniques", [])
    kill_chain_context = raw.get("kill_chain_context", "")
    if isinstance(kill_chain_context, dict):
        kill_chain_context = " | ".join(
            f"{k}={v}" for k, v in kill_chain_context.items() if str(v).strip()
        )
    elif isinstance(kill_chain_context, list):
        kill_chain_context = " | ".join(str(item).strip() for item in kill_chain_context if str(item).strip())
    return {
        "status": "ok",
        "model": model,
        "agreement": str(raw.get("agreement", "")).strip() or "partial",
        "confidence": str(raw.get("confidence", "")).strip() or "medium",
        "rationale": str(raw.get("rationale", "")).strip(),
        "kill_chain_context": str(kill_chain_context).strip(),
        "validated_techniques": [item for item in validated if isinstance(item, dict)][:5],
        "alternate_techniques": [item for item in alternates if isinstance(item, dict)][:5],
        "_raw_text_preview": str(raw.get("_raw_text_preview", "")).strip(),
    }


def _mitre_attack_bundle(result: dict[str, Any]) -> dict[str, Any]:
    intent = str(result.get("intent", "")).strip().lower()
    summary = str(result.get("summary", "")).lower()
    mappings: list[dict[str, str]] = []
    next_pivots: list[str] = []
    progression: list[dict[str, str]] = []
    frame = ""

    def add(
        tactic: str,
        technique: str,
        technique_id: str,
        rationale: str,
        confidence: str = "medium",
        definition: str = "",
    ) -> None:
        entry = {
            "tactic": tactic,
            "technique": technique,
            "technique_id": technique_id,
            "confidence": confidence,
            "rationale": rationale,
            "definition": definition,
        }
        if entry not in mappings:
            mappings.append(entry)
    def add_pivot(text: str) -> None:
        value = str(text or "").strip()
        if value and value not in next_pivots:
            next_pivots.append(value)
    def add_progression(tactic: str, technique: str, technique_id: str, why: str) -> None:
        entry = {"tactic": tactic, "technique": technique, "technique_id": technique_id, "why": why}
        if entry not in progression:
            progression.append(entry)

    if intent in {"failed_login_activity", "linux_auth_failures", "windows_auth_failures"}:
        add(
            "Credential Access",
            "Brute Force",
            "T1110",
            "Failed login investigation paths map to repeated authentication failure and credential guessing activity.",
            "high",
            "Adversaries may use repeated login attempts or password guessing to gain access to accounts.",
        )
        add_pivot("Check for successful logons from the same source IPs after the failures.")
        add_pivot("Pivot by username across Linux and Windows to detect cross-platform credential guessing.")
        add_pivot("Review the same sources for privilege escalation or administrative logon activity after the failures.")
        add_progression("Defense Evasion", "Valid Accounts", "T1078", "Repeated failed logons are often followed by successful account use if credentials are eventually guessed or reused.")
    if intent in {"linux_privilege_escalation", "linux_privilege_escalation_activity", "linux_privilege_escalation_first_seen"}:
        add(
            "Privilege Escalation",
            "Abuse Elevation Control Mechanism",
            "T1548",
            "Linux sudo/su investigation paths align to privilege-escalation control abuse patterns.",
            "medium",
            "Adversaries may abuse elevation controls such as sudo or UAC-style mechanisms to gain higher privileges.",
        )
        add_pivot("Review the parent authentication events and source users immediately before the sudo or su activity.")
        add_pivot("Check whether the same user or host showed failed logins before the elevation attempt.")
        add_progression("Execution", "Command and Scripting Interpreter", "T1059", "Privilege escalation frequently precedes interactive shell or command execution activity.")
    if intent in {"apache_access_top_ips", "apache_404_spike", "apache_suspicious_user_agents"} or "enumeration" in summary or "scanning" in summary:
        add(
            "Reconnaissance",
            "Active Scanning",
            "T1595",
            "Apache anomaly investigation and 404-heavy probing patterns align to active scanning and web reconnaissance.",
            "high",
            "Adversaries may probe public-facing services and applications to identify exposed targets and weaknesses.",
        )
        add_pivot("Pivot into requested URI paths and user-agent strings for the most active source IPs.")
        add_pivot("Check whether the same source IPs touched authentication endpoints, admin panels, or sensitive files.")
        add_progression("Initial Access", "Exploit Public-Facing Application", "T1190", "Web reconnaissance commonly precedes exploitation attempts against exposed applications.")
    if "cloudtrail" in intent or "cloudtrail" in summary:
        add(
            "Discovery",
            "Cloud Service Discovery",
            "T1526",
            "CloudTrail activity reviews often center on cloud service enumeration and event/service usage patterns.",
            "medium",
            "Adversaries may enumerate cloud services, APIs, and service usage to understand the environment.",
        )
        add_pivot("Pivot by userIdentity, sourceIPAddress, and eventName to separate routine management from unusual cloud discovery behavior.")
        add_pivot("Review eventSource and service combinations around the same timeframe for escalation or persistence changes.")
        add_progression("Persistence", "Account Manipulation", "T1098", "Cloud discovery activity can precede IAM policy or account changes.")
    if intent in {"cisco_asa_network_flows", "aws_vpc_flow_activity"}:
        add(
            "Discovery",
            "Network Service Discovery",
            "T1046",
            "Network flow investigations often align to identifying scanning, service probing, and destination-port targeting behavior.",
            "medium",
            "Adversaries may attempt to determine which network services are available by probing ports and destinations.",
        )
        add_pivot("Review the most active source IPs across destination ports and actions to identify scanning or service targeting patterns.")
        add_pivot("Pivot from repeated denied flows to any later accepted connections from the same source.")
        add_progression("Reconnaissance", "Active Scanning", "T1595", "Network flow patterns can reflect broader scanning or external reconnaissance before exploitation.")
    if intent in {"stream_http_activity"}:
        add(
            "Command and Control",
            "Web Protocols",
            "T1071.001",
            "HTTP telemetry investigations often align to suspicious web-based beaconing, outbound activity, or misuse of common web protocols.",
            "medium",
            "Adversaries may communicate over HTTP or HTTPS to blend malicious traffic into normal web activity.",
        )
        add_pivot("Pivot by destination site, user agent, and URI path to separate routine browsing from repeated suspicious HTTP behavior.")
        add_pivot("Check whether the same clients also made DNS queries or network connections that support command-and-control hypotheses.")
        add_progression("Command and Control", "Ingress Tool Transfer", "T1105", "Suspicious web activity can precede or accompany payload download and staging behavior.")
    if intent in {"aad_signin_activity"}:
        add(
            "Defense Evasion",
            "Valid Accounts",
            "T1078",
            "Azure AD sign-in investigations often focus on whether known credentials or identities are being used in suspicious ways across apps and IPs.",
            "medium",
            "Adversaries may use valid accounts to blend into normal identity activity and bypass simple detection rules.",
        )
        add_pivot("Pivot by user, app, IP address, and sign-in status to separate expected identity use from suspicious account activity.")
        add_pivot("Review impossible-travel, unfamiliar app access, and repeated failure-to-success transitions for the same user.")
        add_progression("Persistence", "Account Manipulation", "T1098", "Suspicious identity use can lead into account changes, consent grants, or policy modification.")
    if intent in {"osquery_process_activity"}:
        add(
            "Execution",
            "Command and Scripting Interpreter",
            "T1059",
            "Process monitoring investigations often focus on command-line execution, script launches, and suspicious spawned processes.",
            "medium",
            "Adversaries may abuse command interpreters or scripting engines to execute payloads and drive follow-on actions.",
        )
        add_pivot("Pivot by host, process path, parent process, and command line to identify unusual execution chains.")
        add_pivot("Review whether the same process paths also appear in network, DNS, or privilege-escalation telemetry.")
        add_progression("Defense Evasion", "Masquerading", "T1036", "Unexpected process paths and command lines can indicate disguised or renamed binaries.")
    if "credential" in summary:
        add(
            "Credential Access",
            "Credentials from Password Stores",
            "T1555",
            "Credential-related summaries often indicate authentication or credential access investigation paths.",
            "low",
            "Adversaries may obtain credentials from local or cloud password stores and identity artifacts.",
        )
    if mappings:
        primary = mappings[0]
        frame = (
            f"Observed behavior aligns most strongly to {primary['tactic']} / "
            f"{primary['technique']} ({primary['technique_id']}). "
            "Use the suggested pivots to test whether the activity progressed into adjacent ATT&CK techniques."
        )
    return {
        "techniques": mappings,
        "next_pivots": next_pivots,
        "possible_progression": progression,
        "frame": frame,
    }


def _persist_mitre_bundle_to_artifact(artifact_path: str, mitre_bundle: dict[str, Any]) -> None:
    target = Path(str(artifact_path or "").strip())
    if not target.exists():
        return
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except Exception:
        return
    if not isinstance(payload, dict):
        return
    result = payload.get("result", {})
    if not isinstance(result, dict):
        return
    result["mitre_attack"] = mitre_bundle
    payload["result"] = result
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _persist_result_updates_to_artifact(artifact_path: str, updates: dict[str, Any]) -> None:
    target = Path(str(artifact_path or "").strip())
    if not target.exists() or not updates:
        return
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except Exception:
        return
    if not isinstance(payload, dict):
        return
    result = payload.get("result", {})
    if not isinstance(result, dict):
        return
    result.update(updates)
    payload["result"] = result
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _ordered_unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        value = str(item or "").strip()
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(value)
    return ordered


def _first_present(row: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = row.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text and text.lower() not in {"unknown", "null", "none", "-", "local"}:
            return text
    return ""


def _extract_case_entities(rows: list[dict[str, Any]], result_body: dict[str, Any]) -> dict[str, list[str]]:
    entities: dict[str, list[str]] = {
        "hosts": [],
        "users": [],
        "source_ips": [],
        "client_ips": [],
        "ports": [],
        "event_names": [],
        "services": [],
        "uri_paths": [],
        "user_agents": [],
    }
    for row in rows:
        if not isinstance(row, dict):
            continue
        entities["hosts"].append(_first_present(row, ("host", "Computer")))
        entities["users"].append(_first_present(row, ("user", "user_name", "TargetUserName", "SubjectUserName", "Account_Name", "Caller_User_Name", "actor")))
        entities["source_ips"].append(_first_present(row, ("src_ip", "Source_Network_Address", "IpAddress", "sourceIPAddress", "source_ip")))
        entities["client_ips"].append(_first_present(row, ("clientip", "src", "src_ip")))
        entities["ports"].append(_first_present(row, ("port", "auth_port", "DestinationPort", "dest_port")))
        entities["event_names"].append(_first_present(row, ("eventName", "EventCode", "EventID")))
        entities["services"].append(_first_present(row, ("service", "eventSource")))
        entities["uri_paths"].append(_first_present(row, ("uri_path", "uri", "url", "file")))
        entities["user_agents"].append(_first_present(row, ("useragent", "http_user_agent")))
    return {key: _ordered_unique(values)[:5] for key, values in entities.items()}


def _rank_entity_values(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    field_map: dict[str, tuple[str, ...]] = {
        "hosts": ("host", "Computer"),
        "users": ("user", "user_name", "TargetUserName", "SubjectUserName", "Account_Name", "Caller_User_Name", "actor"),
        "source_ips": ("src_ip", "Source_Network_Address", "IpAddress", "sourceIPAddress", "source_ip"),
        "client_ips": ("clientip", "src", "src_ip"),
        "event_names": ("eventName", "EventCode", "EventID"),
        "services": ("service", "eventSource"),
    }
    ranked: dict[str, list[dict[str, Any]]] = {}
    for bucket, keys in field_map.items():
        counts: dict[str, int] = {}
        first_seen: dict[str, int] = {}
        for idx, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            value = _first_present(row, keys)
            if not value:
                continue
            counts[value] = counts.get(value, 0) + 1
            first_seen.setdefault(value, idx)
        ordered = sorted(counts.items(), key=lambda item: (-item[1], first_seen.get(item[0], 999999), item[0]))
        ranked[bucket] = [{"value": value, "count": count} for value, count in ordered[:8]]
    return ranked


def _classify_pivot_seed(text: str) -> dict[str, str]:
    value = str(text or "").strip()
    lower = value.lower()
    target_type = "derived_field"
    target_label = "Derived field"
    pivot_kind = "generic_followup"
    if "source ip" in lower:
        target_type = "source_ip"
        target_label = "Source IP"
        pivot_kind = "same_source_ip_followup"
    elif "username" in lower or "user " in lower:
        target_type = "username"
        target_label = "Username"
        pivot_kind = "username_followup"
    elif "host" in lower:
        target_type = "host"
        target_label = "Host"
        pivot_kind = "host_followup"
    if "successful logon" in lower or "successful login" in lower:
        pivot_kind = "success_after_failure"
    elif "privilege escalation" in lower or "administrative logon" in lower:
        pivot_kind = "privilege_escalation_check"
    elif "uri" in lower or "user-agent" in lower or "user agent" in lower:
        pivot_kind = "web_client_drilldown"
    elif "useridentity" in lower or "eventname" in lower or "sourceipaddress" in lower:
        pivot_kind = "cloud_identity_drilldown"
    return {
        "title": value,
        "target_type": target_type,
        "target_label": target_label,
        "pivot_kind": pivot_kind,
    }


def _build_stateful_followup_question(seed: str, target_label: str, target_values: list[str], root_question: str) -> str:
    base = str(seed or "").strip().rstrip(".")
    value_text = ", ".join(target_values[:3])
    if value_text:
        base = f"{base} Use {target_label} value(s): {value_text}."
    root = str(root_question or "").strip()
    if root:
        base = f"{base} Continue the prior investigation context from: {root}"
    return base.strip()


def _quote_values(values: list[str]) -> str:
    return " OR ".join(f'"{str(value).replace(chr(34), "\\\"")}"' for value in values if str(value).strip())


def _base_time_range(result_body: dict[str, Any], query_args: dict[str, Any]) -> tuple[str, str]:
    earliest = str(query_args.get("earliest_time", "")).strip() or "-24h"
    latest = str(query_args.get("latest_time", "")).strip() or "now"
    return earliest, latest


def _build_deterministic_pivot_query_args(
    *,
    base_intent: str,
    pivot_kind: str,
    target_type: str,
    target_values: list[str],
    entities: dict[str, list[str]],
    base_query_args: dict[str, Any],
) -> dict[str, Any] | None:
    values = [str(item).strip() for item in target_values if str(item).strip()]
    if not values:
        return None
    earliest, latest = _base_time_range({}, base_query_args)
    host_filters = entities.get("hosts", [])
    host_clause = ""
    if host_filters:
        host_expr = " OR ".join(f'host=\"{str(host).replace(chr(34), "\\\"")}\"' for host in host_filters[:3])
        host_clause = f" ({host_expr}) "
    if base_intent in {"failed_login_activity", "linux_auth_failures", "windows_auth_failures"}:
        if pivot_kind == "success_after_failure" and target_type == "source_ip":
            ip_expr = " OR ".join(f'src_ip=\"{str(value).replace(chr(34), "\\\"")}\"' for value in values[:5])
            query = (
                "search ("
                "(index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
                "(\"Accepted password\" OR \"Accepted publickey\" OR \"session opened for user\" OR \"Accepted keyboard-interactive/pam\")) "
                "OR "
                "((index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog "
                "(EventCode=4624 OR EventID=4624 OR \"An account was successfully logged on\"))"
                ") "
                "| eval platform=case(index=\"linux\",\"linux\", true(), \"windows\") "
                "| rex field=_raw \"(?i)Accepted (?:password|publickey|keyboard-interactive/pam) for (?<success_user>[^ ]+)\" "
                "| rex field=_raw \"(?i)from (?<success_src_ip>\\d{1,3}(?:\\.\\d{1,3}){3}) port (?<success_port>\\d+)\" "
                "| eval src_ip=coalesce(Source_Network_Address,IpAddress,src,src_ip,clientip,success_src_ip,ip) "
                "| eval user_name=coalesce(TargetUserName,SubjectUserName,Account_Name,user,username,success_user) "
                "| eval auth_port=coalesce(DestinationPort,dest_port,port,success_port) "
                f"| search ({ip_expr}) "
                + (f"| search{host_clause}" if host_clause else "")
                + "| stats count by platform index host user_name src_ip auth_port | sort - count"
            )
            return {"query": query, "earliest_time": earliest, "latest_time": latest, "row_limit": 50}
        if pivot_kind == "username_followup" and target_type == "username":
            user_expr = " OR ".join(f'user_name=\"{str(value).replace(chr(34), "\\\"")}\" OR user=\"{str(value).replace(chr(34), "\\\"")}\"' for value in values[:5])
            template = map_question_to_template("Show failed login activity in the last 24 hours")
            query_args = template_to_query_args(template, "")
            query = str(query_args.get("query", "")).strip()
            if "| fillnull" in query:
                query = query.replace("| fillnull", f"| search ({user_expr}) | fillnull", 1)
            else:
                query = f"{query} | search ({user_expr})"
            query += " | sort - count"
            return {"query": query, "earliest_time": earliest, "latest_time": latest, "row_limit": 50}
        if pivot_kind == "privilege_escalation_check":
            actor_expr = " OR ".join(
                [f'actor=\"{str(v).replace(chr(34), "\\\"")}\"' for v in values[:5]]
                + [f'target_user=\"{str(v).replace(chr(34), "\\\"")}\"' for v in values[:5]]
            )
            host_expr = " OR ".join(f'host=\"{str(host).replace(chr(34), "\\\"")}\"' for host in host_filters[:3])
            clauses = [f"({actor_expr})"] if actor_expr else []
            if host_expr:
                clauses.append(f"({host_expr})")
            search_clause = " AND ".join(clauses)
            query = (
                "search index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") "
                "(\"sudo:\" OR \"su:\" OR \"pam_unix(sudo:session)\" OR \"pam_unix(su:session)\" OR \"session opened for user root\") "
                "| rex field=_raw \"(?i)sudo:\\s+(?<sudo_actor>[A-Za-z0-9_.-]+)\\s+:\" "
                "| rex field=_raw \"(?i)\\buser=(?<auth_user>[^\\s;]+)\" "
                "| eval actor=coalesce(sudo_actor,auth_user,user,account,user_name) "
                "| eval target_user=coalesce(target_user,user,account,user_name) "
            )
            if search_clause:
                query += f"| search {search_clause} "
            query += "| table _time host actor target_user sourcetype _raw | head 50"
            return {"query": query, "earliest_time": earliest, "latest_time": latest, "row_limit": 50}
    if base_intent == "apache_access_top_ips" and target_type in {"source_ip", "host", "derived_field"}:
        ip_values = values or entities.get("client_ips", [])
        if ip_values:
            ip_expr = " OR ".join(f'clientip=\"{str(value).replace(chr(34), "\\\"")}\"' for value in ip_values[:5])
            query = (
                "search index=linux sourcetype=access_combined "
                f"| search ({ip_expr}) "
                "| stats count values(status) as statuses values(method) as methods values(useragent) as useragents by clientip uri_path "
                "| sort - count | head 50"
            )
            return {"query": query, "earliest_time": earliest, "latest_time": latest, "row_limit": 50}
    if base_intent == "aws_cloudtrail_activity":
        safe_values = [str(value).replace('"', '\\"') for value in values[:5]]
        values_expr = " OR ".join(f'"{safe_value}"' for safe_value in safe_values)
        query = (
            "search index=main sourcetype=aws:cloudtrail "
            f"| search ({values_expr}) "
            "| stats count values(eventSource) as event_sources values(eventName) as event_names by userIdentity.arn sourceIPAddress "
            "| sort - count | head 50"
        )
        return {"query": query, "earliest_time": earliest, "latest_time": latest, "row_limit": 50}
    return None


def _build_structured_pivot_context(result_body: dict[str, Any], sample_rows: list[dict[str, Any]]) -> dict[str, Any]:
    base_query_args = result_body.get("query_args", {}) if isinstance(result_body.get("query_args"), dict) else {}
    base_query = str(base_query_args.get("query", "")).strip()
    base_intent = str(result_body.get("intent", "")).strip()
    root_question = str(result_body.get("root_question") or result_body.get("question") or "").strip()
    entities = _extract_case_entities(sample_rows, result_body)
    ranked_entities = _rank_entity_values(sample_rows)
    if result_body.get("supported") is False:
        return {
            "root_question": root_question,
            "base_intent": base_intent,
            "base_query_args": base_query_args,
            "base_query": base_query,
            "time_range": {
                "earliest": str(base_query_args.get("earliest_time", "")).strip() or "-24h",
                "latest": str(base_query_args.get("latest_time", "")).strip() or "now",
            },
            "entities": entities,
            "ranked_entities": ranked_entities,
            "pivot_candidates": [],
        }
    raw_pivots = []
    mitre_pivots = result_body.get("mitre_attack", {}).get("next_pivots", []) if isinstance(result_body.get("mitre_attack"), dict) else []
    tdir_pivots = result_body.get("tdir_case", {}).get("recommended_next_pivots", []) if isinstance(result_body.get("tdir_case"), dict) else []
    for item in (mitre_pivots if isinstance(mitre_pivots, list) and mitre_pivots else tdir_pivots if isinstance(tdir_pivots, list) else []):
        text = str(item or "").strip()
        if text:
            raw_pivots.append(text)
    candidates: list[dict[str, Any]] = []
    for index, text in enumerate(_ordered_unique(raw_pivots)[:6]):
        seed = _classify_pivot_seed(text)
        target_values: list[str] = []
        ranked_bucket: list[dict[str, Any]] = []
        if seed["target_type"] == "source_ip":
            ranked_bucket = ranked_entities.get("source_ips") or ranked_entities.get("client_ips") or []
            target_values = [item.get("value", "") for item in ranked_bucket if str(item.get("value", "")).strip()]
            if not target_values:
                target_values = entities.get("source_ips") or entities.get("client_ips") or []
        elif seed["target_type"] == "username":
            ranked_bucket = ranked_entities.get("users") or []
            target_values = [item.get("value", "") for item in ranked_bucket if str(item.get("value", "")).strip()]
            if not target_values:
                target_values = entities.get("users") or []
        elif seed["target_type"] == "host":
            ranked_bucket = ranked_entities.get("hosts") or []
            target_values = [item.get("value", "") for item in ranked_bucket if str(item.get("value", "")).strip()]
            if not target_values:
                target_values = entities.get("hosts") or []
        else:
            ranked_bucket = ranked_entities.get("users") or ranked_entities.get("hosts") or ranked_entities.get("source_ips") or []
            target_values = [item.get("value", "") for item in ranked_bucket if str(item.get("value", "")).strip()]
            if not target_values:
                target_values = entities.get("users") or entities.get("hosts") or entities.get("source_ips") or []
        target_values = [str(item).strip() for item in target_values if str(item).strip()][:3]
        ranked_bucket = [item for item in ranked_bucket if str(item.get("value", "")).strip()][:3]
        direct_query_args = _build_deterministic_pivot_query_args(
            base_intent=base_intent,
            pivot_kind=seed["pivot_kind"],
            target_type=seed["target_type"],
            target_values=target_values,
            entities=entities,
            base_query_args=base_query_args,
        )
        candidates.append(
            {
                "id": f"pivot_{index+1}_{re.sub(r'[^a-z0-9]+', '_', seed['pivot_kind'].lower()).strip('_') or 'followup'}",
                "index": index,
                "title": text,
                "target_type": seed["target_type"],
                "target_label": seed["target_label"],
                "target_values": target_values,
                "target_rankings": ranked_bucket,
                "pivot_kind": seed["pivot_kind"],
                "execution_mode": "deterministic_query" if isinstance(direct_query_args, dict) else "stateful_followup_question",
                "query_args": direct_query_args,
                "next_question": _build_stateful_followup_question(text, seed["target_label"], target_values[:3], root_question),
                "provenance": {
                    "source": "returned_evidence",
                    "selection_rule": "top_ranked_values_by_frequency",
                    "explanation": f"Selected from the highest-frequency {seed['target_label'].lower()} values in the returned evidence rows.",
                },
            }
        )
    return {
        "root_question": root_question,
        "base_intent": base_intent,
        "base_query_args": base_query_args,
        "base_query": base_query,
        "time_range": {
            "earliest": str(base_query_args.get("earliest_time", "")).strip() or "-24h",
            "latest": str(base_query_args.get("latest_time", "")).strip() or "now",
        },
        "entities": entities,
        "ranked_entities": ranked_entities,
        "pivot_candidates": candidates,
    }


def _build_graph_case_state_payload(
    *,
    question: str,
    result_body: dict[str, Any],
    sample_rows: list[dict[str, Any]],
    case_id: str = "",
    current_node_id: str = "",
    parent_node_id: str = "",
    node_type: str = "investigation",
    previous_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entities = _extract_case_entities(sample_rows, result_body)
    ranked_entities = _rank_entity_values(sample_rows)
    pivot_context = result_body.get("pivot_context", {}) if isinstance(result_body.get("pivot_context"), dict) else {}
    pivot_candidates = pivot_context.get("pivot_candidates", []) if isinstance(pivot_context.get("pivot_candidates"), list) else []
    return snapshot_graph_case_state(
        previous=previous_state,
        question=question,
        result_body=result_body,
        case_id=case_id,
        current_node_id=current_node_id,
        parent_node_id=parent_node_id,
        node_type=node_type,
        evidence_entities=entities,
        ranked_entities=ranked_entities,
        pivot_candidates=pivot_candidates,
    )


def _write_pivot_artifact(*, result_body: dict[str, Any], session_id: str, question: str, pivot_candidate: dict[str, Any]) -> str:
    ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    safe_session = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(session_id or "manual").strip() or "manual")
    target_dir = ARTIFACTS_ROOT / "runs" / "pivots" / safe_session
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"pivot_investigation_{ts}.json"
    payload = {
        "meta": {
            "artifact": str(target.relative_to(PROJECT_ROOT)),
            "pipeline": "structured_pivot",
            "session_id": safe_session,
            "question": question,
            "pivot_candidate": pivot_candidate,
            "written_at_epoch": int(time.time()),
        },
        "result": result_body,
    }
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(target.relative_to(PROJECT_ROOT))


def _run_structured_pivot_investigation(
    *,
    question: str,
    pivot_context: dict[str, Any],
    pivot_candidate: dict[str, Any],
    session_id: str,
    write_artifact: bool,
) -> dict[str, Any]:
    query_args = pivot_candidate.get("query_args", {}) if isinstance(pivot_candidate.get("query_args"), dict) else {}
    if not query_args or not str(query_args.get("query", "")).strip():
        raise ValueError("structured pivot candidate is missing deterministic query_args")
    intent = str(pivot_context.get("base_intent", "")).strip() or "agentic_pivot"
    summary_hint = "Summarize the pivot findings, what changed from the prior search scope, and the best next investigative check."
    splunk_data = run_splunk_query_args(query_args, intent=intent, summary_hint=summary_hint)
    structured = splunk_data.get("structured", {}) if isinstance(splunk_data.get("structured"), dict) else {}
    rows = structured.get("results", []) if isinstance(structured.get("results"), list) else []
    total_rows = int(structured.get("total_rows", len(rows) if isinstance(rows, list) else 0) or 0)
    try:
        summary = summarize_with_ollama_model(question, splunk_data, model=DEFAULT_MODEL_FINAL_SUMMARY, think=False)
    except Exception:
        summary = "Structured pivot executed. Review the returned evidence rows and decide whether a narrower follow-up is warranted."
    selected_values = ", ".join(pivot_candidate.get("target_values", [])[:3]) or "derived values"
    if total_rows <= 0:
        summary = (
            f"The pivot executed successfully using preserved case context for {pivot_candidate.get('target_label', 'pivot target')} "
            f"value(s): {selected_values}, but no matching rows were returned. Review the same evidence in Splunk, narrow to a single value, "
            "or choose a different pivot."
        )
    result_body: dict[str, Any] = {
        "question": question,
        "root_question": str(pivot_context.get("root_question", question)).strip() or question,
        "active_question": question,
        "intent": intent,
        "supported": True,
        "selected_tool": "splunk_run_query",
        "query_args": query_args,
        "selected_spl_details": [
            {
                "tool": "splunk_run_query",
                "query": str(query_args.get("query", "")).strip(),
                "rows_returned": len(rows) if isinstance(rows, list) else 0,
                "total_rows": total_rows,
            }
        ],
        "rows_returned": len(rows) if isinstance(rows, list) else 0,
        "total_rows": total_rows,
        "summary": summary,
        "evidence": {
            "query_or_args": query_args,
            "top_entities": rows[:25] if isinstance(rows, list) else [],
        },
        "search_strategy_summary": f"Structured pivot executed from preserved case context using {pivot_candidate.get('target_label', 'pivot target')} value(s): {selected_values}.",
        "pivot_source": {
            "kind": "structured_pivot",
            "candidate": pivot_candidate,
        },
        "tdir_case": {
            "question": question,
            "selected_intent": intent,
            "pipeline": "structured_pivot",
            "rows_returned": len(rows) if isinstance(rows, list) else 0,
            "recommended_next_pivots": [],
        },
        "phase_status": {
            "detect": "complete",
            "triage": "complete",
            "investigate": "complete" if rows else "no_evidence",
        },
    }
    meta: dict[str, Any] = {"pipeline": "structured_pivot"}
    if write_artifact:
        meta["artifact"] = _write_pivot_artifact(
            result_body=result_body,
            session_id=session_id,
            question=question,
            pivot_candidate=pivot_candidate,
        )
    return {"meta": meta, "result": result_body}


def _default_expected_models() -> list[str]:
    ordered: list[str] = []
    for key in EXPECTED_MODEL_KEYS:
        model = str(DEFAULT_MODEL_ASSIGNMENTS.get(key, "")).strip()
        if model and model not in ordered:
            ordered.append(model)
    return ordered


def _autofill_model_assignments(values: dict[str, str], available_models: list[str] | None = None) -> dict[str, str]:
    updated = {str(key): str(value).strip() for key, value in values.items()}
    installed = set(str(model).strip() for model in (available_models or []) if str(model).strip())
    for key in EXPECTED_MODEL_KEYS:
        if updated.get(key, "").strip():
            continue
        default_model = str(DEFAULT_MODEL_ASSIGNMENTS.get(key, "")).strip()
        if default_model and default_model in installed:
            updated[key] = default_model
    return updated


DEPENDENCY_COMMANDS: list[tuple[str, list[str], str]] = [
    ("git", ["git", "--version"], "git --version"),
    ("curl", ["curl", "--version"], "curl --version"),
    ("make", ["make", "--version"], "make --version"),
]


def _collect_dependency_status() -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    all_ok = True
    for key, argv, display in DEPENDENCY_COMMANDS:
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=6, check=False)
            raw_output = (proc.stdout or proc.stderr or "").strip()
            first_line = raw_output.splitlines()[0].strip() if raw_output else ""
            ok = proc.returncode == 0
            all_ok = all_ok and ok
            checks.append(
                {
                    "key": key,
                    "command": display,
                    "state": "ok" if ok else "error",
                    "detail": first_line or (f"{display} returned exit code {proc.returncode}" if not ok else "available"),
                }
            )
        except FileNotFoundError:
            all_ok = False
            checks.append(
                {
                    "key": key,
                    "command": display,
                    "state": "error",
                    "detail": "command not found",
                }
            )
        except Exception as exc:
            all_ok = False
            checks.append(
                {
                    "key": key,
                    "command": display,
                    "state": "error",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            )
    return {
        "scope_note": "This reflects what the current A.G.E.N.T. Smith runtime can directly see and execute.",
        "overall_state": "ok" if all_ok else "error",
        "checks": checks,
    }


def _mcp_probe(values: dict[str, str]) -> dict[str, Any]:
    splunk_mcp = str(values.get("SPLUNK_MCP_URL", "")).strip()
    token = str(values.get("SPLUNK_LAB_BEARER_TOKEN", "")).strip()
    if not splunk_mcp:
        return {
            "status": "error",
            "detail": "SPLUNK_MCP_URL is empty.",
            "tool": "splunk_get_indexes",
            "rows_returned": 0,
        }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "agtsmith-config-probe", "version": "1.0"},
        },
    }
    tool_payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "splunk_get_indexes",
            "arguments": {},
        },
    }
    try:
        with urllib.request.urlopen(
            urllib.request.Request(
                splunk_mcp,
                data=json.dumps(init_payload).encode("utf-8"),
                headers=headers,
                method="POST",
            ),
            timeout=12.0,
            context=ssl._create_unverified_context(),
        ) as init_resp:
            init_status = getattr(init_resp, "status", 200)
            init_body = init_resp.read().decode("utf-8", errors="replace")
        with urllib.request.urlopen(
            urllib.request.Request(
                splunk_mcp,
                data=json.dumps(tool_payload).encode("utf-8"),
                headers=headers,
                method="POST",
            ),
            timeout=20.0,
            context=ssl._create_unverified_context(),
        ) as tool_resp:
            tool_status = getattr(tool_resp, "status", 200)
            tool_body_raw = tool_resp.read().decode("utf-8", errors="replace")
        try:
            tool_body = json.loads(tool_body_raw)
        except Exception:
            return {
                "status": "error",
                "detail": f"MCP probe returned non-JSON response after initialize HTTP {init_status} / tool HTTP {tool_status}.",
                "tool": "splunk_get_indexes",
                "rows_returned": 0,
                "raw_excerpt": tool_body_raw[:300],
            }
        if not isinstance(tool_body, dict):
            return {
                "status": "error",
                "detail": "MCP probe returned an unexpected response shape.",
                "tool": "splunk_get_indexes",
                "rows_returned": 0,
            }
        if "error" in tool_body:
            return {
                "status": "error",
                "detail": f"MCP JSON-RPC error: {tool_body['error']}",
                "tool": "splunk_get_indexes",
                "rows_returned": 0,
            }
        result = tool_body.get("result", {}) if isinstance(tool_body, dict) else {}
        structured = result.get("structuredContent", {}) if isinstance(result, dict) else {}
        rows = structured.get("results", []) if isinstance(structured, dict) else []
        total_rows = int(structured.get("total_rows", len(rows))) if isinstance(structured, dict) else len(rows)
        return {
            "status": "ok",
            "detail": f"MCP tool call succeeded against {splunk_mcp}.",
            "tool": "splunk_get_indexes",
            "rows_returned": total_rows,
            "http_status": tool_status,
        }
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {
            "status": "error",
            "detail": f"MCP probe failed with HTTP {exc.code}.",
            "tool": "splunk_get_indexes",
            "rows_returned": 0,
            "raw_excerpt": body[:300],
        }
    except Exception as exc:
        return {
            "status": "error",
            "detail": f"{type(exc).__name__}: {exc}",
            "tool": "splunk_get_indexes",
            "rows_returned": 0,
        }


def _global_nav(active: str) -> str:
    items = [
        ("/mcp", "Splunk MCP Chat", "MCP", "mcp"),
        ("/investigation", "Investigation UI", "Investigate", "investigation"),
        ("/artifacts", "Artifact Repository", "Artifacts", "artifacts"),
        ("__control__", "Control Center", "Control", "control"),
        ("/logout", "Logout", "Session", "logout"),
    ]
    if _can_show_environment_page():
        items.insert(2, ("/environment", "Data Domains", "Profile", "environment"))
    links: list[str] = []
    for href, label, kicker, key in items:
        if href == "__control__":
            dropdown_items = [
                ("/architecture", "Architecture", "System flow and trust boundaries"),
                ("/langgraph-graph", "LangGraph Graph", "Canonical workflow, active topology, and run path"),
                ("/docs", "Docs", "Whitepapers, guides, and references"),
                ("/configure", "Configuration", "Endpoints, models, validation"),
                ("/cases", "Case Workspace", "Persistent cases, pivots, and branch history"),
                ("/learning", "SPL Optimization", "AI-driven SPL improvement and review"),
                ("/spl-assets", "SPL Asset Repository", "Approved reusable SPL assets"),
                ("/users", "Users", "Local users and audit trail"),
            ]
            item_links = "".join(
                f'<a class="nav-submenu-item" href="{sub_href}">'
                f'<span class="nav-submenu-title">{html.escape(sub_label)}</span>'
                f'<span class="nav-submenu-copy">{html.escape(sub_copy)}</span>'
                "</a>"
                for sub_href, sub_label, sub_copy in dropdown_items
            )
            cls = "nav-item nav-item-dropdown active" if key == active else "nav-item nav-item-dropdown"
            links.append(
                f'<div class="{cls}">'
                f'<a class="nav-trigger" href="/configure">'
                f'<span class="nav-kicker">{html.escape(kicker)}</span>'
                f'<span class="nav-label">{html.escape(label)}</span>'
                "</a>"
                f'<div class="nav-submenu">{item_links}</div>'
                "</div>"
            )
            continue
        cls = "nav-item active" if key == active else "nav-item"
        links.append(
            f'<a class="{cls}" href="{html.escape(href)}">'
            f'<span class="nav-kicker">{html.escape(kicker)}</span>'
            f'<span class="nav-label">{html.escape(label)}</span>'
            "</a>"
        )
    return f'<nav class="topnav">{"".join(links)}</nav>'


def _control_subnav(active: str) -> str:
    items = [
        ("/architecture", "Architecture"),
        ("/langgraph-graph", "LangGraph Graph"),
        ("/docs", "Docs"),
        ("/configure", "Configuration"),
        ("/cases", "Case Workspace"),
        ("/learning", "SPL Optimization"),
        ("/spl-assets", "SPL Asset Repository"),
        ("/users", "Users"),
    ]
    links: list[str] = []
    for href, label in items:
        cls = "control-pane-link active" if href == active else "control-pane-link"
        links.append(
            f'<a class="{cls}" href="{href}">'
            f'<span class="control-pane-link-title">{html.escape(label)}</span>'
            "</a>"
        )
    return (
        '<section class="control-pane">'
        '<div class="control-pane-head">'
        '<div class="control-pane-kicker">Control Center</div>'
        '<h2 class="control-pane-title">Navigation</h2>'
        "</div>"
        f'<div class="control-pane-links">{"".join(links)}</div>'
        "</section>"
    )


def _load_json_if_exists(path: Path) -> dict[str, Any] | list[Any] | None:
    try:
        if path.exists() and path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return None


def _latest_matching_file(root: Path, pattern: str) -> Path | None:
    if not root.exists():
        return None
    matches = [item for item in root.rglob(pattern) if item.is_file()]
    if not matches:
        return None
    return max(matches, key=lambda item: item.stat().st_mtime)


def _latest_multi_model_run_payload() -> dict[str, Any] | None:
    latest = _latest_matching_file(ARTIFACTS_ROOT / "runs" / "multi_model", "multi_model_run_*.json")
    payload = _load_json_if_exists(latest) if latest else None
    if isinstance(payload, dict) and latest is not None:
        payload["_artifact_path"] = str(latest.relative_to(PROJECT_ROOT))
    return payload if isinstance(payload, dict) else None


def _latest_langgraph_topology_eval_payload() -> dict[str, Any] | None:
    latest = _latest_matching_file(ARTIFACTS_ROOT / "evals" / "langgraph", "langgraph_topology_eval_latest.json")
    payload = _load_json_if_exists(latest) if latest else None
    if isinstance(payload, dict) and latest is not None:
        payload["_artifact_path"] = str(latest.relative_to(PROJECT_ROOT))
    return payload if isinstance(payload, dict) else None


def _graph_mermaid(
    diagram: dict[str, Any],
    *,
    title: str,
    executed_nodes: set[str] | None = None,
    direction: str = "LR",
    use_subgraphs: bool = False,
    expanded: bool = False,
    subgraph_direction: str = "LR",
) -> str:
    executed_nodes = executed_nodes or set()
    rank_spacing = 54 if expanded else 45
    node_spacing = 30 if expanded else 24
    curve = "catmullRom" if expanded else "linear"
    lines = [
        "%%{init: {\"flowchart\": {\"curve\": \"" + curve + "\", \"nodeSpacing\": " + str(node_spacing) + ", \"rankSpacing\": " + str(rank_spacing) + "}} }%%",
        f"flowchart {direction}",
    ]
    group_labels = {
        "controller": "Controller",
        "primary_inference": "Primary Inference",
        "data_plane": "Data Plane",
    }
    nodes = diagram.get("nodes", [])
    if use_subgraphs:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for node in nodes:
            grouped[str(node.get("group", ""))].append(node)
        group_order = ["controller", "primary_inference", "data_plane"]
        for group in group_order:
            group_nodes = grouped.get(group, [])
            if not group_nodes:
                continue
            lines.append(f"    subgraph {group}[{group_labels.get(group, group.title())}]")
            lines.append(f"      direction {subgraph_direction}")
            for node in group_nodes:
                node_id = str(node.get("id", "")).strip()
                label = html.escape(str(node.get("label", node_id)))
                lines.append(f'      {node_id}["{label}"]')
            lines.append("    end")
    else:
        for node in nodes:
            node_id = str(node.get("id", "")).strip()
            label = html.escape(str(node.get("label", node_id)))
            lines.append(f'    {node_id}["{label}"]')
    for edge in diagram.get("edges", []):
        src = str(edge.get("from", "")).strip()
        dst = str(edge.get("to", "")).strip()
        label = str(edge.get("label", "")).strip()
        kind = str(edge.get("kind", "direct")).strip()
        connector = "-->" if kind == "direct" else "-.->"
        if label:
            lines.append(f"    {src} {connector}|{html.escape(label)}| {dst}")
        else:
            lines.append(f"    {src} {connector} {dst}")
    lines.append("    classDef controller fill:#0c1f34,stroke:#27506c,color:#f5f9ff;")
    lines.append("    classDef primary_inference fill:#0f2d27,stroke:#2b5a52,color:#f5f9ff;")
    lines.append("    classDef data_plane fill:#0a1525,stroke:#27506c,color:#f5f9ff;")
    lines.append("    classDef executed fill:#3b2506,stroke:#fbbf24,color:#fff7d6,stroke-width:3px;")
    lines.append("    classDef ingestStage fill:#0b1d33,stroke:#67b7ff,color:#eef6ff,stroke-width:2px;")
    lines.append("    classDef plannerStage fill:#122742,stroke:#79c3ff,color:#eef6ff,stroke-width:2px;")
    lines.append("    classDef writerStage fill:#103328,stroke:#39d49d,color:#effff8,stroke-width:2px;")
    lines.append("    classDef reviewStage fill:#33270f,stroke:#ffca62,color:#fff7e6,stroke-width:2px;")
    lines.append("    classDef validationStage fill:#3a2217,stroke:#ff9966,color:#fff4ed,stroke-width:2px;")
    lines.append("    classDef executionStage fill:#12263d,stroke:#63b3ff,color:#eef6ff,stroke-width:2px;")
    lines.append("    classDef summaryStage fill:#1d2a3d,stroke:#93b4d8,color:#eef6ff,stroke-width:2px;")
    lines.append("    classDef controllerGroup fill:#081423,stroke:#315a79,color:#cfe8ff;")
    lines.append("    classDef primaryGroup fill:#0a1d1a,stroke:#2f6c60,color:#d5fff0;")
    lines.append("    classDef dataGroup fill:#09111d,stroke:#315a79,color:#dbeafe;")
    groups: dict[str, list[str]] = defaultdict(list)
    for node in nodes:
        groups[str(node.get("group", ""))].append(str(node.get("id", "")).strip())
    for group, node_ids in groups.items():
        if group and node_ids:
            lines.append(f"    class {','.join(node_ids)} {group};")
    if executed_nodes:
        executed_node_ids = [node_id for node_id in executed_nodes if node_id]
        if executed_node_ids:
            lines.append(f"    class {','.join(executed_node_ids)} executed;")
    stage_classes = {
        "ingestStage": ["ingest_question", "guardrail"],
        "plannerStage": ["planner"],
        "writerStage": ["writer"],
        "reviewStage": ["security_review", "peer_review", "peer_review_2", "evidence_review"],
        "validationStage": ["validate_final_plan"],
        "executionStage": ["run_tool"],
        "summaryStage": ["summarize", "finalize"],
    }
    node_ids_present = {str(node.get("id", "")).strip() for node in nodes}
    for cls, ids in stage_classes.items():
        present = [node_id for node_id in ids if node_id in node_ids_present]
        if present:
            lines.append(f"    class {','.join(present)} {cls};")
    if use_subgraphs:
        if groups.get("controller"):
            lines.append("    class controller controllerGroup;")
        if groups.get("primary_inference"):
            lines.append("    class primary_inference primaryGroup;")
        if groups.get("data_plane"):
            lines.append("    class data_plane dataGroup;")
    return '<div class="mermaid">' + "\n".join(lines) + "</div>"


def _latest_stage_overlay() -> tuple[str, set[str]]:
    payload = _latest_multi_model_run_payload()
    if not payload:
        return (
            '<div class="lg-muted">No multi-model run artifact found yet. Run a live investigation or <code>make multi-model-run</code> first.</div>',
            set(),
        )
    result = payload.get("result", {}) if isinstance(payload.get("result", {}), dict) else {}
    stage_logs = result.get("stage_logs", []) if isinstance(result.get("stage_logs", []), list) else []
    stage_map = {
        "guardrail": "guardrail",
        "planner": "planner",
        "writer": "writer",
        "reviewer": "security_review",
        "peer_review_1": "peer_review",
        "peer_review_2": "peer_review_2",
        "validation": "validate_final_plan",
        "execution": "run_tool",
        "evidence_review": "evidence_review",
        "summary": "summarize",
    }
    executed_nodes: set[str] = set()
    cards: list[str] = []
    for entry in stage_logs:
        if not isinstance(entry, dict):
            continue
        stage = str(entry.get("stage", "")).strip()
        mapped = stage_map.get(stage, "")
        if mapped:
            executed_nodes.add(mapped)
        title = str(entry.get("title", stage)).strip() or stage
        duration = int(entry.get("duration_ms", 0) or 0)
        details = entry.get("details", []) if isinstance(entry.get("details", []), list) else []
        cards.append(
            '<div class="lg-run-card">'
            f'<div class="lg-run-head"><span class="lg-run-stage">{html.escape(stage)}</span><span class="lg-run-ms">{duration} ms</span></div>'
            f'<div class="lg-run-title">{html.escape(title)}</div>'
            + ("".join(f'<div class="lg-run-detail">{html.escape(str(item))}</div>' for item in details[:3]))
            + "</div>"
        )
    meta = (
        f'<div class="lg-meta">Latest artifact: <code>{html.escape(str(payload.get("_artifact_path", "")))}</code></div>'
        f'<div class="lg-meta">Intent: <code>{html.escape(str(result.get("intent", "")))}</code> | '
        f'Tool: <code>{html.escape(str(result.get("selected_tool", "")))}</code> | '
        f'Rows: <code>{html.escape(str(result.get("rows_returned", 0)))}</code> | '
        f'Skip peer review: <code>{html.escape(str(result.get("skip_peer_review", False)).lower())}</code></div>'
    )
    body = meta + '<div class="lg-run-grid">' + "".join(cards) + "</div>"
    return body, executed_nodes


def _experiment_summary_block() -> str:
    payload = _latest_langgraph_topology_eval_payload()
    if not payload:
        return '<div class="lg-muted">No topology eval artifact found yet. Run <code>make langgraph-topology-eval</code> to populate experiment rankings.</div>'
    experiments = payload.get("experiments", []) if isinstance(payload.get("experiments", []), list) else []
    rows: list[str] = []
    for item in experiments[:6]:
        if not isinstance(item, dict):
            continue
        rows.append(
            "<tr>"
            f"<td><code>{html.escape(str(item.get('id', '')))}</code></td>"
            f"<td>{float(item.get('avg_score', 0)):.2f}</td>"
            f"<td>{float(item.get('support_rate_pct', 0)):.1f}%</td>"
            f"<td>{float(item.get('intent_match_rate_pct', 0)):.1f}%</td>"
            f"<td>{float(item.get('avg_latency_ms', 0)):.0f}</td>"
            f"<td>{float(item.get('skip_peer_rate_pct', 0)):.1f}%</td>"
            "</tr>"
        )
    return (
        f'<div class="lg-meta">Latest eval artifact: <code>{html.escape(str(payload.get("_artifact_path", "")))}</code></div>'
        '<div class="lg-table-wrap"><table class="lg-table"><thead><tr>'
        '<th>Experiment</th><th>Avg Score</th><th>Support</th><th>Intent Match</th><th>Avg Latency ms</th><th>Skip Peer</th>'
        '</tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _admin_onboarding_modal(user: dict[str, Any] | None) -> str:
    if not isinstance(user, dict):
        return ""
    role = str(user.get("role", "")).strip().lower()
    if role != "admin":
        return ""
    if bool(user.get("admin_onboarding_skip", False)):
        return ""
    return (
        '<div id="smith-welcome-modal" class="welcome-modal-backdrop" aria-hidden="true">'
        '<div class="welcome-modal" role="dialog" aria-modal="true" aria-labelledby="smith-welcome-title">'
        '<div class="welcome-kicker">First Time?</div>'
        '<h2 id="smith-welcome-title" class="welcome-title">Open Configuration now?</h2>'
        '<p class="welcome-copy">If this is your first admin sign-in, head to Configuration to validate endpoints, assign models, and complete the setup flow.</p>'
        '<div class="welcome-actions">'
        '<button id="smith-welcome-go" class="welcome-btn primary" type="button">Yes</button>'
        '<button id="smith-welcome-skip" class="welcome-btn" type="button">Skip</button>'
        '<button id="smith-welcome-snooze" class="welcome-btn" type="button">Snooze Indefinitely</button>'
        "</div>"
        "</div>"
        "</div>"
    )


def _running_in_container() -> bool:
    return Path("/.dockerenv").exists()


def _environment_profile_exists() -> bool:
    return ENV_PROFILE_PATH.exists() and ENV_PROFILE_PATH.is_file()


def _environment_profile_bootstrap_in_progress() -> bool:
    if not ENV_PROFILE_BOOTSTRAP_LOCK.exists():
        return False
    try:
        age = time.time() - ENV_PROFILE_BOOTSTRAP_LOCK.stat().st_mtime
    except Exception:
        return False
    if age > 30 * 60:
        try:
            ENV_PROFILE_BOOTSTRAP_LOCK.unlink()
        except Exception:
            pass
        return False
    return True


def _can_show_environment_page() -> bool:
    if not _running_in_container():
        return True
    return _environment_profile_exists()


def _personalization_in_progress() -> bool:
    if not PERSONALIZATION_LOCK.exists():
        return False
    try:
        age = time.time() - PERSONALIZATION_LOCK.stat().st_mtime
    except Exception:
        return False
    if age > 60 * 60:
        try:
            PERSONALIZATION_LOCK.unlink()
        except Exception:
            pass
        return False
    return True


def _environment_profile_refresh_in_progress() -> bool:
    if not ENV_PROFILE_REFRESH_LOCK.exists():
        return False
    try:
        age = time.time() - ENV_PROFILE_REFRESH_LOCK.stat().st_mtime
    except Exception:
        return False
    if age > 2 * 60 * 60:
        try:
            ENV_PROFILE_REFRESH_LOCK.unlink()
        except Exception:
            pass
        return False
    return True


def _local_learning_in_progress() -> bool:
    if not LOCAL_LEARNING_LOCK.exists():
        return False
    try:
        age = time.time() - LOCAL_LEARNING_LOCK.stat().st_mtime
    except Exception:
        return False
    if age > LOCAL_LEARNING_STALE_SECONDS:
        try:
            LOCAL_LEARNING_LOCK.unlink()
        except Exception:
            pass
        return False
    return True


def _runtime_mode_label() -> str:
    if not _running_in_container():
        return "host_runtime"
    mounts_path = Path("/app/config")
    return "docker_container" if mounts_path.exists() else "container_runtime"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _environment_profile_bootstrap_state() -> str:
    if _environment_profile_exists():
        return "ready"
    if _environment_profile_bootstrap_in_progress():
        return "in_progress"
    return "pending"


def _personalization_status() -> dict[str, Any]:
    state = _read_json(PERSONALIZATION_STATE)
    if state:
        if PERSONALIZATION_LOG.exists():
            try:
                state["log_path"] = display_path(PERSONALIZATION_LOG)
                state["output"] = PERSONALIZATION_LOG.read_text(encoding="utf-8")[-12000:]
            except Exception:
                pass
        if SPL_SKILLPACK_PATH.exists() and "path" not in state:
            state["path"] = display_path(SPL_SKILLPACK_PATH)
        return state
    if _personalization_in_progress():
        return {
            "state": "in_progress",
            "detail": "Personalization build is running.",
            "progress_pct": 5,
            "phase": "starting",
            "output": "",
            "log_path": display_path(PERSONALIZATION_LOG),
        }
    if not _environment_profile_exists():
        return {
            "state": "blocked",
            "detail": "Data Domains must exist before personalization can build environment-aware SPL guidance.",
        }
    if SPL_SKILLPACK_PATH.exists():
        try:
            stat = SPL_SKILLPACK_PATH.stat()
            return {
                "state": "ready",
                "detail": "Environment-aware SPL personalization is available.",
                "path": display_path(SPL_SKILLPACK_PATH),
                "updated_epoch": int(stat.st_mtime),
                "progress_pct": 100,
                "phase": "complete",
            }
        except Exception:
            return {
                "state": "ready",
                "detail": "Environment-aware SPL personalization is available.",
                "path": display_path(SPL_SKILLPACK_PATH),
                "progress_pct": 100,
                "phase": "complete",
            }
    return {
        "state": "pending",
        "detail": "Ready to build environment-aware SPL personalization from the current Data Domains profile.",
        "progress_pct": 0,
        "phase": "idle",
        "output": "",
        "log_path": display_path(PERSONALIZATION_LOG),
    }


def _local_learning_status() -> dict[str, Any]:
    path = ensure_learning_registry()
    summary = learning_registry_summary()
    progress = load_learning_progress()
    state = _read_json(LOCAL_LEARNING_STATE)
    if state:
        stale_progress = False
        if str(state.get("state", "")).strip() == "in_progress":
            try:
                updated_epoch = int(state.get("updated_epoch", 0) or 0)
            except Exception:
                updated_epoch = 0
            stale_progress = bool(updated_epoch) and (time.time() - updated_epoch > LOCAL_LEARNING_STALE_SECONDS)
        if str(state.get("state", "")).strip() == "in_progress" and (not _local_learning_in_progress() or stale_progress):
            state = {
                "state": "error",
                "detail": "The previous SPL Optimization AI Engine run did not finish cleanly. Start a new optimization cycle to continue.",
                "progress_pct": 100,
                "phase": "interrupted",
                "updated_epoch": int(time.time()),
            }
            _write_json(LOCAL_LEARNING_STATE, state)
        if LOCAL_LEARNING_LOG.exists():
            try:
                state["log_path"] = display_path(LOCAL_LEARNING_LOG)
                state["output"] = LOCAL_LEARNING_LOG.read_text(encoding="utf-8")[-12000:]
            except Exception:
                pass
        if isinstance(progress, dict) and progress:
            state["improvement"] = progress
        state.setdefault("path", display_path(path))
        state.update(summary)
        return state
    if _local_learning_in_progress():
        payload = {
            "state": "in_progress",
            "detail": "Starting SPL Optimization AI Engine run...",
            "path": display_path(path),
            "progress_pct": 5,
            "phase": "starting",
            "log_path": display_path(LOCAL_LEARNING_LOG),
            "output": "",
            **summary,
        }
        if isinstance(progress, dict) and progress:
            payload["improvement"] = progress
        return payload
    counts = summary.get("counts", {}) if isinstance(summary, dict) else {}
    approved = int(counts.get("approved", 0) or 0)
    if approved > 0:
        detail = (
            "The SPL Optimization AI Engine is active for this install. "
            "Approved SPL assets and local hints can influence SPL planning and review through the optimization context; "
            "pending, rejected, and not applied records do not affect runtime behavior."
        )
    else:
        detail = (
            "The SPL Optimization AI Engine is initialized for this install. "
            "Approved SPL assets and local hints can influence SPL planning and review through the optimization context; "
            "pending, rejected, and not applied records do not affect runtime behavior."
        )
    payload = {
        "state": "ready",
        "detail": detail,
        "path": display_path(path),
        "progress_pct": 0,
        "phase": "idle",
        "log_path": display_path(LOCAL_LEARNING_LOG),
        "output": "",
        **summary,
    }
    if isinstance(progress, dict) and progress:
        payload["improvement"] = progress
    return payload


def _environment_profile_refresh_status() -> dict[str, Any]:
    state = _read_json(ENV_PROFILE_REFRESH_STATE)
    if state:
        if ENV_PROFILE_REFRESH_LOG.exists():
            try:
                state["log_path"] = display_path(ENV_PROFILE_REFRESH_LOG)
                state["output"] = ENV_PROFILE_REFRESH_LOG.read_text(encoding="utf-8")[-12000:]
            except Exception:
                pass
        return state
    if _environment_profile_refresh_in_progress():
        return {
            "state": "in_progress",
            "progress_pct": 5,
            "detail": "Environment profile refresh is running.",
            "output": "",
            "log_path": display_path(ENV_PROFILE_REFRESH_LOG),
        }
    detail = "Ready to refresh Data Domains and rebuild environment-aware SPL artifacts."
    if not _environment_profile_exists():
        detail = "No Data Domains profile exists yet. Run a refresh after Splunk MCP validates."
    return {
        "state": "pending",
        "progress_pct": 0,
        "detail": detail,
        "output": "",
        "log_path": display_path(ENV_PROFILE_REFRESH_LOG),
    }


def _run_environment_profile_bootstrap() -> None:
    ENV_PROFILE_BOOTSTRAP_LOCK.parent.mkdir(parents=True, exist_ok=True)
    try:
        ENV_PROFILE_BOOTSTRAP_LOCK.write_text(str(int(time.time())), encoding="utf-8")
    except Exception:
        return
    try:
        subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "scripts" / "build_environment_profile.py"), "--snapshot"],
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    finally:
        try:
            ENV_PROFILE_BOOTSTRAP_LOCK.unlink()
        except Exception:
            pass


def _run_personalization_refresh() -> None:
    PERSONALIZATION_LOCK.parent.mkdir(parents=True, exist_ok=True)
    try:
        PERSONALIZATION_LOCK.write_text(str(int(time.time())), encoding="utf-8")
    except Exception:
        return
    try:
        PERSONALIZATION_LOG.write_text("", encoding="utf-8")
    except Exception:
        pass
    _set_personalization_state("in_progress", "Starting environment-aware SPL personalization...", 8, "starting")
    try:
        commands = [
            (
                "[personalization] refresh environment profile\n",
                [sys.executable, str(PROJECT_ROOT / "scripts" / "build_environment_profile.py"), "--snapshot"],
            ),
            (
                "[personalization] build skillpack\n",
                [sys.executable, str(PROJECT_ROOT / "scripts" / "build_spl_skillpack.py")],
            ),
        ]
        for banner, command in commands:
            try:
                with PERSONALIZATION_LOG.open("a", encoding="utf-8") as handle:
                    handle.write(banner)
            except Exception:
                pass
            phase_update = _personalization_progress_for_line(banner)
            if phase_update:
                pct, phase, detail = phase_update
                _set_personalization_state("in_progress", detail, pct, phase)
            proc = subprocess.Popen(
                command,
                cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            if proc.stdout is not None:
                for raw_line in proc.stdout:
                    try:
                        with PERSONALIZATION_LOG.open("a", encoding="utf-8") as handle:
                            handle.write(raw_line)
                    except Exception:
                        pass
                    phase_update = _personalization_progress_for_line(raw_line)
                    if phase_update:
                        pct, phase, detail = phase_update
                        _set_personalization_state("in_progress", detail, pct, phase)
                proc.stdout.close()
            code = proc.wait()
            if code != 0:
                _set_personalization_state("error", f"Environment-aware SPL personalization failed with exit code {code}.", 100, "failed", returncode=code)
                return
        try:
            with PERSONALIZATION_LOG.open("a", encoding="utf-8") as handle:
                handle.write("[personalization] complete\n")
        except Exception:
            pass
        _set_personalization_state("ready", "Environment-aware SPL personalization completed successfully.", 100, "complete", returncode=0)
    except Exception as exc:
        try:
            with PERSONALIZATION_LOG.open("a", encoding="utf-8") as handle:
                handle.write(f"\n[personalization] exception: {exc}\n")
        except Exception:
            pass
        _set_personalization_state("error", f"Environment-aware SPL personalization failed: {exc}", 100, "failed")
    finally:
        try:
            PERSONALIZATION_LOCK.unlink()
        except Exception:
            pass


def _set_env_refresh_state(state: str, detail: str, progress_pct: int, phase: str, returncode: int | None = None) -> None:
    payload: dict[str, Any] = {
        "state": state,
        "detail": detail,
        "progress_pct": max(0, min(100, int(progress_pct))),
        "phase": phase,
        "updated_epoch": int(time.time()),
    }
    if returncode is not None:
        payload["returncode"] = int(returncode)
    _write_json(ENV_PROFILE_REFRESH_STATE, payload)


def _set_personalization_state(state: str, detail: str, progress_pct: int, phase: str, returncode: int | None = None) -> None:
    payload: dict[str, Any] = {
        "state": state,
        "detail": detail,
        "progress_pct": max(0, min(100, int(progress_pct))),
        "phase": phase,
        "updated_epoch": int(time.time()),
    }
    if SPL_SKILLPACK_PATH.exists():
        payload["path"] = display_path(SPL_SKILLPACK_PATH)
    if returncode is not None:
        payload["returncode"] = int(returncode)
    _write_json(PERSONALIZATION_STATE, payload)


def _set_local_learning_state(state: str, detail: str, progress_pct: int, phase: str, returncode: int | None = None, **extra: Any) -> None:
    payload: dict[str, Any] = {
        "state": state,
        "detail": detail,
        "progress_pct": max(0, min(100, int(progress_pct))),
        "phase": phase,
        "updated_epoch": int(time.time()),
    }
    if returncode is not None:
        payload["returncode"] = int(returncode)
    payload.update(extra)
    _write_json(LOCAL_LEARNING_STATE, payload)


def _run_local_learning_refresh() -> None:
    LOCAL_LEARNING_LOCK.parent.mkdir(parents=True, exist_ok=True)
    try:
        LOCAL_LEARNING_LOCK.write_text(str(int(time.time())), encoding="utf-8")
    except Exception:
        return
    try:
        LOCAL_LEARNING_LOG.write_text("", encoding="utf-8")
    except Exception:
        pass
    _set_local_learning_state("in_progress", "Starting SPL Optimization AI Engine run...", 5, "starting")

    def _progress(detail: str, pct: int, phase: str) -> None:
        _set_local_learning_state("in_progress", detail, pct, phase)

    def _log(line: str) -> None:
        try:
            with LOCAL_LEARNING_LOG.open("a", encoding="utf-8") as handle:
                handle.write(f"{line.rstrip()}\n")
        except Exception:
            pass

    try:
        result = generate_self_learn_candidates(progress_cb=_progress, log_cb=_log)
        avg_delta = float(((result.get("improvement", {}) or {}).get("comparison", {}) or {}).get("avg_score_delta", 0.0) or 0.0)
        detail = (
            f"SPL Optimization AI Engine complete. "
            f"generated={int(result.get('generated', 0))} "
            f"kept={int(result.get('selected', 0))} "
            f"considered={int(result.get('considered', 0))} "
            f"avg_score_delta={avg_delta:+.2f} "
            f"active_assets={int(((result.get('repository', {}) or {}).get('active_assets', 0)) or 0)}"
        )
        _set_local_learning_state(
            "ready",
            detail,
            100,
            "complete",
            returncode=0,
            created=int(result.get("created", 0)),
            stale_marked=int(result.get("stale_marked", 0)),
            considered=int(result.get("considered", 0)),
            generated=int(result.get("generated", 0)),
            selected=int(result.get("selected", 0)),
            timeout_warnings=int(result.get("timeout_warnings", 0)),
            improvement=result.get("improvement", {}),
        )
    except Exception as exc:
        _log(f"[learning] exception: {exc}")
        _set_local_learning_state("error", f"SPL Optimization AI Engine failed: {exc}", 100, "failed")
    finally:
        try:
            LOCAL_LEARNING_LOCK.unlink()
        except Exception:
            pass


def _phase_progress_for_line(line: str) -> tuple[int, str, str] | None:
    text = line.strip()
    if not text:
        return None
    if "[env-profile-build]" in text:
        return (24, "env_profile_build", text)
    if "build_environment_profile.py" in text:
        return (34, "env_profile_build", text)
    if "[env-profile-check]" in text:
        return (60, "env_profile_check", text)
    if "check_environment_profile_freshness.py" in text:
        return (70, "env_profile_check", text)
    if "[spl-skillpack-refresh]" in text:
        return (82, "spl_skillpack_refresh", text)
    if "build_spl_skillpack.py" in text:
        return (90, "spl_skillpack_refresh", text)
    if "[env-profile-refresh] complete" in text:
        return (100, "complete", "Environment profile refresh completed.")
    return None


def _personalization_progress_for_line(line: str) -> tuple[int, str, str] | None:
    text = line.strip()
    if not text:
        return None
    if "build_environment_profile.py" in text or "[personalization] refresh environment profile" in text:
        return (28, "env_profile_build", "Refreshing environment profile for personalization.")
    if "build_spl_skillpack.py" in text or "[personalization] build skillpack" in text:
        return (76, "spl_skillpack_refresh", "Rebuilding environment-aware SPL skillpack.")
    if "[personalization] complete" in text:
        return (100, "complete", "Environment-aware SPL personalization completed.")
    return None


def _run_environment_profile_refresh() -> None:
    ENV_PROFILE_REFRESH_LOCK.parent.mkdir(parents=True, exist_ok=True)
    try:
        ENV_PROFILE_REFRESH_LOCK.write_text(str(int(time.time())), encoding="utf-8")
    except Exception:
        return
    try:
        ENV_PROFILE_REFRESH_LOG.write_text("", encoding="utf-8")
    except Exception:
        pass
    _set_env_refresh_state("in_progress", "Starting Data Domains refresh...", 6, "starting")
    try:
        proc = subprocess.Popen(
            ["make", "env-profile-refresh"],
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        if proc.stdout is not None:
            for raw_line in proc.stdout:
                try:
                    with ENV_PROFILE_REFRESH_LOG.open("a", encoding="utf-8") as handle:
                        handle.write(raw_line)
                except Exception:
                    pass
                phase_update = _phase_progress_for_line(raw_line)
                if phase_update:
                    pct, phase, detail = phase_update
                    _set_env_refresh_state("in_progress", detail, pct, phase)
            proc.stdout.close()
        code = proc.wait()
        if code == 0:
            _set_env_refresh_state("ready", "Environment profile refresh completed successfully.", 100, "complete", returncode=0)
            if SPL_SKILLPACK_PATH.exists():
                _set_personalization_state(
                    "ready",
                    "Environment-aware SPL personalization is current from the latest Data Domains refresh.",
                    100,
                    "complete",
                    returncode=0,
                )
        else:
            _set_env_refresh_state("error", f"Environment profile refresh failed with exit code {code}.", 100, "failed", returncode=code)
    except Exception as exc:
        try:
            with ENV_PROFILE_REFRESH_LOG.open("a", encoding="utf-8") as handle:
                handle.write(f"\n[web-ui-refresh] exception: {exc}\n")
        except Exception:
            pass
        _set_env_refresh_state("error", f"Environment profile refresh failed: {exc}", 100, "failed")
    finally:
        try:
            ENV_PROFILE_REFRESH_LOCK.unlink()
        except Exception:
            pass


def _wipe_environment_profile_artifacts() -> list[str]:
    removed: list[str] = []
    targets = [
        ENV_PROFILE_PATH,
        ENV_PROFILE_BOOTSTRAP_LOCK,
        ENV_PROFILE_REFRESH_LOCK,
        ENV_PROFILE_REFRESH_LOG,
        ENV_PROFILE_REFRESH_STATE,
        PERSONALIZATION_LOCK,
        PERSONALIZATION_LOG,
        PERSONALIZATION_STATE,
        SPL_SKILLPACK_PATH,
    ]
    environment_dir = ENV_PROFILE_PATH.parent
    if environment_dir.exists():
        for candidate in sorted(environment_dir.glob("environment_profile_*.json")):
            if candidate not in targets:
                targets.append(candidate)
    for target in targets:
        try:
            if target.exists():
                target.unlink()
                removed.append(display_path(target))
        except Exception:
            continue
    return removed


def _run_environment_profile_wipe_refresh() -> None:
    removed = _wipe_environment_profile_artifacts()
    detail = "Starting fresh Data Domains rebuild..."
    if removed:
        detail = f"Cleared {len(removed)} existing Data Domains artifact(s). Starting fresh rebuild..."
    _set_env_refresh_state("in_progress", detail, 4, "wipe")
    _run_environment_profile_refresh()


def _maybe_trigger_environment_profile_bootstrap(validation: dict[str, Any]) -> str:
    if _environment_profile_exists():
        return "ready"
    checks = validation.get("checks", []) if isinstance(validation, dict) else []
    mcp_ok = any(
        isinstance(check, dict)
        and str(check.get("name", "")).strip() == "splunk_mcp"
        and str(check.get("status", "")).strip() == "ok"
        for check in checks
    )
    if not mcp_ok:
        return "pending"
    if _environment_profile_bootstrap_in_progress():
        return "in_progress"
    threading.Thread(target=_run_environment_profile_bootstrap, daemon=True).start()
    return "in_progress"


def _config_snapshot() -> dict[str, Any]:
    _lines, file_values = parse_env_file(UI_ENV_PATH)
    values = {key: file_values.get(key, os.getenv(key, "")).strip() for key in CONFIG_EDITABLE_KEYS}
    if not values.get("OLLAMA_HOST"):
        values["OLLAMA_HOST"] = get_ollama_host()
    if not values.get("SPLUNK_BASE_URL"):
        values["SPLUNK_BASE_URL"] = get_splunk_base_url()
    if not values.get("SPLUNK_MCP_URL"):
        values["SPLUNK_MCP_URL"] = get_splunk_mcp_url()
    if not values.get("EDGE_LLM_ENABLED"):
        values["EDGE_LLM_ENABLED"] = "1" if get_edge_llm_enabled() else "0"
    if not values.get("EDGE_LLM_HOST"):
        values["EDGE_LLM_HOST"] = get_edge_llm_host()
    if not values.get("EDGE_LLM_MODEL"):
        values["EDGE_LLM_MODEL"] = get_edge_llm_model()
    if not values.get("EDGE_LLM_ROLE"):
        values["EDGE_LLM_ROLE"] = get_edge_llm_role()
    if not values.get("EDGE_LLM_TIMEOUT_SEC"):
        values["EDGE_LLM_TIMEOUT_SEC"] = get_edge_llm_timeout_sec()
    expected_models = _default_expected_models()
    models = [values.get(key, "") for key in EXPECTED_MODEL_KEYS if values.get(key, "").strip()]
    unique_models: list[str] = []
    for model in models:
        if model not in unique_models:
            unique_models.append(model)
    token = values.get("SPLUNK_LAB_BEARER_TOKEN", "")
    token_display = TOKEN_MASK_SENTINEL if token else ""
    token_masked = _mask_secret_display(token)
    edge_enabled = values.get("EDGE_LLM_ENABLED", "0") == "1"
    edge_host = values.get("EDGE_LLM_HOST", "").strip().rstrip("/")
    edge_model = values.get("EDGE_LLM_MODEL", "").strip()
    splunk_mcp_config = {
        "mcpServers": {
            "splunk-mcp-server": {
                "command": "npx",
                "args": [
                    "-y",
                    "mcp-remote",
                    values.get("SPLUNK_MCP_URL", ""),
                    "--header",
                    f"Authorization: Bearer {token_masked or '<masked>'}",
                ],
            }
        }
    }
    config_display = display_path(UI_ENV_PATH)
    return {
        "runtime_mode": _runtime_mode_label(),
        "config_path": config_display,
        "environment_profile_status": _environment_profile_bootstrap_state(),
        "environment_profile_refresh": _environment_profile_refresh_status(),
        "personalization": _personalization_status(),
        "local_learning": _local_learning_status(),
        "values": {**values, "SPLUNK_LAB_BEARER_TOKEN": token_display},
        "secret_state": {
            "splunk_token_present": bool(token),
            "splunk_token_masked": token_masked,
        },
        "expected_models": expected_models,
        "ollama_pull_commands": [f"ollama pull {model}" for model in expected_models],
        "assigned_model_pull_commands": [f"ollama pull {model}" for model in unique_models],
        "ollama_available_models": _discover_ollama_models(values.get("OLLAMA_HOST", get_ollama_host())),
        "edge_ollama_available_models": _discover_ollama_models(edge_host) if edge_enabled and edge_host else [],
        "splunk_mcp_config_json": json.dumps(splunk_mcp_config, indent=2),
        "host_restart_command": "make dev",
        "docker_wrapper_restart_command": "make docker-down && AGTSMITH_UI_PORT=8788 make docker-up",
        "docker_deploy_restart_command": "make docker-deploy-down && AGTSMITH_DEPLOY_PORT=8789 make docker-deploy-up",
        "setup_guide_path": "runbooks/initial_setup.md",
        "connectivity_checks": {
            "ollama_tags": f"curl {values.get('OLLAMA_HOST', get_ollama_host())}/api/tags",
            "edge_ollama_tags": f"curl {edge_host}/api/tags" if edge_enabled and edge_host else "",
            "splunk_mcp": (
                "curl -k -i -H "
                f"\"Authorization: Bearer {token_masked or '<masked>'}\" "
                f"{values.get('SPLUNK_MCP_URL', get_splunk_mcp_url())}"
            ),
        },
        "edge_helper": {
            "enabled": edge_enabled,
            "host": edge_host,
            "model": edge_model,
            "role": values.get("EDGE_LLM_ROLE", "").strip(),
            "timeout_sec": values.get("EDGE_LLM_TIMEOUT_SEC", "").strip(),
            "pull_command": f"ollama pull {edge_model}" if edge_enabled and edge_model else "",
        },
    }


def _http_json(url: str, headers: dict[str, str] | None = None, timeout: float = 8.0) -> tuple[int, Any]:
    req = urllib.request.Request(url, headers=headers or {})
    context = ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        return int(getattr(resp, "status", 200)), json.loads(raw) if raw.strip() else {}


def _discover_ollama_models(ollama_host: str) -> list[str]:
    host = str(ollama_host or "").strip().rstrip("/")
    if not host:
        return []
    try:
        _status, payload = _http_json(f"{host}/api/tags")
    except Exception:
        return []
    models = payload.get("models", []) if isinstance(payload, dict) else []
    names: list[str] = []
    for item in models:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if name:
            names.append(name)
    return names


def _validation_connectivity_checks(values: dict[str, str]) -> dict[str, str]:
    ollama_host = str(values.get("OLLAMA_HOST", "")).strip().rstrip("/") or get_ollama_host()
    edge_enabled = str(values.get("EDGE_LLM_ENABLED", "0")).strip() == "1"
    edge_host = str(values.get("EDGE_LLM_HOST", "")).strip().rstrip("/")
    splunk_mcp = str(values.get("SPLUNK_MCP_URL", "")).strip() or get_splunk_mcp_url()
    token = str(values.get("SPLUNK_LAB_BEARER_TOKEN", "")).strip()
    return {
        "ollama_tags": f"curl {ollama_host}/api/tags",
        "edge_ollama_tags": f"curl {edge_host}/api/tags" if edge_enabled and edge_host else "",
        "splunk_mcp": f'curl -k -i -H "Authorization: Bearer {token}" {splunk_mcp}',
    }


def _validate_runtime_config(values: dict[str, str], scope: str = "full") -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    summary = {"ok": 0, "warn": 0, "error": 0}
    available_models: list[str] = []
    edge_available_models: list[str] = []
    expected_models = _default_expected_models()

    def add_result(name: str, status: str, detail: str, extra: dict[str, Any] | None = None) -> None:
        summary[status] += 1
        entry = {"name": name, "status": status, "detail": detail}
        if extra:
            entry.update(extra)
        results.append(entry)

    if scope != "edge":
        ollama_host = str(values.get("OLLAMA_HOST", "")).strip().rstrip("/")
        try:
            code, payload = _http_json(f"{ollama_host}/api/tags")
            models = payload.get("models", []) if isinstance(payload, dict) else []
            installed = sorted(
                str(item.get("name", "")).strip() for item in models if isinstance(item, dict) and str(item.get("name", "")).strip()
            )
            available_models = installed
            add_result("ollama_api", "ok", f"Ollama reachable ({code}); discovered {len(installed)} model(s).", {"models": installed})
            expected = list(expected_models)
            missing = [model for model in expected if model not in installed]
            if missing:
                add_result("ollama_expected_models", "warn", "Some expected models are not installed on the Ollama host.", {"missing_models": missing})
            else:
                add_result("ollama_expected_models", "ok", "All expected models are installed on the Ollama host.")
        except Exception as exc:
            add_result("ollama_api", "error", f"Could not reach Ollama API: {type(exc).__name__}: {exc}")

        missing_assignments = [key for key in EXPECTED_MODEL_KEYS if not str(values.get(key, "")).strip()]
        if missing_assignments:
            add_result(
                "model_assignments",
                "error",
                "One or more runtime roles do not have an assigned model. Save Configuration after validation to auto-fill supported defaults, or assign models manually.",
                {"missing_assignments": missing_assignments},
            )
        else:
            add_result("model_assignments", "ok", "All runtime roles currently have assigned models.")

    edge_enabled = str(values.get("EDGE_LLM_ENABLED", "0")).strip() == "1"
    edge_host = str(values.get("EDGE_LLM_HOST", "")).strip().rstrip("/")
    edge_model = str(values.get("EDGE_LLM_MODEL", "")).strip()
    if edge_enabled:
        if not edge_host:
            add_result("edge_helper", "error", "Edge helper is enabled but EDGE_LLM_HOST is empty.")
        else:
            try:
                code, payload = _http_json(f"{edge_host}/api/tags")
                models = payload.get("models", []) if isinstance(payload, dict) else []
                installed = sorted(
                    str(item.get("name", "")).strip()
                    for item in models
                    if isinstance(item, dict) and str(item.get("name", "")).strip()
                )
                edge_available_models = installed
                if not edge_model:
                    add_result(
                        "edge_helper",
                        "warn",
                        f"Edge helper reachable ({code}); assign one of the discovered models before saving the helper as enabled.",
                        {"models": installed},
                    )
                elif edge_model in installed:
                    add_result(
                        "edge_helper",
                        "ok",
                        f"Edge helper reachable ({code}); model '{edge_model}' is installed.",
                        {"models": installed},
                    )
                else:
                    add_result(
                        "edge_helper",
                        "warn",
                        f"Edge helper reachable ({code}) but the assigned model '{edge_model}' is not installed.",
                        {"models": installed, "missing_models": [edge_model]},
                    )
            except Exception as exc:
                add_result("edge_helper", "error", f"Could not reach edge helper API: {type(exc).__name__}: {exc}")
    else:
        add_result("edge_helper", "ok", "Edge helper is disabled by operator; the primary inference host handles all planning and writing stages.")

    if scope != "edge":
        splunk_base = str(values.get("SPLUNK_BASE_URL", "")).strip().rstrip("/")
        if splunk_base:
            try:
                req = urllib.request.Request(splunk_base, method="GET")
                context = ssl._create_unverified_context()
                with urllib.request.urlopen(req, timeout=8.0, context=context) as resp:
                    add_result("splunk_base", "ok", f"Splunk base URL reachable ({getattr(resp, 'status', 200)}).")
            except urllib.error.HTTPError as exc:
                add_result("splunk_base", "ok", f"Splunk base URL reachable and returned HTTP {exc.code}.")
            except Exception as exc:
                add_result("splunk_base", "error", f"Could not reach Splunk base URL: {type(exc).__name__}: {exc}")

        splunk_mcp = str(values.get("SPLUNK_MCP_URL", "")).strip()
        token = str(values.get("SPLUNK_LAB_BEARER_TOKEN", "")).strip()
        if splunk_mcp:
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            try:
                req = urllib.request.Request(splunk_mcp, headers=headers, method="GET")
                context = ssl._create_unverified_context()
                with urllib.request.urlopen(req, timeout=8.0, context=context) as resp:
                    add_result("splunk_mcp", "ok", f"Splunk MCP reachable ({getattr(resp, 'status', 200)}).")
            except urllib.error.HTTPError as exc:
                if exc.code == 405:
                    add_result("splunk_mcp", "ok", "Splunk MCP endpoint is reachable and returned HTTP 405, which is expected for a non-MCP GET probe.")
                elif exc.code in {401, 403}:
                    add_result("splunk_mcp", "warn", f"Splunk MCP reached but auth failed with HTTP {exc.code}. Check bearer token.")
                else:
                    add_result("splunk_mcp", "warn", f"Splunk MCP reached but returned HTTP {exc.code}.")
            except Exception as exc:
                add_result("splunk_mcp", "error", f"Could not reach Splunk MCP endpoint: {type(exc).__name__}: {exc}")

        env_state = _environment_profile_bootstrap_state()
        runtime_label = "container runtime" if _running_in_container() else "host runtime"
        if env_state == "ready":
            add_result("environment_profile", "ok", f"Data Domains profile is available for the {runtime_label}.")
        elif env_state == "in_progress":
            add_result("environment_profile", "warn", "Initial Data Domains build is running after successful Splunk MCP validation.")
        else:
            add_result("environment_profile", "warn", "Data Domains will be initialized after Splunk MCP validates successfully.")

    return {
        "summary": summary,
        "checks": results,
        "expected_models": expected_models,
        "connectivity_checks": _validation_connectivity_checks(values),
        "ollama_available_models": available_models,
        "edge_ollama_available_models": edge_available_models,
    }


def _auth_enabled() -> bool:
    value = str(os.getenv("SOC_UI_AUTH_ENABLED", "1")).strip().lower()
    return value not in {"0", "false", "no", "off"}


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return PASSWORD_HASH_PREFIX + base64.b64encode(salt + digest).decode("ascii")


def _password_matches(stored: str, candidate: str) -> bool:
    if not stored:
        return False
    if stored.startswith(PASSWORD_HASH_PREFIX) or stored.startswith(LEGACY_PASSWORD_HASH_PREFIX):
        prefix = PASSWORD_HASH_PREFIX if stored.startswith(PASSWORD_HASH_PREFIX) else LEGACY_PASSWORD_HASH_PREFIX
        payload = stored[len(prefix) :]
        try:
            raw = base64.b64decode(payload.encode("ascii"))
        except Exception:
            return False
        if len(raw) < 48:
            return False
        salt = raw[:16]
        expected = raw[16:]
        actual = hashlib.pbkdf2_hmac("sha256", candidate.encode("utf-8"), salt, 200_000)
        return hmac.compare_digest(expected, actual)
    return hmac.compare_digest(stored, candidate)


def _auth_users_env_value(users: dict[str, dict[str, str]]) -> str:
    payload: list[dict[str, str]] = []
    for username in sorted(users.keys()):
        item = users.get(username, {})
        password = str(item.get("password", "")).strip()
        role = str(item.get("role", "analyst")).strip().lower()
        if not username or not password:
            continue
        if role not in ALLOWED_APP_ROLES:
            role = "analyst"
        payload.append({"username": username, "password": password, "role": role})
    return json.dumps(payload, separators=(",", ":"))


def _persist_auth_users(users: dict[str, dict[str, str]]) -> None:
    env_value = _auth_users_env_value(users)
    write_env_file(
        {
            "SOC_UI_AUTH_USERS_JSON": env_value,
            "SOC_UI_AUTH_ENABLED": "1",
            "SOC_UI_AUTH_INITIALIZED": "1",
        },
        UI_ENV_PATH,
    )
    os.environ["SOC_UI_AUTH_USERS_JSON"] = env_value
    os.environ["SOC_UI_AUTH_ENABLED"] = "1"
    os.environ["SOC_UI_AUTH_INITIALIZED"] = "1"


def _auth_users_for_ui() -> list[dict[str, str]]:
    users = _load_auth_users()
    rows: list[dict[str, str]] = []
    for username in sorted(users.keys()):
        item = users.get(username, {})
        rows.append(
            {
                "username": username,
                "role": str(item.get("role", "analyst")).strip().lower() or "analyst",
                "password_kind": "hashed" if str(item.get("password", "")).startswith(PASSWORD_HASH_PREFIX) else "legacy_plaintext",
            }
        )
    return rows


def _users_snapshot() -> dict[str, Any]:
    return {
        "auth_users": _auth_users_for_ui(),
    }


def _append_query_audit(entry: dict[str, Any]) -> None:
    AUDIT_ROOT.mkdir(parents=True, exist_ok=True)
    with QUERY_AUDIT_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, separators=(",", ":")) + "\n")


def _recent_query_audit(limit: int = 40) -> list[dict[str, Any]]:
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


def _first_run_setup_required() -> bool:
    _lines, file_values = parse_env_file(UI_ENV_PATH)
    initialized = str(os.getenv("SOC_UI_AUTH_INITIALIZED", file_values.get("SOC_UI_AUTH_INITIALIZED", ""))).strip().lower()
    if initialized in {"1", "true", "yes", "on"}:
        return False
    users_env = str(os.getenv("SOC_UI_AUTH_USERS_JSON", file_values.get("SOC_UI_AUTH_USERS_JSON", ""))).strip()
    if users_env:
        return False
    password = str(os.getenv("SOC_UI_AUTH_PASSWORD", file_values.get("SOC_UI_AUTH_PASSWORD", ""))).strip()
    username = str(os.getenv("SOC_UI_AUTH_USERNAME", file_values.get("SOC_UI_AUTH_USERNAME", ""))).strip()
    if not username or not password:
        return True
    return password in DEFAULT_UI_PASSWORDS


def _load_auth_users() -> dict[str, dict[str, str]]:
    _lines, file_values = parse_env_file(UI_ENV_PATH)
    users_env = str(os.getenv("SOC_UI_AUTH_USERS_JSON", file_values.get("SOC_UI_AUTH_USERS_JSON", ""))).strip()
    users: dict[str, dict[str, str]] = {}

    if users_env:
        try:
            parsed = json.loads(users_env)
            if isinstance(parsed, list):
                for item in parsed:
                    if not isinstance(item, dict):
                        continue
                    username = str(item.get("username", "")).strip()
                    password = str(item.get("password", "")).strip()
                    role = str(item.get("role", "analyst")).strip().lower()
                    if username and password:
                        if role not in ALLOWED_APP_ROLES:
                            role = "analyst"
                        users[username] = {"password": password, "role": role}
            elif isinstance(parsed, dict):
                for username, item in parsed.items():
                    if not isinstance(item, dict):
                        continue
                    password = str(item.get("password", "")).strip()
                    role = str(item.get("role", "analyst")).strip().lower()
                    if username and password:
                        if role not in ALLOWED_APP_ROLES:
                            role = "analyst"
                        users[str(username)] = {"password": password, "role": role}
        except Exception:
            users = {}

    if users:
        return users

    username = str(os.getenv("SOC_UI_AUTH_USERNAME", file_values.get("SOC_UI_AUTH_USERNAME", "analyst"))).strip()
    password = str(os.getenv("SOC_UI_AUTH_PASSWORD", file_values.get("SOC_UI_AUTH_PASSWORD", "changeme123!"))).strip()
    role = str(os.getenv("SOC_UI_AUTH_ROLE", file_values.get("SOC_UI_AUTH_ROLE", "ops"))).strip().lower()
    if role not in ALLOWED_APP_ROLES:
        role = "analyst"
    if username and password:
        users[username] = {"password": password, "role": role}
    return users


def _create_session(username: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with SESSIONS_LOCK:
        SESSIONS[token] = {
            "username": username,
            "role": role,
            "created": now,
            "expires": now + SESSION_TTL_SECONDS,
            "admin_onboarding_skip": False,
        }
    return token


def _get_session(token: str) -> dict[str, Any] | None:
    if not token:
        return None
    now = int(time.time())
    with SESSIONS_LOCK:
        session = SESSIONS.get(token)
        if not session:
            return None
        expires = int(session.get("expires", 0))
        if expires <= now:
            SESSIONS.pop(token, None)
            return None
        return dict(session)


def _delete_session(token: str) -> None:
    if not token:
        return
    with SESSIONS_LOCK:
        SESSIONS.pop(token, None)


def _set_session_admin_onboarding_skip(token: str, skip: bool) -> bool:
    if not token:
        return False
    with SESSIONS_LOCK:
        session = SESSIONS.get(token)
        if not session:
            return False
        session["admin_onboarding_skip"] = bool(skip)
    return True


FAVICON_SVG = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>
<defs>
  <linearGradient id='bg' x1='0' y1='0' x2='1' y2='1'>
    <stop offset='0%' stop-color='#ffffff'/>
    <stop offset='100%' stop-color='#eef2f7'/>
  </linearGradient>
  <linearGradient id='lens' x1='0' y1='0' x2='1' y2='1'>
    <stop offset='0%' stop-color='#020617'/>
    <stop offset='100%' stop-color='#0f172a'/>
  </linearGradient>
  <filter id='glow' x='-20%' y='-20%' width='140%' height='140%'>
    <feGaussianBlur stdDeviation='1.4' result='b'/>
    <feMerge>
      <feMergeNode in='b'/>
      <feMergeNode in='SourceGraphic'/>
    </feMerge>
  </filter>
</defs>
<rect x='2' y='2' width='60' height='60' rx='14' fill='url(#bg)' stroke='#334155' stroke-width='2.4'/>
<path d='M9 24c8-9 38-9 46 0' stroke='#0f172a' stroke-width='3.2' fill='none' stroke-linecap='round'/>
<rect x='10' y='23' width='19' height='14' rx='4' fill='url(#lens)' stroke='#020617' stroke-width='1.8'/>
<rect x='35' y='23' width='19' height='14' rx='4' fill='url(#lens)' stroke='#020617' stroke-width='1.8'/>
<rect x='28' y='28' width='8' height='4' rx='1.5' fill='#111827'/>
<path d='M13 27h13M38 27h13' stroke='#475569' stroke-width='1.2' opacity='0.5'/>
<path d='M14 41h36' stroke='#475569' stroke-width='1.8' opacity='0.9' stroke-linecap='round'/>
<path d='M18 18l6 4M46 18l-6 4' stroke='#1e293b' stroke-width='1.4' opacity='0.9' stroke-linecap='round'/>
</svg>
"""


APP_HTML = """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>A.G.E.N.T. Smith</title>
  <link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg?v=agtsmith1\" />
  <link rel=\"icon\" href=\"/favicon.ico?v=agtsmith1\" />
  <style>
    :root {
      --bg:#0f172a; --card:#111827; --card2:#0b1220; --muted:#9ca3af; --fg:#e5e7eb;
      --accent:#22c55e; --warn:#f59e0b; --link:#93c5fd; --line:#1f2937; --bad:#ef4444; --ok:#10b981;
    }
    html {
      min-height:100%;
      background: linear-gradient(140deg,#0b1220 0%,#111827 65%,#0a1f16 100%);
      background-repeat:no-repeat;
      background-size:cover;
    }
    body {
      margin:0;
      min-height:100vh;
      font-family: "Trebuchet MS", "Segoe UI", "Helvetica Neue", Helvetica, sans-serif;
      background: linear-gradient(140deg,#0b1220,#111827 65%,#0a1f16);
      background-repeat:no-repeat;
      background-size:cover;
      color:var(--fg);
    }
    .wrap { max-width: 1740px; min-height:calc(100vh - 48px); margin: 24px auto; padding: 0 28px 32px; box-sizing:border-box; }
    .topnav {
      position:relative;
      z-index:220;
      display:flex;
      flex-wrap:nowrap;
      gap:4px;
      margin-bottom:18px;
      justify-content:flex-start;
      align-items:stretch;
      padding:6px;
      border:1px solid rgba(34,66,92,.44);
      border-radius:22px;
      background:linear-gradient(180deg, rgba(7,18,31,.82), rgba(5,12,23,.72));
      box-shadow:0 18px 34px rgba(0,0,0,.18), inset 0 1px 0 rgba(255,255,255,.03);
      backdrop-filter:blur(16px);
    }
    .nav-item {
      position:relative;
      display:flex;
      flex-direction:column;
      justify-content:center;
      gap:2px;
      min-width:0;
      flex:1 1 0;
      text-decoration:none;
      border:1px solid transparent;
      border-radius:16px;
      padding:8px 9px 9px;
      background:linear-gradient(180deg, rgba(255,255,255,.015), rgba(255,255,255,.008));
      color:#dce9f8;
      box-shadow:inset 0 1px 0 rgba(255,255,255,.018);
      transition:transform .16s ease, border-color .16s ease, box-shadow .16s ease, background .16s ease, color .16s ease;
      overflow:hidden;
    }
    .nav-item-dropdown { overflow:visible; }
    .nav-item-dropdown{ z-index:221; }
    .nav-trigger {
      display:flex;
      flex-direction:column;
      justify-content:center;
      gap:2px;
      min-width:0;
      text-decoration:none;
      color:inherit;
    }
    .nav-item::after{
      content:"";
      position:absolute;
      left:12px;
      right:12px;
      bottom:0;
      height:2px;
      border-radius:999px;
      background:linear-gradient(90deg, rgba(96,165,250,.82), rgba(45,212,191,.82));
      opacity:0;
      transform:scaleX(.5);
      transition:opacity .16s ease, transform .16s ease;
    }
    .nav-item:hover {
      border-color:rgba(81,127,163,.46);
      background:linear-gradient(180deg, rgba(18,35,53,.74), rgba(9,21,34,.66));
      transform:translateY(-1px);
      box-shadow:0 10px 18px rgba(2,6,23,.16), inset 0 1px 0 rgba(255,255,255,.03);
      color:#f8fbff;
    }
    .nav-item:hover::after{
      opacity:.58;
      transform:scaleX(1);
    }
    .nav-item.active {
      border-color:rgba(61,105,136,.5);
      background:linear-gradient(180deg, rgba(17,37,57,.92), rgba(10,24,39,.9));
      color:#ecfdf5;
      box-shadow:0 12px 22px rgba(2,6,23,.18), inset 0 1px 0 rgba(255,255,255,.04);
    }
    .nav-item.active::after{
      opacity:1;
      transform:scaleX(1);
    }
    .nav-kicker { font-size:9px; color:#7ea2c1; text-transform:uppercase; letter-spacing:.12em; font-weight:800; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .nav-item.active .nav-kicker { color:#8fd3ff; }
    .nav-label { font-size:13px; font-weight:900; line-height:1.15; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .nav-submenu {
      position:absolute;
      top:calc(100% + 10px);
      left:0;
      min-width:320px;
      display:grid;
      gap:0;
      padding:8px;
      border:1px solid rgba(46,82,110,.8);
      border-radius:16px;
      background:linear-gradient(180deg, rgba(10,22,36,.98), rgba(6,14,24,.96));
      box-shadow:0 18px 34px rgba(0,0,0,.32), inset 0 1px 0 rgba(255,255,255,.03);
      opacity:0;
      visibility:hidden;
      transform:translateY(6px);
      transition:opacity .14s ease, transform .14s ease, visibility .14s ease;
      z-index:260;
    }
    .nav-item-dropdown:hover .nav-submenu,
    .nav-item-dropdown:focus-within .nav-submenu {
      opacity:1;
      visibility:visible;
      transform:translateY(0);
    }
    .nav-submenu-item {
      display:grid;
      gap:3px;
      padding:10px 12px;
      border-radius:10px;
      text-decoration:none;
      color:#e5eef8;
      transition:background .14s ease, transform .14s ease;
    }
    .nav-submenu-item:hover {
      background:linear-gradient(180deg, rgba(18,37,57,.92), rgba(10,24,39,.88));
      transform:translateX(1px);
    }
    .nav-submenu-title {
      font-size:13px;
      font-weight:900;
      line-height:1.2;
      color:#eff6ff;
    }
    .nav-submenu-copy {
      font-size:12px;
      line-height:1.4;
      color:#9fb4cc;
    }
    .stack { display:grid; grid-template-columns: 1fr; gap:14px; align-items:start; }
    .invest-shell {
      display:grid;
      grid-template-columns:minmax(360px, 408px) minmax(0, 1fr);
      gap:24px;
      align-items:start;
    }
    .invest-sidebar {
      min-width:0;
      align-self:start;
      position:sticky;
      top:88px;
    }
    .invest-sidebar-inner {
      max-height:calc(100vh - 88px);
      overflow-y:auto;
      overscroll-behavior:contain;
      scrollbar-gutter:stable;
      padding-right:4px;
      height:fit-content;
    }
    .invest-main { min-width:0; }
    .card {
      background: rgba(17,24,39,.93);
      border:1px solid var(--line);
      border-radius: 14px;
      padding: 16px;
      box-shadow: 0 12px 30px rgba(0,0,0,.30);
    }
    .control-rail {
      padding:18px;
      border-color:#28445d;
      background:linear-gradient(180deg,#0b1625,#08111d);
    }
    .control-rail .hero-head {
      grid-template-columns:1fr;
      gap:10px;
      margin-bottom:12px;
    }
    .control-rail button {
      width:100%;
      justify-content:center;
    }
    .results-shell {
      display:grid;
      gap:16px;
      padding-bottom:88px;
    }
    .results-card {
      padding:18px 18px 20px;
      background:linear-gradient(180deg,#0a1422,#07111d);
    }
    .hero-head {
      display:grid;
      grid-template-columns: minmax(0, .95fr) minmax(320px, 1.05fr);
      gap:16px;
      align-items:start;
      margin-bottom:8px;
    }
    .hero-title-block { min-width:0; }
    .hero-summary {
      min-width:0;
      padding:10px 14px;
      border:1px solid #24364a;
      border-radius:12px;
      background:linear-gradient(180deg, rgba(10,22,37,.88), rgba(9,18,31,.82));
      color:#d6e3f1;
      line-height:1.55;
      font-size:13px;
    }
    .card-head { display:flex; align-items:center; justify-content:space-between; gap:10px; }
    h1 { margin: 0 0 8px; font-size: 24px; letter-spacing:.2px; }
    h2 { margin: 0 0 8px; font-size: 20px; letter-spacing:.2px; }
    h3 { margin: 14px 0 8px; }
    .muted { color: var(--muted); font-size: 13px; }
    .hint {
      display:inline-flex;
      align-items:center;
      justify-content:center;
      width:16px;
      height:16px;
      border-radius:999px;
      border:1px solid #36516b;
      color:#b9e6ff;
      font-size:11px;
      cursor:help;
      margin-left:6px;
      position:relative;
      top:-1px;
    }
    .hint:hover .hint-pop, .hint:focus-within .hint-pop { display:block; }
    .hint-pop {
      display:none;
      position:absolute;
      top:20px;
      left:-8px;
      width:280px;
      z-index:20;
      background:#07111f;
      border:1px solid #294560;
      border-radius:8px;
      padding:8px;
      color:#dbeafe;
      font-size:12px;
      line-height:1.35;
      box-shadow:0 10px 18px rgba(0,0,0,.35);
    }
    label { display:block; margin: 12px 0 6px; font-size: 13px; color:#d1d5db; }
    textarea, input, select {
      width:100%; box-sizing:border-box; background:var(--card2); color:var(--fg);
      border:1px solid #374151; border-radius:10px; padding:10px;
      font-family: "Trebuchet MS", "Segoe UI", "Helvetica Neue", Helvetica, sans-serif;
      font-size:14px;
    }
    textarea { min-height: 100px; }
    .row { display:grid; grid-template-columns: 1fr 160px 180px 220px; gap:10px; }
    .control-grid { display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:12px; margin-top:10px; }
    .control-grid > div { min-width:0; }
    .control-grid .wide { grid-column:1 / -1; }
    .row-ops { display:none; }
    .ops-field { min-width: 0; }
    .ops-field.wide { grid-column: span 2; }
    .label-row {
      display:flex;
      align-items:center;
      gap:6px;
      flex-wrap:wrap;
    }
    .ops-actions { display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }
    .ops-actions button { margin-top:0; }
    button {
      margin-top: 14px;
      background:linear-gradient(135deg,#22c55e,#14b86a);
      color:#03210d;
      border:1px solid rgba(134,239,172,.22);
      border-radius:14px;
      font-weight:800;
      padding:11px 16px;
      cursor:pointer;
      font-family: "Trebuchet MS", "Segoe UI", "Helvetica Neue", Helvetica, sans-serif;
      letter-spacing:.01em;
      box-shadow:0 10px 22px rgba(20,184,106,.24), inset 0 1px 0 rgba(255,255,255,.18);
      transition:transform .18s ease, box-shadow .18s ease, filter .18s ease, border-color .18s ease;
    }
    button:hover {
      transform:translateY(-1px);
      filter:brightness(1.03);
      box-shadow:0 14px 28px rgba(20,184,106,.30), inset 0 1px 0 rgba(255,255,255,.2);
    }
    .btn-secondary {
      background:linear-gradient(180deg,#16324a,#102435);
      color:#dbeafe;
      border-color:#315a79;
      box-shadow:0 10px 20px rgba(8,23,37,.26), inset 0 1px 0 rgba(255,255,255,.05);
    }
    .btn-secondary:hover {
      box-shadow:0 14px 28px rgba(8,23,37,.34), inset 0 1px 0 rgba(255,255,255,.06);
    }
    .btn-followup {
      background:linear-gradient(135deg,#38bdf8,#0ea5e9);
      color:#041723;
      border-color:rgba(186,230,253,.24);
      box-shadow:0 10px 22px rgba(14,165,233,.22), inset 0 1px 0 rgba(255,255,255,.18);
    }
    .btn-followup:hover {
      box-shadow:0 14px 28px rgba(14,165,233,.30), inset 0 1px 0 rgba(255,255,255,.2);
    }
    .btn-splunk {
      background:linear-gradient(135deg,#22c55e,#16a34a);
      color:#03210d;
      border-color:rgba(134,239,172,.24);
      box-shadow:0 10px 22px rgba(20,184,106,.24), inset 0 1px 0 rgba(255,255,255,.18);
    }
    .btn-splunk:hover {
      box-shadow:0 14px 28px rgba(20,184,106,.30), inset 0 1px 0 rgba(255,255,255,.2);
    }
    .btn-danger { background:#7f1d1d; color:#fee2e2; }
    button:disabled { opacity:.6; cursor:wait; }
    .run-progress-wrap {
      margin-top:10px;
      border:1px solid #2a4056;
      border-radius:10px;
      background:#07111f;
      padding:8px;
    }
    .run-progress-meta {
      display:flex;
      justify-content:space-between;
      gap:8px;
      align-items:center;
      font-size:12px;
      color:#c7d8eb;
      margin-bottom:6px;
    }
    .run-progress-track {
      width:100%;
      height:10px;
      border-radius:999px;
      border:1px solid #1f2937;
      background:#0b2130;
      overflow:hidden;
    }
    .run-progress-bar {
      height:100%;
      width:0%;
      border-radius:999px;
      background:linear-gradient(90deg,#22c55e,#10b981);
      transition:width .2s ease;
    }
    .run-progress-detail-row {
      display:flex;
      justify-content:space-between;
      gap:8px;
      flex-wrap:wrap;
      margin-top:8px;
    }
    .run-progress-detail {
      font-size:12px;
      color:#9fb4cc;
    }
    .run-progress-note {
      margin-top:8px;
      font-size:12px;
      line-height:1.5;
      color:#dbeafe;
      border:1px solid #27415a;
      border-radius:10px;
      background:#081729;
      padding:8px 10px;
    }
    .run-progress-actions {
      display:flex;
      justify-content:flex-end;
      margin-top:8px;
    }
    pre {
      white-space: pre-wrap; background:#020617; border:1px solid var(--line);
      border-radius:10px; padding:12px; overflow:auto; line-height:1.4;
      font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
      font-size:13px;
    }
    #ops-log-output { height: 460px; overflow:auto; }
    .warn { color: var(--warn); }
    .badge {
      display:inline-block; border-radius:999px; padding:4px 10px; border:1px solid #223245;
      background:#0b2130; color:#bde6ff; font-size:12px; margin-left:8px;
    }
    .domain-hints {
      margin-top:8px;
      background:#07111f;
      border:1px solid #27415a;
      border-radius:10px;
      padding:8px;
    }
    .domain-hints summary {
      cursor:pointer;
      outline:none;
      list-style:none;
    }
    .domain-hints summary::-webkit-details-marker { display:none; }
    .domain-hints summary::after {
      content:"Show";
      float:right;
      color:#9fb4cc;
      font-size:12px;
      font-weight:700;
    }
    .domain-hints[open] summary::after { content:"Hide"; }
    .domain-hints .hint-title {
      color:#c7d8eb;
      font-size:12px;
      font-weight:700;
      margin-bottom:0;
    }
    .domain-list {
      display:flex;
      flex-direction:column;
      gap:6px;
    }
    .domain-item {
      border:1px solid #25435f;
      background:#0a1b2d;
      border-radius:8px;
      padding:6px 8px;
      font-size:12px;
      line-height:1.4;
    }
    .domain-item .idx {
      color:#93c5fd;
      font-weight:700;
      font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
    }
    .domain-item .meta {
      color:#bcd2e8;
      margin-top:2px;
      overflow-wrap:anywhere;
    }
    .badge.ok { border-color:#14532d; background:#052e1f; color:#a7f3d0; }
    .badge.bad { border-color:#7f1d1d; background:#2a0d0d; color:#fecaca; }
    .tdir-card {
      background:#07111f;
      border:1px solid #23384f;
      border-radius:10px;
      padding:10px;
      margin-bottom:8px;
    }
    .tdir-head {
      display:flex;
      flex-wrap:wrap;
      gap:8px;
      align-items:center;
      margin-bottom:8px;
    }
    .pill {
      display:inline-block;
      border-radius:999px;
      padding:3px 10px;
      border:1px solid #2a4056;
      background:#0b2130;
      color:#dbeafe;
      font-size:12px;
      line-height:1.2;
      font-weight:700;
    }
    .pill-sev-info { border-color:#1e40af; background:#0f1f4a; color:#bfdbfe; }
    .pill-sev-low { border-color:#166534; background:#052e16; color:#bbf7d0; }
    .pill-sev-medium { border-color:#92400e; background:#3b1d08; color:#fde68a; }
    .pill-sev-high { border-color:#b91c1c; background:#3f1212; color:#fecaca; }
    .pill-risk-low { border-color:#1d4ed8; background:#0f1f4a; color:#bfdbfe; }
    .pill-risk-medium { border-color:#a16207; background:#3b2a08; color:#fde68a; }
    .pill-risk-high { border-color:#b91c1c; background:#3f1212; color:#fecaca; }
    .tdir-meta {
      color:#a7b4c5;
      font-size:12px;
      line-height:1.35;
    }
    .tdir-body {
      display:grid;
      gap:12px;
      margin-top:10px;
    }
    .tdir-section {
      border:1px solid #23384f;
      background:#091525;
      border-radius:12px;
      padding:12px;
    }
    .tdir-section.takeaway {
      border-color:#16a34a;
      background:linear-gradient(180deg, #0d1f17 0%, #0a1611 100%);
      box-shadow:0 0 0 1px rgba(34,197,94,0.18), 0 16px 36px rgba(0,0,0,0.28);
    }
    .tdir-kicker {
      font-size:11px;
      letter-spacing:0.12em;
      text-transform:uppercase;
      color:#86efac;
      font-weight:800;
      margin-bottom:6px;
    }
    .tdir-title {
      color:#f8fafc;
      font-size:18px;
      line-height:1.2;
      font-weight:800;
      margin-bottom:8px;
    }
    .tdir-takeaway-copy {
      color:#dcfce7;
      font-size:14px;
      line-height:1.55;
      margin-bottom:10px;
    }
    .tdir-response-note {
      color:#cbd5e1;
      font-size:12px;
      line-height:1.45;
      padding-top:8px;
      border-top:1px solid rgba(148,163,184,0.2);
    }
    .summary-box {
      white-space:pre-wrap;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size:14px;
      line-height:1.7;
      color:#e5eefc;
      background:#0a1422;
      border:1px solid #23384f;
      border-radius:12px;
      padding:14px 16px;
    }
    .summary-box strong {
      color:#ffffff;
      font-weight:800;
    }
    .summary-box .summary-lead {
      color:#ffffff;
      font-weight:800;
    }
    .summary-section {
      margin-bottom:14px;
      padding:12px 14px;
      border:1px solid #22384f;
      border-radius:12px;
      background:#081729;
    }
    .summary-section:last-child { margin-bottom:0; }
    .summary-section-title {
      color:#f8fafc;
      font-size:12px;
      font-weight:900;
      letter-spacing:.08em;
      text-transform:uppercase;
      margin-bottom:8px;
    }
    .summary-section-copy {
      color:#dbeafe;
      font-size:14px;
      line-height:1.65;
    }
    .summary-bullets {
      margin:0;
      padding-left:18px;
      display:grid;
      gap:8px;
    }
    .summary-bullets li {
      color:#e5eefc;
      line-height:1.55;
    }
    .summary-callout {
      border-color:#2f6b95;
      background:linear-gradient(180deg,#0b1b2b,#081729);
    }
    .summary-callout .summary-section-title {
      color:#bde6ff;
    }
    .summary-critical {
      border-color:#16a34a;
      background:linear-gradient(180deg,#0d1f17,#091712);
      box-shadow:0 0 0 1px rgba(34,197,94,.14);
    }
    .summary-critical .summary-section-title {
      color:#bbf7d0;
    }
    .tdir-label {
      color:#8fb6d9;
      font-size:11px;
      letter-spacing:0.08em;
      text-transform:uppercase;
      font-weight:800;
      margin-bottom:8px;
    }
    .tdir-hypothesis {
      color:#dbeafe;
      font-size:14px;
      line-height:1.5;
    }
    .tdir-phase-grid {
      display:flex;
      flex-wrap:wrap;
      gap:8px;
    }
    .phase-pill {
      display:flex;
      align-items:center;
      gap:8px;
      border-radius:999px;
      padding:7px 12px;
      border:1px solid #29445f;
      background:#0c1d2d;
      min-width:150px;
    }
    .phase-pill .phase-name {
      font-size:12px;
      font-weight:800;
      letter-spacing:0.04em;
      text-transform:uppercase;
      color:#e2e8f0;
    }
    .phase-pill .phase-state {
      font-size:12px;
      color:#d6e4f5;
      font-weight:700;
    }
    .phase-pill.detect { border-color:#1d4ed8; background:#0b1731; }
    .phase-pill.triage { border-color:#15803d; background:#061a12; }
    .phase-pill.investigate { border-color:#b45309; background:#221105; }
    .phase-pill.respond { border-color:#dc2626; background:#2a0b0b; }
    .phase-pill.recover { border-color:#7c3aed; background:#160a2d; }
    .phase-pill.soar_automation { border-color:#0f766e; background:#081f23; }
    .phase-pill.complete .phase-state { color:#bbf7d0; }
    .phase-pill.planned .phase-state { color:#fde68a; }
    .phase-pill.not_enabled_yet .phase-state { color:#93c5fd; }
    .phase-pill.awaiting_human_approval .phase-state { color:#fca5a5; }
    .tdir-pivot-list {
      display:grid;
      gap:8px;
      margin:0;
      padding:0;
      list-style:none;
    }
    .tdir-pivot-item {
      border:1px solid rgba(74,222,128,0.28);
      background:rgba(34,197,94,0.08);
      border-radius:10px;
      padding:10px 12px;
      color:#f0fdf4;
      font-size:14px;
      line-height:1.5;
      font-weight:600;
    }
    .tdir-pivot-item.priority {
      border-color:#22c55e;
      background:linear-gradient(180deg, rgba(34,197,94,0.18) 0%, rgba(34,197,94,0.08) 100%);
      color:#ffffff;
      box-shadow:0 0 0 1px rgba(34,197,94,0.18);
    }
    .persona-grid {
      display:flex;
      flex-wrap:wrap;
      align-items:stretch;
      gap:8px;
      margin-bottom:4px;
    }
    .persona {
      border:1px solid #27415a;
      background:#07111f;
      border-radius:10px;
      padding:8px 9px;
      min-width:0;
      flex:1 1 220px;
      max-width:320px;
      overflow:hidden;
    }
    .persona .p-head {
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:8px;
      margin-bottom:3px;
    }
    .persona .p-name {
      font-weight:700;
      color:#dbeafe;
      font-size:12px;
    }
    .persona.planner { border-color:#1d4ed8; background:#0b1731; }
    .persona.reviewer { border-color:#15803d; background:#061a12; }
    .persona.judge { border-color:#b45309; background:#221105; }
    .persona.judge2 { border-color:#db2777; background:#2a0b1c; }
    .persona.policy { border-color:#7c3aed; background:#1a0a2e; }
    .persona .p-role {
      color:#9fb4cc;
      font-size:11px;
      margin-bottom:4px;
    }
    .persona .p-detail {
      color:#cdd8e5;
      font-size:11px;
      line-height:1.4;
      display:grid;
      gap:4px;
      overflow-wrap:anywhere;
    }
    .persona .p-model {
      color:#8fb7ff;
      font-size:10px;
      overflow-wrap:anywhere;
      margin-bottom:4px;
    }
    .persona .p-why,.persona .p-outcome{
      border-top:1px solid rgba(53,83,110,.48);
      padding-top:4px;
    }
    .persona .p-mini-label{
      color:#8fb6d9;
      font-size:9px;
      text-transform:uppercase;
      letter-spacing:.08em;
      font-weight:800;
      margin-bottom:2px;
    }
    .persona-arrow{
      flex:0 0 auto;
      display:flex;
      align-items:center;
      justify-content:center;
      color:#6cb7ff;
      font-size:18px;
      font-weight:900;
      padding:0 2px;
      opacity:.9;
    }
    .persona.planner .p-model { color:#93c5fd; }
    .persona.reviewer .p-model { color:#86efac; }
    .persona.judge .p-model { color:#fcd34d; }
    .persona.judge2 .p-model { color:#f9a8d4; }
    .persona.policy .p-model { color:#d8b4fe; }
    .spl-card {
      border:1px solid rgba(41,69,96,.72);
      background:linear-gradient(180deg,#071523,#06111d);
      border-radius:10px;
      padding:12px;
    }
    .spl-raw-shell{
      display:none;
      margin-top:12px;
      padding-top:12px;
      border-top:1px solid rgba(36,67,96,.65);
    }
    .spl-raw-shell.open{
      display:block;
    }
    .spl-toggle {
      margin-top:8px;
      border:1px solid #22384f;
      border-radius:10px;
      background:#081729;
      padding:8px 10px;
    }
    .spl-toggle summary {
      cursor:pointer;
      list-style:none;
      outline:none;
      color:#dbeafe;
      font-size:13px;
      font-weight:700;
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
    }
    .spl-toggle summary::-webkit-details-marker { display:none; }
    .spl-toggle summary::after {
      content:"Show";
      color:#9fb4cc;
      font-size:12px;
      font-weight:800;
    }
    .spl-toggle[open] summary::after { content:"Hide"; }
    .spl-toggle-body {
      margin-top:8px;
    }
    .section-head {
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
    }
    .spl-title {
      font-weight:700;
      font-size:13px;
      color:#dbeafe;
      margin-bottom:0;
    }
    .coverage-grid{
      display:grid;
      gap:10px;
    }
    .coverage-row{
      display:grid;
      grid-template-columns:180px minmax(0,1fr);
      gap:12px;
      padding:10px 12px;
      border:1px solid #22384f;
      border-radius:10px;
      background:#081729;
    }
    .coverage-row-title{
      color:#8fb6d9;
      font-size:11px;
      font-weight:800;
      letter-spacing:.08em;
      text-transform:uppercase;
    }
    .coverage-row-copy{
      color:#e5eefc;
      font-size:13px;
      line-height:1.5;
      overflow-wrap:anywhere;
    }
    .coverage-row.gap{
      border-color:#7f1d1d;
      background:linear-gradient(180deg,#231018,#140b10);
    }
    .decision-log {
      white-space: pre-wrap;
      background:#020617;
      border:1px solid var(--line);
      border-radius:10px;
      padding:12px;
      overflow:auto;
      line-height:1.45;
      font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
      font-size:13px;
    }
    .role-line { margin-bottom:4px; }
    .role-line strong { font-weight:800; }
    .role-line.planner strong { color:#93c5fd; }
    .role-line.reviewer strong { color:#86efac; }
    .role-line.judge strong { color:#fcd34d; }
    .role-line.judge2 strong { color:#f9a8d4; }
    .role-line.policy strong { color:#d8b4fe; }
    .role-model{font-weight:900;color:#f8fafc;overflow-wrap:anywhere;}
    .decision-subhead {
      margin:10px 0 6px;
      color:#9fb4cc;
      font-weight:700;
    }
    .advanced-shell {
      position:fixed;
      left:24px;
      right:24px;
      bottom:0;
      z-index:8;
      border:1px solid #27415a;
      border-bottom:0;
      border-radius:16px 16px 0 0;
      background:linear-gradient(180deg,rgba(8,20,35,.98),rgba(5,13,24,.98));
      box-shadow:0 -18px 36px rgba(2,6,23,.38);
      padding:0;
      overflow:hidden;
    }
    .advanced-shell:not([open]){
      border-color:#23384f;
      box-shadow:0 -12px 26px rgba(2,6,23,.28);
    }
    .advanced-shell summary {
      cursor:pointer;
      font-weight:800;
      color:#dbeafe;
      outline:none;
      list-style:none;
      display:grid;
      grid-template-columns:minmax(0,1fr) auto;
      align-items:center;
      gap:10px;
      padding:8px 14px;
    }
    .advanced-shell:not([open]) summary{
      padding:10px 14px;
      background:linear-gradient(180deg,rgba(7,19,32,.98),rgba(6,14,24,.98));
    }
    .advanced-shell summary::-webkit-details-marker{display:none;}
    .advanced-shell[open] .advanced-drawer-toggle{
      transform:rotate(180deg);
    }
    .advanced-drawer-head{
      display:flex;
      flex-direction:column;
      align-items:flex-start;
      gap:5px;
      min-width:0;
    }
    .advanced-drawer-title-row{
      display:flex;
      align-items:center;
      gap:8px;
      min-width:0;
      flex-wrap:wrap;
    }
    .advanced-drawer-copy{
      color:#9fb4cc;
      font-size:11px;
      line-height:1.2;
      font-weight:400;
      white-space:normal;
    }
    .advanced-summary-main{
      min-width:0;
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:12px;
    }
    .advanced-summary-controls{
      display:flex;
      align-items:center;
      justify-content:flex-end;
      gap:8px;
      min-width:0;
      flex-wrap:nowrap;
    }
    .drawer-update-indicator{
      display:none;
      align-items:center;
      gap:6px;
      padding:6px 10px;
      border-radius:999px;
      border:1px solid rgba(52,211,153,.38);
      background:rgba(6,78,59,.32);
      color:#bbf7d0;
      font-size:11px;
      font-weight:700;
      letter-spacing:.08em;
      text-transform:uppercase;
      white-space:nowrap;
      box-shadow:0 0 0 1px rgba(16,185,129,.08), 0 0 22px rgba(16,185,129,.12);
    }
    .drawer-update-indicator.visible{display:inline-flex;}
    .drawer-update-dot{
      width:8px;
      height:8px;
      border-radius:999px;
      background:#34d399;
      box-shadow:0 0 0 4px rgba(16,185,129,.12);
    }
    .drawer-jump-links{
      display:flex;
      flex-wrap:nowrap;
      gap:5px;
      align-items:center;
      min-width:0;
      overflow-x:auto;
      scrollbar-width:none;
    }
    .drawer-jump-links::-webkit-scrollbar{display:none;}
    .drawer-jump-links .jump-link{
      padding:4px 8px;
      font-size:11px;
      background:rgba(8,23,37,.84);
      white-space:nowrap;
    }
    .drawer-jump-links .jump-link.active{
      background:linear-gradient(135deg,#0ea5e9,#1d4ed8);
      border-color:#60a5fa;
      color:#f8fafc;
    }
    .drawer-jump-links .jump-link.has-update{
      border-color:rgba(52,211,153,.48);
      color:#d1fae5;
      box-shadow:0 0 0 1px rgba(16,185,129,.14);
    }
    .drawer-spl-toggle{
      margin-top:0;
      white-space:nowrap;
      padding:6px 9px;
      font-size:11px;
      flex:0 0 auto;
    }
    .advanced-drawer-actions{
      display:flex;
      align-items:center;
      gap:8px;
    }
    .advanced-drawer-toggle{
      display:inline-flex;
      align-items:center;
      justify-content:center;
      width:24px;
      height:24px;
      border-radius:999px;
      border:1px solid #315a79;
      background:#0a2034;
      color:#dbeafe;
      font-size:15px;
      font-weight:900;
      flex:0 0 auto;
      transition:transform .18s ease;
    }
    .advanced-drawer-expand{
      display:inline-flex;
      align-items:center;
      justify-content:center;
      width:32px;
      height:28px;
      border-radius:999px;
      border:1px solid #315a79;
      background:#0a2034;
      color:#dbeafe;
      font-size:14px;
      font-weight:900;
      flex:0 0 auto;
      padding:0;
    }
    .advanced-shell:not([open]) .advanced-drawer-expand{
      opacity:.45;
      pointer-events:none;
    }
    .advanced-body {
      margin-top:0;
      display:grid;
      gap:14px;
      padding:0 16px 16px;
      max-height:38vh;
      overflow:auto;
    }
    .advanced-shell[data-mode="medium"] .advanced-body{
      max-height:38vh;
    }
    .advanced-shell[data-mode="full"]{
      top:76px;
      left:24px;
      right:24px;
    }
    .advanced-shell[data-mode="full"] .advanced-body{
      max-height:calc(100vh - 124px);
    }
    .advanced-panel {
      border:1px solid #22384f;
      border-radius:10px;
      background:#081729;
      padding:10px;
    }
    .advanced-panel[data-tray-panel]{display:none;}
    .advanced-panel[data-tray-panel].active{display:block;}
    .drawer-clone-grid{display:grid;gap:12px;}
    .drawer-clone-card{border:1px solid #27415a;border-radius:12px;background:#071523;padding:12px;}
    .drawer-clone-title{font-size:12px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:#7dd3fc;margin-bottom:6px;}
    .drawer-clone-copy{color:#dbeafe;font-size:13px;line-height:1.55;}
    .drawer-spl-pre{white-space:pre-wrap;background:#030b17;border:1px solid #26435c;border-radius:10px;padding:10px;overflow:auto;line-height:1.45;font-family:"Consolas","SFMono-Regular",Menlo,monospace;font-size:12px;color:#dbeafe;max-height:240px;}
    .drawer-trust-strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;}
    .drawer-trust-card{border:1px solid #27415a;border-radius:12px;background:#071523;padding:10px 12px;}
    .drawer-trust-label{font-size:11px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:#9fb4cc;margin-bottom:6px;}
    .drawer-trust-value{color:#f8fafc;font-size:14px;font-weight:800;line-height:1.35;}
    .drawer-trust-note{margin-top:4px;color:#a9bdd4;font-size:12px;line-height:1.45;}
    .drawer-action-list{display:grid;gap:10px;}
    .drawer-action-card{display:grid;grid-template-columns:minmax(0,1.4fr) repeat(3,minmax(120px,.9fr)) auto;gap:10px;align-items:center;border:1px solid #27415a;border-radius:12px;background:#071523;padding:10px 12px;}
    .drawer-action-head{display:block;min-width:0;}
    .drawer-action-title{font-size:13px;font-weight:800;color:#f8fafc;line-height:1.35;}
    .drawer-action-kicker{font-size:10px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:#7dd3fc;margin-bottom:4px;}
    .drawer-action-copy{color:#c8d6e5;font-size:12px;line-height:1.45;margin-top:4px;}
    .drawer-action-meta{display:contents;}
    .drawer-action-meta-item{border:1px solid #1f3348;border-radius:10px;background:rgba(7,21,35,.88);padding:8px;min-width:0;}
    .drawer-action-meta-item strong{display:block;color:#dbeafe;font-size:10px;letter-spacing:.06em;text-transform:uppercase;margin-bottom:4px;}
    .drawer-action-buttons{display:flex;flex-direction:column;gap:8px;align-items:stretch;}
    .drawer-action-buttons button,.drawer-action-buttons a{margin-top:0;width:auto;}
    .drawer-inline-note{border:1px dashed #315a79;border-radius:12px;padding:10px 12px;background:rgba(8,23,37,.56);color:#b9cbe0;font-size:12px;line-height:1.5;}
    .drawer-entity-table{width:100%;border-collapse:separate;border-spacing:0 8px;}
    .drawer-entity-table th{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#89a5c0;text-align:left;padding:0 10px 2px;}
    .drawer-entity-table td{background:#071523;border-top:1px solid #27415a;border-bottom:1px solid #27415a;padding:9px 10px;color:#dbeafe;font-size:13px;vertical-align:top;}
    .drawer-entity-table tr.drawer-row-link{cursor:pointer;}
    .drawer-entity-table tr.drawer-row-link:hover td{background:#0b1d30;}
    .drawer-entity-table td:first-child{border-left:1px solid #27415a;border-radius:10px 0 0 10px;}
    .drawer-entity-table td:last-child{border-right:1px solid #27415a;border-radius:0 10px 10px 0;}
    .drawer-value-tag{display:inline-flex;max-width:100%;padding:4px 8px;border-radius:999px;border:1px solid #315a79;font-size:12px;font-weight:700;line-height:1.35;overflow-wrap:anywhere;}
    .drawer-empty{color:#9fb4cc;font-size:13px;line-height:1.55;}
    .drawer-timeline-mini{display:grid;gap:10px;}
    .drawer-timeline-step{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:start;border:1px solid #27415a;border-radius:12px;background:#071523;padding:10px 12px;}
    .drawer-timeline-index{width:24px;height:24px;border-radius:999px;background:#0a2034;border:1px solid #315a79;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:900;color:#dbeafe;}
    .drawer-timeline-title{font-size:13px;font-weight:800;color:#f8fafc;}
    .drawer-timeline-copy{color:#b9cbe0;font-size:12px;line-height:1.5;margin-top:4px;}
    .drawer-timeline-tag{font-size:11px;font-weight:800;color:#c8d6e5;background:#102235;border:1px solid #27415a;border-radius:999px;padding:4px 8px;white-space:nowrap;}
    .drawer-chip-row{display:flex;flex-wrap:wrap;gap:8px;}
    .drawer-chip{display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border-radius:999px;border:1px solid #27415a;background:#081729;color:#dbeafe;font-size:12px;font-weight:700;}
    .drawer-technique-grid{display:grid;gap:10px;}
    .drawer-technique-card{--mitre-accent:#5b7f9c;border:1px solid color-mix(in srgb, var(--mitre-accent) 40%, #2a4056);border-left:3px solid color-mix(in srgb, var(--mitre-accent) 85%, #2a4056);border-radius:12px;background:linear-gradient(180deg, color-mix(in srgb, var(--mitre-accent) 9%, #071523), #071523 72%);padding:12px;}
    .drawer-technique-title{font-size:13px;font-weight:900;color:#f8fafc;line-height:1.35;}
    .drawer-technique-kicker{font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:#8fb6d9;font-weight:800;margin-bottom:4px;}
    .drawer-technique-copy{color:#c8d6e5;font-size:12px;line-height:1.5;margin-top:6px;}
    .drawer-technique-meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px;}
    .drawer-technique-pill{display:inline-flex;align-items:center;padding:5px 9px;border-radius:999px;border:1px solid #315a79;background:#0a2034;color:#dbeafe;font-size:11px;font-weight:700;}
    .advanced-subhead {
      margin:0 0 8px;
      font-size:13px;
      font-weight:800;
      color:#dbeafe;
      letter-spacing:.2px;
    }
    .flow-shell {
      margin-top:0;
      border:1px solid #27415a;
      border-radius:10px;
      background:#061423;
      padding:8px 10px;
    }
    .flow-shell summary {
      cursor:pointer;
      font-weight:700;
      color:#dbeafe;
      outline:none;
    }
    .flow-track {
      margin-top:10px;
      display:flex;
      gap:8px;
      align-items:stretch;
      flex-wrap:wrap;
    }
    .flow-node {
      min-width:150px;
      flex:1 1 150px;
      border-radius:10px;
      border:1px solid #2a4056;
      background:#0b2130;
      padding:8px;
    }
    .flow-node .n-title {
      font-weight:800;
      font-size:12px;
      color:#e5e7eb;
      margin-bottom:4px;
      letter-spacing:.2px;
    }
    .flow-node .n-status {
      font-size:12px;
      color:#cbd5e1;
      margin-bottom:4px;
    }
    .flow-node .n-time {
      font-size:12px;
      color:#93c5fd;
      font-weight:700;
    }
    .flow-arrow {
      align-self:center;
      color:#7dd3fc;
      font-weight:800;
      font-size:14px;
      padding:0 2px;
    }
    .flow-node.complete { border-color:#166534; background:#052e16; }
    .flow-node.in_progress { border-color:#92400e; background:#3b1d08; }
    .flow-node.awaiting_human_approval { border-color:#7c3aed; background:#2a1148; }
    .flow-node.planned { border-color:#1d4ed8; background:#0f1f4a; }
    .flow-node.not_enabled_yet { border-color:#475569; background:#0f172a; }
    .flow-meta { margin-top:8px; color:#9fb4cc; font-size:12px; }
    .continue-shell {
      margin-top:14px;
      padding:14px;
      border:1px solid #244360;
      border-radius:12px;
      background:linear-gradient(180deg,#0d1a2d,#091423);
    }
    .continue-title {
      margin:0 0 8px;
      font-size:16px;
      color:#e2e8f0;
    }
    .continue-copy {
      margin:0 0 10px;
      color:#9fb4cc;
      font-size:13px;
      line-height:1.5;
      white-space:pre-wrap;
    }
    .continue-actions {
      display:flex;
      gap:10px;
      align-items:center;
      flex-wrap:wrap;
    }
    .continue-pill {
      display:inline-flex;
      align-items:center;
      gap:6px;
      padding:5px 10px;
      border-radius:999px;
      border:1px solid #2a4d6b;
      background:#0a2034;
      color:#cbe4ff;
      font-size:12px;
      font-weight:700;
    }
    .toggle-row{
      display:flex;
      align-items:center;
      gap:10px;
      min-height:44px;
    }
    .switch{
      position:relative;
      display:inline-block;
      width:54px;
      height:30px;
      flex:0 0 auto;
    }
    .switch input{
      opacity:0;
      width:0;
      height:0;
      position:absolute;
    }
    .slider{
      position:absolute;
      inset:0;
      cursor:pointer;
      background:#0f2233;
      border:1px solid #315a79;
      transition:.2s ease;
      border-radius:999px;
      box-shadow:inset 0 1px 0 rgba(255,255,255,.03);
    }
    .slider:before{
      content:"";
      position:absolute;
      height:22px;
      width:22px;
      left:3px;
      top:3px;
      background:#dbeafe;
      transition:.2s ease;
      border-radius:50%;
      box-shadow:0 4px 10px rgba(2,6,23,.35);
    }
    .switch input:checked + .slider{
      background:linear-gradient(135deg,#22c55e,#16a34a);
      border-color:#22c55e;
    }
    .switch input:checked + .slider:before{
      transform:translateX(24px);
      background:#03140b;
    }
    .toggle-copy{
      color:#dbeafe;
      font-size:13px;
      font-weight:700;
    }
    .control-status {
      margin-top:12px;
      border:1px solid #294560;
      border-radius:12px;
      background:#091423;
      padding:10px 12px;
    }
    .control-collapsible {
      margin-top:12px;
      border:1px solid #294560;
      border-radius:12px;
      background:#091423;
      padding:10px 12px;
    }
    .control-collapsible summary {
      cursor:pointer;
      list-style:none;
      outline:none;
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      color:#dbeafe;
      font-size:13px;
      font-weight:800;
    }
    .control-collapsible summary::-webkit-details-marker { display:none; }
    .control-collapsible summary::after {
      content:"Show";
      color:#9fb4cc;
      font-size:12px;
      font-weight:800;
    }
    .control-collapsible[open] summary::after { content:"Hide"; }
    .control-collapsible-body {
      margin-top:10px;
      display:grid;
      gap:10px;
    }
    .control-collapsible:not([open]) .control-collapsible-body {
      display:none;
    }
    .followup-panel {
      margin-top:12px;
      border:1px solid #2b4a66;
      border-radius:12px;
      background:linear-gradient(180deg,#0a1828,#08111d);
      padding:12px;
      box-shadow:0 12px 24px rgba(0,0,0,.24);
    }
    .followup-panel.empty {
      border-color:#22384f;
      background:#091423;
    }
    .followup-head {
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      margin-bottom:8px;
    }
    .followup-body {
      color:#dbeafe;
      font-size:13px;
      line-height:1.55;
      white-space:pre-wrap;
      min-height:40px;
    }
    .followup-meta {
      margin-top:8px;
      color:#8fb6d9;
      font-size:12px;
      line-height:1.45;
    }
    .followup-item {
      border:1px solid #27415a;
      border-radius:10px;
      background:#0a1625;
      padding:10px;
      cursor:pointer;
      transition:border-color .18s ease, background .18s ease, transform .18s ease;
    }
    .followup-item:hover {
      border-color:#4f7aa1;
      background:#0c1b2d;
      transform:translateY(-1px);
    }
    .followup-item.active {
      border-color:#22c55e;
      background:linear-gradient(180deg,#0d2017,#091712);
      box-shadow:0 0 0 1px rgba(34,197,94,.16);
    }
    .followup-item-kicker {
      color:#93c5fd;
      font-size:10px;
      font-weight:800;
      letter-spacing:.08em;
      text-transform:uppercase;
      margin-bottom:6px;
    }
    .followup-item-copy {
      color:#e5eefc;
      font-size:13px;
      line-height:1.5;
    }
    .followup-empty {
      color:#9fb4cc;
      font-size:12px;
      line-height:1.5;
      padding:10px;
      border:1px dashed #294560;
      border-radius:10px;
      background:#091423;
    }
    .followup-actions {
      display:flex;
      gap:8px;
      flex-wrap:wrap;
      margin-top:10px;
    }
    .followup-actions button {
      margin-top:0;
      width:auto;
      justify-content:center;
    }
    .mitre-selects {
      display:grid;
      gap:8px;
      margin-top:10px;
    }
    .mitre-select-row {
      display:flex;
      align-items:flex-start;
      justify-content:space-between;
      gap:10px;
      border:1px solid #22384f;
      border-radius:10px;
      background:#091423;
      padding:10px;
    }
    .mitre-select-copy {
      color:#dbeafe;
      font-size:12px;
      line-height:1.5;
      flex:1 1 auto;
    }
    .mitre-select-btn {
      appearance:none;
      border:1px solid #315a79;
      border-radius:999px;
      padding:7px 10px;
      background:linear-gradient(180deg,#16324a,#102435);
      color:#dbeafe;
      font-size:12px;
      font-weight:800;
      cursor:pointer;
      white-space:nowrap;
      flex:0 0 auto;
    }
    .mitre-select-btn:hover {
      border-color:#60a5fa;
      transform:translateY(-1px);
    }
    .control-status-head {
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      margin-bottom:6px;
    }
    .control-status-copy {
      color:#9fb4cc;
      font-size:12px;
      line-height:1.5;
    }
    .phase-strip{
      margin-top:10px;
      display:grid;
      gap:8px;
    }
    .phase-strip-row{
      display:grid;
      grid-template-columns:repeat(3,minmax(0,1fr));
      gap:8px;
    }
    .case-rail{
      margin-top:12px;
      border:1px solid #294560;
      border-radius:12px;
      background:#091423;
      padding:10px 12px;
      display:grid;
      gap:10px;
    }
    .drawer-narrative-shell{
      display:grid;
      gap:12px;
      margin-bottom:12px;
    }
    .timeline-story-card{
      border:1px solid #294560;
      border-radius:14px;
      background:linear-gradient(135deg,rgba(8,24,40,.98),rgba(9,32,24,.9));
      padding:14px 16px;
      box-shadow:0 10px 30px rgba(0,0,0,.16);
      display:grid;
      gap:12px;
    }
    .timeline-story-head{
      display:flex;
      flex-wrap:wrap;
      justify-content:space-between;
      gap:10px;
      align-items:flex-start;
    }
    .timeline-story-title{
      color:#f8fbff;
      font-size:14px;
      font-weight:900;
      letter-spacing:.01em;
    }
    .timeline-story-copy{
      color:#dbeafe;
      font-size:13px;
      line-height:1.6;
      max-width:980px;
    }
    .timeline-pattern-strip,.timeline-entity-strip{
      display:flex;
      flex-wrap:wrap;
      gap:8px;
      margin-top:10px;
    }
    .timeline-pattern-chip,.entity-pill{
      display:inline-flex;
      align-items:center;
      gap:6px;
      padding:6px 10px;
      border-radius:999px;
      border:1px solid #264760;
      background:#081826;
      color:#dbeafe;
      font-size:11px;
      font-weight:700;
      line-height:1.2;
    }
    .timeline-pattern-chip strong,.entity-pill strong{
      color:#7dd3fc;
      font-size:10px;
      letter-spacing:.08em;
      text-transform:uppercase;
    }
    .entity-pill{
      cursor:pointer;
      background:linear-gradient(180deg,#0a1a27,#091522);
      transition:border-color .15s ease, transform .15s ease, opacity .15s ease;
    }
    .entity-pill:hover{border-color:#4f7aa1;transform:translateY(-1px);}
    .entity-pill.active{border-color:#22c55e;background:linear-gradient(180deg,#0d2017,#0b1a14);}
    .entity-pill .entity-count{color:#9fb4cc;font-size:10px;font-weight:800;}
    .timeline-decision-block{
      margin-top:10px;
      border:1px solid #27415a;
      border-radius:12px;
      background:#071523;
      padding:12px;
      display:grid;
      gap:8px;
    }
    .timeline-decision-title{
      color:#f8fafc;
      font-size:12px;
      font-weight:900;
      letter-spacing:.08em;
      text-transform:uppercase;
    }
    .timeline-decision-copy{
      color:#dbeafe;
      font-size:13px;
      line-height:1.55;
    }
    .timeline-decision-actions{
      display:flex;
      flex-wrap:wrap;
      gap:8px;
    }
    .timeline-filter-bar{
      display:flex;
      flex-wrap:wrap;
      gap:8px;
      margin-top:10px;
    }
    .timeline-filter-chip{
      border:1px solid #294560;
      border-radius:999px;
      background:#071523;
      color:#dbeafe;
      font-size:11px;
      font-weight:800;
      padding:6px 10px;
      cursor:pointer;
    }
    .timeline-filter-chip.active{border-color:#22c55e;background:#0d2017;color:#effef5;}
    .timeline-active-filter{
      margin-top:10px;
      border:1px solid #315a79;
      border-radius:10px;
      background:#08131f;
      color:#dbeafe;
      padding:8px 10px;
      font-size:12px;
      line-height:1.45;
    }
    .case-timeline-list{
      display:grid;
      gap:14px;
      max-height:540px;
      overflow-y:auto;
      overflow-x:hidden;
      padding-right:4px;
      min-width:0;
      position:relative;
    }
    .case-timeline-list::before{
      content:'';
      position:absolute;
      left:20px;
      top:8px;
      bottom:8px;
      width:2px;
      background:linear-gradient(180deg,rgba(34,197,94,.2),rgba(56,189,248,.22),rgba(148,163,184,.14));
      border-radius:999px;
      pointer-events:none;
    }
    .timeline-step-card{
      position:relative;
      margin-left:22px;
      border:1px solid #28415b;
      border-radius:16px;
      background:linear-gradient(180deg,#071523,#081727);
      padding:14px 14px 12px;
      display:grid;
      gap:12px;
      box-sizing:border-box;
      min-width:0;
      overflow:hidden;
      transition:border-color .16s ease, transform .16s ease, opacity .16s ease, box-shadow .16s ease;
      box-shadow:0 8px 24px rgba(0,0,0,.12);
    }
    .timeline-step-card::before{
      content:'';
      position:absolute;
      left:-18px;
      top:22px;
      width:12px;
      height:12px;
      border-radius:999px;
      border:2px solid #244762;
      background:#061523;
      box-shadow:0 0 0 3px rgba(6,21,35,.96);
    }
    .timeline-step-card[data-step-type=\"investigation\"]::before{border-color:#38bdf8;background:#0a2034;}
    .timeline-step-card[data-step-type=\"pivot\"]::before{border-color:#22c55e;background:#0d2017;}
    .timeline-step-card:hover{border-color:#4f7aa1;transform:translateY(-1px);}
    .timeline-step-card.current{border-color:#22c55e;background:linear-gradient(180deg,#0d2017,#0a1724);}
    .timeline-step-card.restored{border-color:#38bdf8;}
    .timeline-step-card.no-results{border-color:#7c4a17;background:linear-gradient(180deg,#16100a,#0b1521);}
    .timeline-step-card.dimmed{opacity:.36;}
    .timeline-step-card.focused{box-shadow:0 0 0 1px rgba(34,197,94,.35), 0 12px 32px rgba(0,0,0,.18);}
    .timeline-step-header{
      display:flex;
      justify-content:space-between;
      gap:10px;
      align-items:flex-start;
      min-width:0;
    }
    .timeline-step-heading{
      display:grid;
      gap:8px;
      min-width:0;
    }
    .timeline-step-labels{
      display:flex;
      flex-wrap:wrap;
      gap:8px;
      align-items:center;
    }
    .timeline-step-kicker{
      color:#9fd3ff;
      font-size:10px;
      font-weight:900;
      letter-spacing:.1em;
      text-transform:uppercase;
    }
    .timeline-step-badge{
      display:inline-flex;
      align-items:center;
      padding:5px 9px;
      border-radius:999px;
      border:1px solid #294560;
      background:#081826;
      color:#dbeafe;
      font-size:10px;
      font-weight:800;
      text-transform:uppercase;
      letter-spacing:.08em;
    }
    .timeline-step-badge.status-current{border-color:#22c55e;background:#0d2017;color:#effef5;}
    .timeline-step-badge.status-restored{border-color:#38bdf8;background:#0a2034;}
    .timeline-step-badge.status-no-results{border-color:#d97706;background:#1b1408;color:#fde68a;}
    .timeline-step-badge.status-superseded{border-color:#3c5267;background:#09131d;color:#b8c9db;}
    .timeline-step-time{
      color:#8fb6d9;
      font-size:11px;
      line-height:1.45;
      text-align:right;
      flex:0 0 auto;
    }
    .timeline-step-question{
      color:#f8fbff;
      font-size:15px;
      font-weight:900;
      line-height:1.4;
      letter-spacing:.01em;
      overflow-wrap:anywhere;
      word-break:break-word;
    }
    .timeline-step-why{
      border-left:3px solid rgba(125,211,252,.35);
      padding-left:10px;
      color:#dbeafe;
      font-size:12px;
      line-height:1.55;
    }
    .timeline-step-why strong{
      color:#7dd3fc;
      font-size:11px;
      letter-spacing:.08em;
      text-transform:uppercase;
      display:block;
      margin-bottom:4px;
    }
    .timeline-step-context{
      color:#9fb4cc;
      font-size:12px;
      line-height:1.5;
      overflow-wrap:anywhere;
    }
    .timeline-meta-row{
      display:flex;
      flex-wrap:wrap;
      gap:8px;
    }
    .timeline-meta-pill{
      display:inline-flex;
      align-items:center;
      gap:6px;
      border-radius:999px;
      border:1px solid #24445e;
      background:#08131f;
      color:#d9ebfc;
      padding:6px 10px;
      font-size:11px;
      line-height:1.2;
    }
    .timeline-meta-pill strong{
      color:#7dd3fc;
      font-size:10px;
      letter-spacing:.08em;
      text-transform:uppercase;
    }
    .timeline-confidence.up .timeline-meta-pill{border-color:#1f6f48;}
    .timeline-confidence.down .timeline-meta-pill{border-color:#7c4a17;}
    .timeline-step-summary{
      color:#dbeafe;
      font-size:13px;
      line-height:1.6;
    }
    .timeline-step-grid{
      display:grid;
      grid-template-columns:repeat(auto-fit,minmax(210px,1fr));
      gap:10px;
    }
    .timeline-section-card{
      border:1px solid #22384d;
      border-radius:12px;
      background:#08131f;
      padding:10px;
      display:grid;
      gap:8px;
      min-width:0;
    }
    .timeline-section-title{
      color:#9fd3ff;
      font-size:10px;
      font-weight:900;
      letter-spacing:.1em;
      text-transform:uppercase;
    }
    .timeline-section-copy{
      color:#dbeafe;
      font-size:12px;
      line-height:1.55;
      overflow-wrap:anywhere;
    }
    .timeline-section-copy.muted{color:#9fb4cc;}
    .timeline-step-actions{
      display:flex;
      flex-wrap:wrap;
      gap:8px;
    }
    .timeline-step-actions .btn-secondary,.timeline-step-actions .btn-primary,.timeline-step-actions .btn-splunk{
      margin-top:0;
      padding:6px 10px;
      font-size:11px;
    }
    .timeline-inline-spl{
      border:1px solid #22384d;
      border-radius:12px;
      background:#06111a;
      overflow:hidden;
    }
    .timeline-inline-spl summary{
      cursor:pointer;
      padding:10px 12px;
      color:#dbeafe;
      font-size:12px;
      font-weight:800;
      list-style:none;
    }
    .timeline-inline-spl summary::-webkit-details-marker{display:none;}
    .timeline-inline-spl pre{
      margin:0;
      padding:0 12px 12px;
      color:#dbeafe;
      font-size:11px;
      line-height:1.55;
      white-space:pre-wrap;
      overflow-wrap:anywhere;
      word-break:break-word;
      max-height:220px;
      overflow:auto;
      font-family:"Consolas","SFMono-Regular",Menlo,monospace;
    }
    .phase-pill-mini{
      border:1px solid #294560;
      border-radius:10px;
      background:#091423;
      padding:8px 10px;
      min-width:0;
    }
    .phase-pill-mini .phase-mini-name{
      display:block;
      color:#8fb6d9;
      font-size:10px;
      font-weight:800;
      letter-spacing:.08em;
      text-transform:uppercase;
      margin-bottom:4px;
    }
    .phase-pill-mini .phase-mini-state{
      display:block;
      color:#e5eefc;
      font-size:12px;
      font-weight:800;
      line-height:1.35;
    }
    .phase-pill-mini.complete{border-color:#166534;background:#071b12;}
    .phase-pill-mini.complete .phase-mini-state{color:#bbf7d0;}
    .phase-pill-mini.in_progress{border-color:#b45309;background:#221105;}
    .phase-pill-mini.in_progress .phase-mini-state{color:#fde68a;}
    .phase-pill-mini.planned{border-color:#1d4ed8;background:#0f1f4a;}
    .phase-pill-mini.planned .phase-mini-state{color:#bfdbfe;}
    .phase-pill-mini.blocked,.phase-pill-mini.awaiting_human_approval{border-color:#b91c1c;background:#2a0b0b;}
    .phase-pill-mini.blocked .phase-mini-state,.phase-pill-mini.awaiting_human_approval .phase-mini-state{color:#fecaca;}
    .brief-grid{
      display:grid;
      grid-template-columns:1.2fr .95fr;
      gap:12px;
      margin:12px 0 14px;
    }
    .brief-card{
      border:1px solid #244360;
      border-radius:12px;
      background:linear-gradient(180deg,#091423,#07131f);
      padding:12px;
      min-width:0;
    }
    .brief-head{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      margin-bottom:8px;
    }
    .brief-kicker{
      color:#93c5fd;
      font-size:11px;
      text-transform:uppercase;
      letter-spacing:.08em;
      font-weight:800;
    }
    .brief-body{
      color:#dbeafe;
      font-size:13px;
      line-height:1.55;
      white-space:pre-wrap;
    }
    .brief-metrics{
      display:grid;
      grid-template-columns:repeat(2,minmax(0,1fr));
      gap:8px;
    }
    .brief-strip {
      border:1px solid #244360;
      border-radius:12px;
      background:linear-gradient(180deg,#091423,#07131f);
      padding:12px;
      margin:-2px 0 14px;
    }
    .brief-strip-head {
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      margin-bottom:8px;
    }
    .brief-strip-metrics {
      display:grid;
      grid-template-columns:repeat(6,minmax(0,1fr));
      gap:8px;
    }
    .brief-metric{
      border:1px solid #203549;
      border-radius:10px;
      background:#081729;
      padding:8px 10px;
    }
    .brief-metric-label{
      color:#8fb6d9;
      font-size:10px;
      text-transform:uppercase;
      letter-spacing:.08em;
      font-weight:800;
      margin-bottom:4px;
    }
    .brief-metric-value{
      color:#f8fafc;
      font-size:13px;
      font-weight:700;
      overflow-wrap:anywhere;
    }
    .mitre-list{
      display:grid;
      gap:8px;
    }
    .mitre-card{
      --mitre-accent:#5b7f9c;
      border:1px solid color-mix(in srgb, var(--mitre-accent) 40%, #2a4056);
      border-left:3px solid color-mix(in srgb, var(--mitre-accent) 85%, #2a4056);
      border-radius:10px;
      background:linear-gradient(180deg, color-mix(in srgb, var(--mitre-accent) 10%, #081729), #081729 72%);
      padding:9px 10px;
      position:relative;
    }
    .mitre-tone-discovery{--mitre-accent:#4ea8de;}
    .mitre-tone-credential-access{--mitre-accent:#7cc48a;}
    .mitre-tone-execution{--mitre-accent:#d1a75d;}
    .mitre-tone-defense-evasion{--mitre-accent:#a88ccf;}
    .mitre-tone-collection{--mitre-accent:#73c0b8;}
    .mitre-tone-command-and-control{--mitre-accent:#cf8aa1;}
    .mitre-tone-default{--mitre-accent:#5b7f9c;}
    .mitre-head{
      display:flex;
      align-items:flex-start;
      justify-content:space-between;
      gap:10px;
      margin-bottom:4px;
    }
    .mitre-title{
      color:#f8fafc;
      font-size:13px;
      font-weight:800;
    }
    .mitre-meta{
      color:#8fb6d9;
      font-size:11px;
      font-weight:700;
      margin-bottom:4px;
    }
    .mitre-copy{
      color:#cbd5e1;
      font-size:12px;
      line-height:1.45;
    }
    .mitre-actions{
      display:flex;
      gap:8px;
      flex-wrap:wrap;
      margin-top:8px;
    }
    .mitre-pivot-btn{
      appearance:none;
      border:1px solid #315a79;
      border-radius:999px;
      padding:7px 10px;
      background:linear-gradient(180deg,#16324a,#102435);
      color:#dbeafe;
      font-size:12px;
      font-weight:800;
      cursor:pointer;
    }
    .mitre-pivot-btn:hover{
      border-color:#60a5fa;
      transform:translateY(-1px);
    }
    .mitre-tip{
      display:inline-flex;
      align-items:center;
      justify-content:center;
      width:20px;
      height:20px;
      border-radius:999px;
      border:1px solid #315a79;
      background:#0d2133;
      color:#dbeafe;
      font-size:11px;
      font-weight:900;
      cursor:help;
      flex:0 0 auto;
      position:relative;
    }
    .mitre-tip-panel{
      display:none;
      position:absolute;
      top:26px;
      right:0;
      width:min(340px, 72vw);
      z-index:20;
      border:1px solid #315a79;
      border-radius:12px;
      background:linear-gradient(180deg,#0a1627,#07111f 78%);
      padding:10px;
      box-shadow:0 18px 34px rgba(2,6,23,.34);
      text-align:left;
    }
    .mitre-tip:hover .mitre-tip-panel,
    .mitre-tip:focus-within .mitre-tip-panel{
      display:block;
    }
    .mitre-tip-line{
      color:#dbeafe;
      font-size:12px;
      line-height:1.45;
      margin-bottom:6px;
    }
    .mitre-tip-line:last-child{margin-bottom:0;}
    .case-header{
      border:1px solid #244360;
      border-radius:14px;
      background:linear-gradient(180deg,#0a1628,#08111d);
      padding:14px 16px;
    }
    .case-header-grid{
      display:block;
    }
    .case-chip-row{
      display:flex;
      flex-wrap:wrap;
      gap:8px;
      align-content:flex-start;
      justify-content:flex-start;
      margin-top:12px;
    }
    .case-chip{
      display:inline-flex;
      align-items:center;
      gap:6px;
      padding:7px 10px;
      border-radius:999px;
      border:1px solid #294560;
      background:#0a2034;
      color:#dbeafe;
      font-size:12px;
      font-weight:800;
    }
    .case-chip.readonly{
      border-color:#15803d;
      background:#082515;
      color:#bbf7d0;
    }
    .workspace-grid{
      display:grid;
      grid-template-columns:minmax(0,1.72fr) minmax(320px,.78fr);
      gap:20px;
      align-items:start;
    }
    .workspace-center,.workspace-main,.workspace-side{
      min-width:0;
      display:grid;
      gap:16px;
      align-content:start;
    }
    .workspace-center{
      grid-template-rows:auto auto;
      gap:0;
      align-self:start;
    }
    .workspace-utility-row{
      position:relative;
      min-height:74px;
    }
    .workspace-side{
      position:static;
    }
    .support-card,.timeline-card,.coverage-card,.pivot-card-shell{
      border:1px solid rgba(36,67,96,.72);
      border-radius:12px;
      background:linear-gradient(180deg,rgba(9,20,35,.94),rgba(7,19,31,.90));
      padding:14px;
      min-width:0;
    }
    .workspace-utility{
      display:grid;
      gap:0;
      position:sticky;
      top:88px;
      z-index:4;
      min-height:42px;
      padding:5px 10px;
      border-bottom:1px solid rgba(49,90,121,.68);
      background:linear-gradient(180deg,rgba(8,21,34,1),rgba(7,18,29,1));
      box-shadow:none;
    }
    .workspace-main{ padding-top:10px; }
    .utility-bar{
      display:flex;
      flex-wrap:wrap;
      gap:6px;
      align-items:center;
      padding:0;
      border:0;
      border-radius:0;
      background:transparent;
      box-shadow:none;
    }
    .utility-pill{
      display:inline-flex;
      align-items:center;
      gap:6px;
      padding:5px 9px;
      border-radius:999px;
      border:1px solid #294560;
      background:#0a2034;
      color:#dbeafe;
      font-size:11px;
      font-weight:800;
      max-width:100%;
    }
    .utility-pill strong{
      font-weight:800;
      color:#f8fafc;
    }
    .utility-pill.readonly{
      border-color:#166534;
      background:#082515;
      color:#bbf7d0;
    }
    .utility-actions{
      margin-left:auto;
      display:flex;
      flex-wrap:wrap;
      gap:8px;
    }
    .jump-links{
      display:flex;
      flex-wrap:wrap;
      gap:6px;
      align-items:center;
      padding:4px 2px 0;
      border-top:1px solid rgba(36,67,96,.48);
    }
    .jump-link{
      color:#9fd1ff;
      text-decoration:none;
      font-size:12px;
      font-weight:700;
      padding:6px 10px;
      border:1px solid #243d56;
      border-radius:999px;
      background:rgba(8,23,37,.72);
    }
    .jump-link:hover{
      color:#dbeafe;
      border-color:#325978;
    }
    @media (max-width: 1280px){
      .advanced-shell summary{
        grid-template-columns:1fr;
      }
      .advanced-summary-main{
        display:grid;
        gap:8px;
      }
      .advanced-drawer-head{
        flex-direction:column;
        align-items:flex-start;
        white-space:normal;
      }
      .advanced-drawer-copy{
        white-space:normal;
      }
      .advanced-summary-controls{
        flex-wrap:wrap;
        justify-content:flex-start;
      }
      .drawer-jump-links{
        flex-wrap:wrap;
        overflow-x:visible;
      }
    }
    #assessment-section,#timeline-section,#spl-section,#coverage-section,#pivots-section,#mitre-section,#advanced-section{
      scroll-margin-top:152px;
    }
    .support-list,.decision-support-grid{
      display:grid;
      gap:10px;
    }
    .support-item,.decision-support-item{
      border:1px solid #22384f;
      border-radius:10px;
      background:#081729;
      padding:10px;
    }
    .support-label{
      color:#8fb6d9;
      font-size:10px;
      text-transform:uppercase;
      letter-spacing:.08em;
      font-weight:800;
      margin-bottom:4px;
    }
    .support-value{
      color:#f8fafc;
      font-size:13px;
      font-weight:700;
      line-height:1.45;
      overflow-wrap:anywhere;
    }
    .support-copy{
      color:#cbd5e1;
      font-size:12px;
      line-height:1.5;
      margin-top:4px;
    }
    .read-only-panel{
      border-color:#166534;
      background:linear-gradient(180deg,#0b1f17,#08150f);
      box-shadow:0 0 0 1px rgba(34,197,94,.14);
    }
    .read-only-panel .support-value{color:#bbf7d0;}
    .timeline-list{
      display:grid;
      gap:10px;
    }
    .timeline-phase{
      border:1px solid #22384f;
      border-radius:12px;
      background:#081729;
      overflow:hidden;
    }
    .timeline-phase summary{
      list-style:none;
      cursor:pointer;
      padding:12px 14px;
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:12px;
      outline:none;
    }
    .timeline-phase summary::-webkit-details-marker{display:none;}
    .timeline-phase-main{
      display:flex;
      align-items:center;
      gap:12px;
      min-width:0;
    }
    .timeline-phase-name{
      color:#f8fafc;
      font-size:14px;
      font-weight:900;
      letter-spacing:.02em;
    }
    .timeline-phase-status{
      display:inline-flex;
      align-items:center;
      padding:4px 8px;
      border-radius:999px;
      border:1px solid #315a79;
      background:#0a2034;
      color:#dbeafe;
      font-size:11px;
      font-weight:800;
      text-transform:uppercase;
      letter-spacing:.06em;
    }
    .timeline-phase.complete .timeline-phase-status{border-color:#166534;background:#052e16;color:#bbf7d0;}
    .timeline-phase.in_progress .timeline-phase-status{border-color:#92400e;background:#3b1d08;color:#fde68a;}
    .timeline-phase.planned .timeline-phase-status{border-color:#1d4ed8;background:#0f1f4a;color:#bfdbfe;}
    .timeline-phase.awaiting_human_approval .timeline-phase-status{border-color:#7c3aed;background:#2a1148;color:#e9d5ff;}
    .timeline-phase-summary{
      color:#cbd5e1;
      font-size:12px;
      line-height:1.45;
      text-align:right;
      min-width:0;
    }
    .timeline-phase-body{
      border-top:1px solid #203549;
      padding:12px 14px 14px;
      display:grid;
      gap:10px;
    }
    .timeline-detail-grid,.coverage-grid,.pivot-meta-grid{
      display:grid;
      grid-template-columns:repeat(2,minmax(0,1fr));
      gap:10px;
    }
    .pivot-meta-grid{
      grid-template-columns:repeat(3,minmax(0,1fr));
    }
    .timeline-detail,.pivot-meta{
      border:1px solid #203549;
      border-radius:10px;
      background:#091423;
      padding:10px;
    }
    .timeline-detail-title{
      color:#8fb6d9;
      font-size:10px;
      text-transform:uppercase;
      letter-spacing:.08em;
      font-weight:800;
      margin-bottom:6px;
    }
    .timeline-detail-copy{
      color:#dbeafe;
      font-size:12px;
      line-height:1.5;
      white-space:pre-wrap;
    }
    .spl-toolbar{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      flex-wrap:wrap;
      margin-bottom:6px;
    }
    .spl-toolbar-actions{
      display:flex;
      gap:8px;
      flex-wrap:wrap;
      align-items:center;
    }
    .spl-toolbar-actions button,.spl-toolbar-actions a{
      margin-top:0;
      width:auto;
    }
    .spl-mode-tabs{
      display:flex;
      gap:8px;
      margin:10px 0;
      flex-wrap:wrap;
    }
    .spl-mode-btn{
      margin-top:0;
      width:auto !important;
      padding:8px 12px;
      border-radius:999px;
      background:linear-gradient(180deg,#16324a,#102435);
      color:#dbeafe;
      border:1px solid #315a79;
      box-shadow:none;
    }
    .spl-mode-btn.active{
      background:linear-gradient(135deg,#22c55e,#16a34a);
      border-color:#22c55e;
      color:#03230f;
    }
    .spl-summary-panel{
      border:1px solid #22384f;
      border-radius:12px;
      background:#081729;
      padding:12px;
    }
    .coverage-callout{
      border:1px solid #315a79;
      border-radius:12px;
      background:linear-gradient(180deg,#0b1b2b,#081729);
      padding:12px;
    }
    .coverage-gap{
      border-color:#92400e;
      background:linear-gradient(180deg,#221105,#1a0d04);
    }
    .coverage-pill{
      display:inline-flex;
      align-items:center;
      gap:6px;
      padding:5px 9px;
      border-radius:999px;
      border:1px solid #294560;
      background:#0a2034;
      color:#dbeafe;
      font-size:11px;
      font-weight:700;
    }
    .pivot-grid{
      display:grid;
      gap:10px;
    }
    .pivot-card{
      border:1px solid #244360;
      border-radius:12px;
      background:linear-gradient(180deg,#081729,#07131f);
      padding:12px;
      display:grid;
      gap:10px;
    }
    .pivot-card-head{
      display:flex;
      justify-content:space-between;
      gap:10px;
      align-items:flex-start;
    }
    .pivot-card-kicker{
      color:#8fb6d9;
      font-size:10px;
      text-transform:uppercase;
      letter-spacing:.08em;
      font-weight:800;
      margin-bottom:4px;
    }
    .pivot-card-title{
      color:#f8fafc;
      font-size:14px;
      font-weight:900;
      line-height:1.35;
    }
    .pivot-card-copy{
      color:#dbeafe;
      font-size:13px;
      line-height:1.55;
    }
    .pivot-meta strong{
      display:block;
      color:#8fb6d9;
      font-size:10px;
      text-transform:uppercase;
      letter-spacing:.08em;
      font-weight:800;
      margin-bottom:6px;
    }
    .pivot-meta span{
      display:block;
      color:#e5eefc;
      font-size:12px;
      line-height:1.5;
      overflow-wrap:anywhere;
    }
    .pivot-meta code{
      display:inline-block;
      padding:4px 8px;
      border-radius:8px;
      border:1px solid #315a79;
      background:#071829;
      color:#bbf7d0;
      font-family:"Consolas","SFMono-Regular",Menlo,monospace;
      font-size:12px;
      font-weight:700;
    }
    .pivot-actions{
      display:flex;
      gap:8px;
      flex-wrap:wrap;
    }
    .pivot-actions button{
      width:auto;
      margin-top:0;
    }
    @media (max-width: 900px) {
      .persona-grid { display:grid; grid-template-columns:1fr; }
      .persona{max-width:none;}
      .drawer-action-card{grid-template-columns:1fr;}
      .drawer-action-buttons{flex-direction:row;flex-wrap:wrap;}
      .persona-arrow{display:none;}
    }
    @media (max-width: 900px) { .hero-head { grid-template-columns: 1fr; } }
    @media (max-width: 1240px) { .stack { grid-template-columns: 1fr; } }
    @media (max-width: 1420px) {
      .workspace-grid{grid-template-columns:1fr;}
      .workspace-side{position:static;}
      .case-header-grid{grid-template-columns:1fr;}
      .case-chip-row{justify-content:flex-start;}
    }
    @media (max-width: 1180px) {
      .wrap { padding:0 18px 28px; }
      .invest-shell { grid-template-columns:1fr; }
      .invest-sidebar { position:static; }
      .workspace-utility { position:static; }
      .advanced-shell { left:12px; right:12px; }
      .advanced-shell[data-mode="full"]{ left:12px; }
    }
    @media (max-width: 1100px) { .ops-field.wide { grid-column: span 1; } }
    @media (max-width: 900px) { .row { grid-template-columns: 1fr 1fr; } }
    @media (max-width: 1100px) { .brief-grid { grid-template-columns:1fr; } }
    @media (max-width: 900px) { .timeline-detail-grid,.coverage-grid,.pivot-meta-grid,.brief-strip-metrics,.coverage-row { grid-template-columns:1fr; } }
    @media (max-width: 700px) { .control-grid { grid-template-columns:1fr; } }
    @media (max-width: 560px) { .row, .row-ops { grid-template-columns: 1fr; } .wrap{padding:0 12px 24px;} }
  </style>
</head>
<body>
  <div class=\"wrap\">
    <nav class=\"topnav\">
      <a class=\"nav-item\" href=\"/mcp\"><span class=\"nav-kicker\">MCP</span><span class=\"nav-label\">Splunk MCP Chat</span></a>
      <a class=\"nav-item active\" href=\"/investigation\"><span class=\"nav-kicker\">Investigate</span><span class=\"nav-label\">Investigation UI</span></a>
      <a class=\"nav-item\" href=\"/environment\"><span class=\"nav-kicker\">Profile</span><span class=\"nav-label\">Data Domains</span></a>
      <a class=\"nav-item\" href=\"/artifacts\"><span class=\"nav-kicker\">Artifacts</span><span class=\"nav-label\">Artifact Repository</span></a>
      <div class=\"nav-item nav-item-dropdown\">
        <a class=\"nav-trigger\" href=\"/configure\"><span class=\"nav-kicker\">Control</span><span class=\"nav-label\">Control Center</span></a>
        <div class=\"nav-submenu\">
          <a class=\"nav-submenu-item\" href=\"/architecture\"><span class=\"nav-submenu-title\">Architecture</span><span class=\"nav-submenu-copy\">System flow and trust boundaries</span></a>
          <a class=\"nav-submenu-item\" href=\"/docs\"><span class=\"nav-submenu-title\">Docs</span><span class=\"nav-submenu-copy\">Whitepapers, guides, and references</span></a>
          <a class=\"nav-submenu-item\" href=\"/configure\"><span class=\"nav-submenu-title\">Configuration</span><span class=\"nav-submenu-copy\">Endpoints, models, validation</span></a>
          <a class=\"nav-submenu-item\" href=\"/learning\"><span class=\"nav-submenu-title\">SPL Optimization</span><span class=\"nav-submenu-copy\">AI-driven SPL improvement and review</span></a>
          <a class=\"nav-submenu-item\" href=\"/spl-assets\"><span class=\"nav-submenu-title\">SPL Asset Repository</span><span class=\"nav-submenu-copy\">Approved reusable SPL assets</span></a>
          <a class=\"nav-submenu-item\" href=\"/users\"><span class=\"nav-submenu-title\">Users</span><span class=\"nav-submenu-copy\">Local users and audit trail</span></a>
        </div>
      </div>
      <a class=\"nav-item\" href=\"/logout\"><span class=\"nav-kicker\">Session</span><span class=\"nav-label\">Logout</span></a>
    </nav>

    <div class=\"invest-shell\" id=\"invest-layout\">
      <aside class=\"invest-sidebar\">
        <div class=\"invest-sidebar-inner\">
      <div class=\"card control-rail\" id=\"analyst-card\">
        <div class=\"hero-head\">
          <div class=\"hero-title-block\">
            <h1>Investigation Workspace</h1>
            <div class=\"muted\">Ask a bounded question, review the evidence, then decide the next move.</div>
          </div>
        </div>
        <label class=\"label-row\">Question
          <span class=\"hint\" tabindex=\"0\">?
            <span class=\"hint-pop\">Natural-language investigation request. Keep it read-only (search/analyze/explain) for this lab flow.</span>
          </span>
        </label>
        <textarea id=\"question\">Show failed login activity in the last 24 hours</textarea>
        <details class=\"domain-hints\">
          <summary class=\"hint-title\">Likely Data Domains (pre-investigation hint)</summary>
          <div id=\"domain-hints\" class=\"domain-list\">
            <div class=\"muted\">Type a question to see likely index/sourcetype targets.</div>
          </div>
        </details>
        <div id=\"selected-followup-panel\" class=\"followup-panel empty\">
          <div class=\"followup-head\">
            <div class=\"brief-kicker\">Follow-Up Drawer</div>
            <span id=\"selected-followup-badge\" class=\"badge\">Nothing selected</span>
          </div>
          <div id=\"selected-followup-text\" class=\"followup-body muted\">Select a follow-up step from Recommended Next Steps in the main investigation column to open it here. This drawer is the single place to review and run a follow-up.</div>
          <div id=\"selected-followup-meta\" class=\"followup-meta\" style=\"display:none;\"></div>
          <div class=\"followup-actions\">
            <button id=\"selected-followup-run\" class=\"btn-followup\" type=\"button\" style=\"display:none;\">Run This Follow-Up</button>
            <button id=\"selected-followup-clear\" class=\"btn-secondary\" type=\"button\" style=\"display:none;\">Clear</button>
          </div>
        </div>
        <details id=\"control-details\" class=\"control-collapsible\">
          <summary>Show Advanced Controls</summary>
          <div class=\"control-collapsible-body\">
            <div class=\"control-grid\">
              <div>
                <label class=\"label-row\">Session ID (optional)
                  <span class=\"hint\" tabindex=\"0\">?
                    <span class=\"hint-pop\">Analyst session grouping key for artifacts and run history, e.g. `night_shift_a`.</span>
                  </span>
                </label>
                <input id=\"session\" placeholder=\"analyst_shift_a\" />
              </div>
              <div>
                <label class=\"label-row\">Max Steps
                  <span class=\"hint\" tabindex=\"0\">?
                    <span class=\"hint-pop\">For Agentic Loop only: upper bound on total inner-graph steps per round. Separate loop controls allow one automatic deeper-investigation round, then require analyst approval for anything deeper.</span>
                  </span>
                </label>
                <input id=\"maxsteps\" type=\"number\" min=\"1\" max=\"8\" value=\"3\" />
              </div>
              <div>
                <label class=\"label-row\">Write Artifact
                  <span class=\"hint\" tabindex=\"0\">?
                    <span class=\"hint-pop\">When enabled, writes JSON run artifacts under `artifacts/runs/*`.</span>
                  </span>
                </label>
                <div class=\"toggle-row\">
                  <label class=\"switch\" aria-label=\"Write Artifact toggle\">
                    <input id=\"artifact\" type=\"checkbox\" />
                    <span class=\"slider\"></span>
                  </label>
                  <span id=\"artifact-label\" class=\"toggle-copy\">Off</span>
                </div>
              </div>
              <div>
                <label class=\"label-row\">Pipeline
                  <span class=\"hint\" tabindex=\"0\">?
                    <span class=\"hint-pop\">
                      <strong>Multi-Model Reviewer</strong>: planner, SPL writer, and security reviewer on every run; peer reviewer 1 and 2 only when the reviewer contests or revises the writer output.<br/><br/>
                      <strong>Agentic Loop</strong>: bounded multi-step investigation with one automatic deeper pass, then analyst approval for any further continuation.
                    </span>
                  </span>
                </label>
                <select id=\"pipeline\">
                  <option value=\"multi_model\">Multi-Model Reviewer</option>
                  <option value=\"agentic\">Agentic Loop</option>
                </select>
              </div>
            </div>
            <p id=\"pipeline-help\" class=\"muted\"></p>
          </div>
        </details>
        <button id=\"run\" type=\"button\" onclick=\"window.runInvestigationSafe && window.runInvestigationSafe(); return false;\" title=\"Execute selected investigation pipeline with current settings\">Run Investigation</button>
        <div id="run-progress-wrap" class="run-progress-wrap" style="display:none;">
          <div class="run-progress-meta">
            <span id="run-progress-label">Preparing investigation...</span>
            <span id="run-progress-pct">0%</span>
          </div>
          <div class="run-progress-track">
            <div id="run-progress-bar" class="run-progress-bar"></div>
          </div>
          <div class="run-progress-detail-row">
            <span id="run-progress-stage" class="run-progress-detail">Stage: waiting to start</span>
            <span id="run-progress-elapsed" class="run-progress-detail">Elapsed: 0s</span>
          </div>
          <div id="run-progress-note" class="run-progress-note">This panel shows whether the delay is coming from planning, Splunk retrieval, or evidence review.</div>
          <div class="run-progress-actions">
            <button id="cancel-run" type="button" class="btn-secondary" style="display:none; margin-top:0;">Cancel In Browser</button>
          </div>
        </div>
        <div class=\"control-status\">
          <div class=\"control-status-head\">
            <div class=\"brief-kicker\">Investigation Status</div>
            <span id=\"brief-supported\" class=\"badge\">Idle</span>
          </div>
          <div id=\"status\" class=\"control-status-copy\">Ready.</div>
          <div id=\"phase-strip\" class=\"phase-strip\">
            <div class=\"brief-kicker\" style=\"margin-top:8px;\">Phase Status</div>
            <div id=\"phase-strip-row\" class=\"phase-strip-row\"></div>
          </div>
        </div>
      </div>
        </div>
      </aside>
      <main class=\"invest-main\">
        <div class=\"card results-card\">
        <div class=\"results-shell\">
          <div class=\"case-header\">
            <div class=\"case-header-grid\">
              <div>
                <div class=\"brief-kicker\">Splunk Investigation Workspace</div>
                <h2>Current Investigation</h2>
                <div class=\"muted\">Splunk evidence remains the source of truth. Structured reasoning, ATT&amp;CK context, and next investigation steps are layered on top of the executed search.</div>
              </div>
            </div>
          </div>
          <div class=\"workspace-grid\">
            <div class=\"workspace-center\">
              <div class=\"workspace-utility-row\">
                <div class=\"workspace-utility\">
                  <div id=\"case-header-chips\" class=\"utility-bar\"></div>
                </div>
              </div>
              <section class=\"workspace-main\">
              <div class=\"brief-card\" id=\"assessment-section\">
                <div class=\"brief-head\"><div class=\"brief-kicker\">Current Assessment</div></div>
                <div id=\"summary\" class=\"summary-box\"></div>
              </div>
              <div class=\"timeline-card\" id=\"timeline-section\">
                <div class=\"brief-head\">
                  <div class=\"brief-kicker\">Splunk Investigation Timeline</div>
                  <span class=\"badge\">Detect &rarr; Triage &rarr; Investigate &rarr; Respond &rarr; Recover</span>
                </div>
                <div id=\"investigation-timeline\" class=\"timeline-list\"></div>
              </div>
              <div class=\"spl-card spl-section\" id=\"spl-section\">
                <div class=\"spl-toolbar\">
                  <div class=\"spl-title\">SPL Executed <span class=\"hint\" tabindex=\"0\">?<span class=\"hint-pop\">Keep Splunk visible. Review the analyst summary first, then inspect the exact SPL exactly as executed.</span></span></div>
                  <div class=\"spl-toolbar-actions\">
                    <button id=\"spl-visibility-toggle\" class=\"btn-secondary\" type=\"button\">Show SPL Executed</button>
                    <button id=\"copy-spl\" class=\"btn-secondary\" type=\"button\" style=\"display:none;\">Copy SPL</button>
                    <a id=\"spl-link\" href=\"#\" target=\"_blank\" rel=\"noopener noreferrer\" style=\"display:none; color:#93c5fd; text-decoration:none; font-size:13px;\">View in Splunk</a>
                  </div>
                </div>
                <div id=\"spl-meta-strip\" class=\"brief-strip-metrics\"></div>
                <div id=\"spl-summary-panel\" class=\"spl-summary-panel\">
                  <div id=\"spl-analyst-summary\" class=\"brief-body muted\">Run an investigation to see the search strategy, data sources queried, and what the SPL was trying to prove or disprove.</div>
                </div>
                <div id=\"spl-raw-shell\" class=\"spl-raw-shell\">
                  <div id=\"spl-raw-panel\" class=\"spl-summary-panel\">
                    <pre id=\"spl-query\"></pre>
                  </div>
                  <details class=\"spl-toggle\">
                    <summary>SPL Results (sample)</summary>
                    <div class=\"spl-toggle-body\">
                      <pre id=\"spl-results\"></pre>
                    </div>
                  </details>
                </div>
              </div>
              <div class=\"coverage-card\" id=\"coverage-section\">
                <div class=\"brief-head\"><div class=\"brief-kicker\">Splunk Coverage and Visibility</div></div>
                <div id=\"coverage-visibility\" class=\"coverage-grid\"></div>
              </div>
              <div class=\"pivot-card-shell\" id=\"pivots-section\">
                <div class=\"brief-head\"><div class=\"brief-kicker\">Recommended Next Steps</div></div>
                <div id=\"pivot-cards\" class=\"pivot-grid\"></div>
              </div>
              </section>
            </div>
            <aside class=\"workspace-side\">
              <div class=\"support-card\" id=\"mitre-section\">
                <div class=\"brief-head\"><div class=\"brief-kicker\">MITRE ATT&CK</div></div>
                <div id=\"brief-mitre\" class=\"mitre-list\"><div class=\"brief-body muted\">No investigation mapping yet.</div></div>
              </div>
              <div class=\"support-card\">
                <div class=\"brief-head\"><div class=\"brief-kicker\">Decision Support</div></div>
                <div id=\"decision-support-summary\" class=\"decision-support-grid\"></div>
              </div>
            </aside>
          </div>
          <details class=\"advanced-shell\" id=\"advanced-section\">
            <summary>
              <div class=\"advanced-summary-main\">
                <div class=\"advanced-drawer-head\">
                  <div class=\"advanced-drawer-title-row\">
                    <span>Investigation Drawer</span>
                    <span id=\"drawer-update-indicator\" class=\"drawer-update-indicator\"><span class=\"drawer-update-dot\"></span><span id=\"drawer-update-text\">New drawer content</span></span>
                  </div>
                  <span class=\"advanced-drawer-copy\">Pivot back into Splunk, inspect supporting evidence, or reopen earlier steps in this investigation path.</span>
                </div>
                <div class=\"advanced-summary-controls\">
                  <div class=\"drawer-jump-links\">
                    <button class=\"jump-link\" type=\"button\" data-tray-tab=\"case\">Investigation Timeline</button>
                    <button class=\"jump-link active\" type=\"button\" data-tray-tab=\"pivot\">Pivot</button>
                    <button class=\"jump-link\" type=\"button\" data-tray-tab=\"evidence\">Evidence</button>
                    <button class=\"jump-link\" type=\"button\" data-tray-tab=\"spl\">SPL</button>
                    <button class=\"jump-link\" type=\"button\" data-tray-tab=\"timeline\">Process</button>
                    <button class=\"jump-link\" type=\"button\" data-tray-tab=\"attack\">ATT&amp;CK</button>
                    <button class=\"jump-link\" type=\"button\" data-tray-tab=\"review\">Decision Trace</button>
                    <button class=\"jump-link\" type=\"button\" data-tray-tab=\"json\">JSON</button>
                  </div>
                  <a id=\"drawer-spl-link\" class=\"btn-splunk drawer-spl-toggle\" href=\"#\" target=\"_blank\" rel=\"noopener noreferrer\" style=\"display:none;text-decoration:none;align-items:center;justify-content:center;\">Open In Splunk</a>
                </div>
              </div>
              <div class=\"advanced-drawer-actions\">
                <button id=\"advanced-full-toggle\" class=\"advanced-drawer-expand\" type=\"button\" title=\"Expand the drawer into full review mode\" aria-label=\"Toggle full review mode\">⤢</button>
                <span class=\"advanced-drawer-toggle\">⌃</span>
              </div>
            </summary>
            <div class=\"advanced-body\">
              <div id=\"drawer-investigation-narrative\" class=\"drawer-narrative-shell\"></div>
              <div class=\"advanced-panel\" data-tray-panel=\"case\">
                <div class=\"advanced-subhead\">Investigation Timeline</div>
                <div class=\"drawer-clone-grid\">
                  <div class=\"drawer-clone-card\">
                    <div style=\"display:flex;align-items:center;justify-content:space-between;gap:10px;\">
                      <div class=\"drawer-clone-title\">Current Investigation Timeline</div>
                      <div style=\"display:flex;align-items:center;gap:8px;\">
                        <a id=\"case-workspace-link\" class=\"btn-secondary\" href=\"/cases\" style=\"margin-top:0;padding:6px 10px;\">Open Cases</a>
                        <button id=\"case-latest-btn\" class=\"btn-secondary\" type=\"button\" style=\"display:none;margin-top:0;padding:6px 10px;\">Return To Latest</button>
                        <span id=\"case-badge\" class=\"badge\">New</span>
                      </div>
                    </div>
                    <div id=\"case-summary\" class=\"drawer-clone-copy\" style=\"margin-top:8px;\">Start an investigation to create a saved investigation timeline. The original finding and each deeper pivot will be tracked here so you can reopen earlier steps without rerunning them.</div>
                    <div id=\"case-pattern-strip\" class=\"timeline-pattern-strip\"></div>
                    <div id=\"case-entity-strip\" class=\"timeline-entity-strip\"></div>
                    <div id=\"case-decision-block\" class=\"timeline-decision-block\"></div>
                    <div id=\"case-filter-bar\" class=\"timeline-filter-bar\">
                      <button type=\"button\" class=\"timeline-filter-chip active\" data-case-filter=\"all\">All Steps</button>
                      <button type=\"button\" class=\"timeline-filter-chip\" data-case-filter=\"pivots\">Pivots</button>
                      <button type=\"button\" class=\"timeline-filter-chip\" data-case-filter=\"no_results\">No Results</button>
                    </div>
                    <div id=\"case-active-filter\" class=\"timeline-active-filter\" style=\"display:none;\"></div>
                  </div>
                  <div class=\"drawer-clone-card\">
                    <div class=\"drawer-clone-title\">Timeline Steps</div>
                    <div id=\"case-timeline-list\" class=\"case-timeline-list\"></div>
                  </div>
                </div>
              </div>
              <div class=\"advanced-panel active\" data-tray-panel=\"pivot\">
                <div class=\"advanced-subhead\">Pivot | Recommended Next Steps</div>
                <div id=\"drawer-pivot-content\" class=\"drawer-clone-grid\"><div class=\"drawer-clone-card\"><div class=\"drawer-clone-copy\">Recommended next steps will appear here after Splunk evidence is returned and reviewed.</div></div></div>
              </div>
              <div class=\"advanced-panel\" data-tray-panel=\"evidence\">
                <div class=\"advanced-subhead\">Evidence Review</div>
                <div class=\"drawer-clone-grid\">
                  <div class=\"drawer-clone-card\"><div class=\"drawer-clone-title\">Current Assessment</div><div id=\"drawer-evidence-summary\" class=\"drawer-clone-copy\">Run an investigation to see the current assessment here.</div></div>
                  <div class=\"drawer-clone-card\"><div class=\"drawer-clone-title\">Coverage And Visibility</div><div id=\"drawer-evidence-coverage\" class=\"drawer-clone-copy\">Coverage detail will appear here after Splunk evidence is returned.</div></div>
                </div>
              </div>
              <div class=\"advanced-panel\" data-tray-panel=\"spl\">
                <div class=\"advanced-subhead\">Executed SPL</div>
                <div class=\"drawer-clone-grid\">
                  <div class=\"drawer-clone-card\"><div class=\"drawer-clone-title\">Search Intent</div><div id=\"drawer-spl-summary\" class=\"drawer-clone-copy\">Run an investigation to see the search intent and evidence strategy.</div></div>
                  <div class=\"drawer-clone-card\"><div style=\"display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:6px;\"><div class=\"drawer-clone-title\" style=\"margin-bottom:0;\">Executed Query</div><a id=\"drawer-spl-inline-link\" class=\"btn-splunk drawer-spl-toggle\" href=\"#\" target=\"_blank\" rel=\"noopener noreferrer\" style=\"display:none;text-decoration:none;align-items:center;justify-content:center;\">Open In Splunk</a></div><pre id=\"drawer-spl-query\" class=\"drawer-spl-pre\">(No Splunk query captured yet)</pre></div>
                  <div class=\"drawer-clone-card\"><div class=\"drawer-clone-title\">Sample Results</div><pre id=\"drawer-spl-results\" class=\"drawer-spl-pre\">(No SPL result rows captured yet)</pre></div>
                </div>
              </div>
              <div class=\"advanced-panel\" data-tray-panel=\"timeline\">
                <div class=\"advanced-subhead\">Investigation Process Flow</div>
                <div id=\"drawer-timeline-content\" class=\"drawer-clone-grid\"><div class=\"drawer-clone-card\"><div class=\"drawer-clone-copy\">Timeline detail will appear here after the investigation progresses.</div></div></div>
                <div id=\"tdir-card\" class=\"tdir-card\" style=\"display:none;\">
                  <div id=\"tdir-head\" class=\"tdir-head\"></div>
                  <div id=\"tdir-meta\" class=\"tdir-meta\"></div>
                </div>
                <div id=\"tdir-case\" class=\"tdir-body\"></div>
                <div id=\"workflow-track\" class=\"flow-track\"></div>
                <div id=\"workflow-meta\" class=\"flow-meta\"></div>
              </div>
              <div class=\"advanced-panel\" data-tray-panel=\"attack\">
                <div class=\"advanced-subhead\">MITRE ATT&amp;CK</div>
                <div id=\"drawer-mitre-content\" class=\"drawer-clone-grid\"><div class=\"drawer-clone-card\"><div class=\"drawer-clone-copy\">ATT&amp;CK context will appear after evidence review completes.</div></div></div>
              </div>
              <div class=\"advanced-panel\" data-tray-panel=\"review\">
                <div class=\"advanced-subhead\">Decision Trace</div>
                <div id=\"model-personas\" class=\"persona-grid\"></div>
                <div class=\"advanced-panel\" style=\"margin-top:10px;\">
                  <div class=\"advanced-subhead\">Execution Audit</div>
                  <div id=\"model-decisions\" class=\"decision-log\"></div>
                </div>
                <div class=\"advanced-panel\" style=\"margin-top:10px;\">
                  <div class=\"advanced-subhead\">Advanced Review Trace</div>
                  <pre id=\"journey\"></pre>
                  <div id=\"continue-shell\" class=\"continue-shell\" style=\"display:none;\">
                    <div class=\"continue-title\">Deeper Investigation Control <span class=\"hint\" tabindex=\"0\">?<span class=\"hint-pop\">Shows the bounded continuation state: one automatic deeper-investigation round is allowed when justified, then further continuation requires analyst approval. Duplicate pivots and low-confidence follow-ups are blocked.</span></span></div>
                    <div id=\"continue-copy\" class=\"continue-copy\"></div>
                    <div class=\"continue-actions\">
                      <span id=\"continue-pill\" class=\"continue-pill\"></span>
                      <button id=\"continue-btn\" class=\"btn-secondary\" style=\"display:none; margin-top:0;\">Run Deeper Investigation</button>
                    </div>
                  </div>
                </div>
              </div>
              <div class=\"advanced-panel\" data-tray-panel=\"json\">
                <div class=\"advanced-subhead\">Raw Result JSON</div>
                <div style=\"display:flex;justify-content:flex-end;margin-bottom:8px;\"><button id=\"drawer-json-toggle\" class=\"btn-secondary drawer-spl-toggle\" type=\"button\">Hide JSON</button></div>
                <pre id=\"output\"></pre>
              </div>
            </div>
          </details>
        </div>
      </div>
      </main>
    </div>
  </div>
  <script>
    window.runInvestigationSafe = async function () {
      if (typeof window.executeInvestigation === 'function') {
        return window.executeInvestigation({});
      }
      const byId = (id) => document.getElementById(id);
      const questionEl = byId('question');
      const sessionEl = byId('session');
      const maxStepsEl = byId('maxsteps');
      const artifactEl = byId('artifact');
      const pipelineEl = byId('pipeline');
      const statusEl = byId('status');
      const outputEl = byId('output');
      const summaryEl = byId('summary');
      const supportedEl = byId('brief-supported');
      const runBtnEl = byId('run');
      if (!questionEl || !statusEl || !runBtnEl) {
        return false;
      }
      try {
        runBtnEl.disabled = true;
        statusEl.textContent = 'Running...';
        if (supportedEl) supportedEl.textContent = 'Running';
        const payload = {
          question: questionEl.value || '',
          session_id: sessionEl ? sessionEl.value : '',
          max_steps: maxStepsEl ? Number(maxStepsEl.value || 3) : 3,
          write_artifact: artifactEl ? Boolean(artifactEl.checked) : false,
          pipeline: pipelineEl ? pipelineEl.value : 'multi_model',
        };
        runAbortController = new AbortController();
        const resp = await fetch('/api/ask', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await resp.json();
        if (!resp.ok) {
          statusEl.textContent = 'Error';
          if (supportedEl) supportedEl.textContent = 'Error';
          if (outputEl) outputEl.textContent = JSON.stringify(data, null, 2);
          return false;
        }
        statusEl.textContent = 'Complete';
        if (supportedEl) supportedEl.textContent = data?.result?.supported === false ? 'Blocked' : 'Supported';
        if (summaryEl) summaryEl.textContent = String(data?.result?.summary || '');
        if (outputEl) outputEl.textContent = JSON.stringify(data, null, 2);
        return true;
      } catch (err) {
        statusEl.textContent = 'Request failed';
        if (supportedEl) supportedEl.textContent = 'Error';
        if (outputEl) outputEl.textContent = String(err);
        return false;
      } finally {
        runBtnEl.disabled = false;
      }
    };
  </script>
  <script>
    const $ = (id) => document.getElementById(id);
    const runBtn = $('run');
    const continueBtn = $('continue-btn');
    const cancelRunBtn = $('cancel-run');
    const drawerJsonToggleBtn = $('drawer-json-toggle');
    let runProgressTimer = null;
    let runProgressValue = 0;
    let runStartAt = 0;
    let runAbortController = null;
    let lastAskResult = null;
    let pendingContinuationState = null;
    let selectedFollowup = null;
    let latestCaseRef = null;
    let inspectingSavedNode = false;
    let activeTrayTab = 'pivot';
    let activeTimelineEntityFilter = '';
    let activeTimelineStepFilter = 'all';
    let drawerHasUnread = false;
    let drawerUnreadTab = '';
    const trayModeStorageKey = 'agtsmith_investigation_tray_mode';
    const trayTabStorageKey = 'agtsmith_investigation_tray_tab';

    const esc = (v) => String(v ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');

    function fmtValue(v) {
      if (v === null || v === undefined) return '';
      if (Array.isArray(v)) {
        return v.map((item) => {
          if (item && typeof item === 'object') {
            try { return JSON.stringify(item); } catch (_e) { return String(item); }
          }
          return String(item ?? '');
        }).join('; ');
      }
      if (typeof v === 'object') {
        try { return JSON.stringify(v); } catch (_e) { return String(v); }
      }
      return String(v);
    }

    function compactValue(v) {
      if (v === null || v === undefined) return '';
      if (Array.isArray(v)) {
        return v.map((item) => compactValue(item)).filter(Boolean).slice(0, 2).join(' | ');
      }
      if (typeof v === 'object') {
        const action = String(v.action || '').trim();
        const description = String(v.description || '').trim();
        const indicator = String(v.indicator || '').trim();
        const reason = String(v.reason || '').trim();
        if (description) return action ? `${action}: ${description}` : description;
        if (indicator) return indicator;
        if (reason) return reason;
        try { return JSON.stringify(v); } catch (_e) { return String(v); }
      }
      return String(v);
    }

    function updatePipelineHelp() {
      const v = $('pipeline')?.value || 'multi_model';
      if (v === 'agentic') {
        $('pipeline-help').textContent =
          'Agentic Loop: allows one automatic deeper-investigation pass, then requires analyst approval for any further continuation.';
      } else {
        $('pipeline-help').textContent =
          'Multi-Model Reviewer: planner -> SPL writer -> security reviewer -> optional peer review -> deterministic gate -> tool execution.';
      }
    }

    function updateArtifactLabel() {
      $('artifact-label').textContent = $('artifact').checked ? 'On' : 'Off';
    }

    function renderSelectedFollowup() {
      const panel = $('selected-followup-panel');
      const badge = $('selected-followup-badge');
      const text = $('selected-followup-text');
      const meta = $('selected-followup-meta');
      const runBtn = $('selected-followup-run');
      const clearBtn = $('selected-followup-clear');
      if (!selectedFollowup || !String(selectedFollowup.text || '').trim()) {
        panel.classList.add('empty');
        badge.textContent = 'Nothing selected';
        text.className = 'followup-body muted';
        text.textContent = 'Select a follow-up step from Recommended Next Steps in the main investigation column to open it here. This drawer is the single place to review and run a follow-up.';
        meta.style.display = 'none';
        meta.textContent = '';
        runBtn.style.display = 'none';
        clearBtn.style.display = 'none';
        return;
      }
      panel.classList.remove('empty');
      const metaView = pivotPresentation(selectedFollowup.candidate || selectedFollowup);
      badge.textContent = `Pivot ${selectedFollowup.index + 1}`;
      text.className = 'followup-body';
      text.textContent = selectedFollowup.text;
      meta.style.display = 'block';
      meta.innerHTML = `${selectedFollowup.origin ? `From ATT&CK: ${esc(selectedFollowup.origin)}` : 'Structured follow-up from the previous investigation'}<br><strong>Target:</strong> <code>${esc(metaView.targetDisplay)}</code>${metaView.provenanceText ? `<br><strong>Why this value:</strong> ${esc(metaView.provenanceText)}` : ''}`;
      runBtn.style.display = 'inline-flex';
      clearBtn.style.display = 'inline-flex';
    }

    async function loadCaseNode(caseId, nodeId) {
      const cid = String(caseId || '').trim();
      const nid = String(nodeId || '').trim();
      if (!cid || !nid) return;
      $('status').textContent = 'Loading saved case node...';
      try {
        const resp = await fetch(`/api/case-node?case_id=${encodeURIComponent(cid)}&node_id=${encodeURIComponent(nid)}`);
        const data = await resp.json();
        if (!resp.ok) throw new Error(String(data?.error || 'Unable to load case node'));
        const result = data?.result && typeof data.result === 'object' ? data.result : {};
        try {
          const caseResp = await fetch(`/api/case?case_id=${encodeURIComponent(cid)}`);
          const caseData = await caseResp.json();
          const caseRecord = caseData?.case && typeof caseData.case === 'object' ? caseData.case : null;
          if (caseResp.ok && caseRecord) {
            result.case_context = Object.assign({}, result.case_context || {}, {
              case_id: caseRecord.case_id || cid,
              root_question: caseRecord.root_question || result.case_context?.root_question || '',
              timeline: Array.isArray(caseRecord.timeline) ? caseRecord.timeline : [],
              node_id: nid,
            });
          }
        } catch (_caseErr) {}
        if (result?.pivot_context && typeof result.pivot_context === 'object') {
          result.pivot_context.case_id = String(result?.case_context?.case_id || cid || result.pivot_context.case_id || '').trim();
          result.pivot_context.current_node_id = String(result?.case_context?.node_id || nid || result.pivot_context.current_node_id || '').trim();
          if (result?.graph_case_state && typeof result.graph_case_state === 'object') {
            result.pivot_context.graph_case_state = result.graph_case_state;
          }
        }
        inspectingSavedNode = true;
        lastAskResult = result;
        if (Array.isArray(result?.sample_rows)) result.__ui_sample_rows = result.sample_rows;
        $('question').value = String(result?.active_question || result?.question || $('question').value || '');
        if (hasEvidenceRows(result)) {
          $('summary').innerHTML = renderSummaryText(result?.summary || '');
          renderModelDecisions(result);
          renderTDIRCase(result);
          renderInvestigationJourney(result);
          renderWorkflowTimeline(result);
          renderContinuationControls(result);
        } else {
          renderNoEvidenceOutcome(result);
          clearContinuationControls();
        }
        $('status').textContent = 'Loaded saved case node without rerunning the search.';
      } catch (err) {
        $('status').textContent = `Unable to load saved case node: ${String(err?.message || err)}`;
      }
    }

    function timelineOrdinalLabel(index) {
      const n = Number(index || 0);
      if (n <= 0) return 'Original';
      const labels = ['First Pivot', 'Second Pivot', 'Third Pivot', 'Fourth Pivot', 'Fifth Pivot'];
      return labels[n - 1] || `Pivot ${n}`;
    }

    function timelineCleanSummary(text) {
      const raw = String(text || '')
        .replaceAll('**', '')
        .replace(/^\\s*-\\s*/gm, '')
        .replace(/\\s+/g, ' ')
        .trim();
      if (!raw) return '';
      const firstSentence = raw.split(/(?<=[.!?])\\s+/)[0] || raw;
      return firstSentence.length > 220 ? `${firstSentence.slice(0, 217).trim()}...` : firstSentence;
    }

    function timelineFmtStamp(ts) {
      const raw = Number(ts || 0);
      if (!raw) return '';
      return new Date(raw * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
    }

    function timelineElapsedText(node, previousNode) {
      const now = Number(node?.created_at || 0);
      const before = Number(previousNode?.created_at || 0);
      if (!now || !before || now <= before) return '';
      const delta = now - before;
      const mins = Math.floor(delta / 60);
      const secs = delta % 60;
      if (mins <= 0) return `+${secs}s after the previous step`;
      return `+${mins}m ${secs}s after the previous step`;
    }

    function timelineHumanIntent(intent) {
      const raw = String(intent || '').trim();
      if (!raw) return 'General Investigation';
      const known = {
        failed_login_activity: 'Credential Access Validation',
        linux_auth_failures: 'Linux Authentication Follow-up',
        apache_access_top_ips: 'Web Access Triage',
        aws_cloudtrail_activity: 'Cloud API Activity Review',
      };
      if (known[raw]) return known[raw];
      return raw.split('_').map((part) => part ? `${part.charAt(0).toUpperCase()}${part.slice(1)}` : '').join(' ');
    }

    function timelinePatternLabel(timeline) {
      const root = timeline[0] || {};
      const latest = timeline[timeline.length - 1] || root;
      const pivotKind = String((latest?.pivot_source || {}).target_type || '');
      if (String(root?.intent || '') === 'failed_login_activity' && pivotKind === 'source_ip') {
        return 'Failed Authentication → Success Check';
      }
      if (String(root?.intent || '') === 'apache_access_top_ips') {
        return 'Top Client IPs → URI / User-Agent Drilldown';
      }
      return latest?.depth > 0 ? 'Root Finding → Follow-up Pivot' : 'Single-Step Investigation';
    }

    function timelineStatusMeta(node, currentNodeId, latestNodeId) {
      const isCurrent = String(node?.node_id || '') === String(currentNodeId || '');
      const isLatest = String(node?.node_id || '') === String(latestNodeId || '');
      if (isCurrent && !isLatest) return { label: 'Restored', className: 'status-restored' };
      if (isCurrent) return { label: 'Current', className: 'status-current' };
      if (node?.supported === false) return { label: 'Blocked', className: 'status-no-results' };
      if (Number(node?.row_count || 0) <= 0) return { label: 'No Results', className: 'status-no-results' };
      if (!isLatest) return { label: 'Superseded', className: 'status-superseded' };
      return { label: 'Complete', className: '' };
    }

    function timelineStepType(node) {
      const depth = Number(node?.depth || 0);
      const pivotKind = String((node?.pivot_source || {}).kind || '');
      const title = String(node?.title || node?.question || '').toLowerCase();
      if (depth <= 0) return 'Initial Query';
      if (pivotKind === 'structured_pivot') return 'Pivot';
      if (title.includes('validate') || title.includes('check for successful')) return 'Validation';
      if (title.includes('narrow') || title.includes('focus')) return 'Scope Narrowing';
      return 'Follow Up';
    }

    function timelineWhyThisStep(node, previousNode) {
      if (!previousNode) return 'Establish the original evidence set for the analyst question.';
      const pivot = node?.pivot_source || {};
      const pivotKind = String(pivot?.title || '').toLowerCase();
      if (pivotKind.includes('successful logons')) return 'Validate whether the failed authentication activity led to successful compromise.';
      if (pivotKind.includes('username')) return 'Carry forward the most important usernames to test for broader credential guessing or reuse.';
      if (pivotKind.includes('privilege')) return 'Test whether the activity escalated beyond failed logons into higher-risk privileged behavior.';
      const provenance = String((pivot?.provenance || {}).explanation || '').trim();
      return provenance || 'Narrow the scope using entities discovered in the prior step.';
    }

    function timelineTimeRangeLabel(node) {
      const range = node?.time_range && typeof node.time_range === 'object' ? node.time_range : {};
      const earliest = String(range.earliest || '').trim();
      const latest = String(range.latest || '').trim();
      if (!earliest && !latest) return 'Not saved';
      return `${earliest || 'default'} → ${latest || 'now'}`;
    }

    function timelineConfidenceDelta(node, previousNode) {
      const current = Number(node?.confidence);
      const previous = previousNode?.confidence;
      if (!Number.isFinite(current)) return { text: 'Not scored', className: '' };
      if (!Number.isFinite(previous)) return { text: `${current.toFixed(2)}`, className: '' };
      const delta = current - Number(previous);
      if (Math.abs(delta) < 0.005) return { text: `${Number(previous).toFixed(2)} → ${current.toFixed(2)}`, className: '' };
      return {
        text: `${Number(previous).toFixed(2)} → ${current.toFixed(2)}`,
        className: delta > 0 ? 'up' : 'down',
      };
    }

    function timelineCollectEntityRefs(node) {
      const entities = node?.evidence_entities && typeof node.evidence_entities === 'object' ? node.evidence_entities : {};
      const refs = [];
      Object.values(entities).forEach((arr) => {
        if (Array.isArray(arr)) arr.forEach((value) => refs.push(String(value || '').trim().toLowerCase()));
      });
      const pivotVals = Array.isArray(node?.pivot_source?.target_values) ? node.pivot_source.target_values : [];
      pivotVals.forEach((value) => refs.push(String(value || '').trim().toLowerCase()));
      return Array.from(new Set(refs.filter(Boolean)));
    }

    function timelineEntityStepCounts(timeline) {
      const counts = new Map();
      (Array.isArray(timeline) ? timeline : []).forEach((node) => {
        timelineCollectEntityRefs(node).forEach((value) => counts.set(value, (counts.get(value) || 0) + 1));
      });
      return counts;
    }

    function renderEntityPills(values, counts, opts = {}) {
      const items = Array.isArray(values) ? values.filter(Boolean) : [];
      if (!items.length) return '<div class="timeline-section-copy muted">None carried forward.</div>';
      return items.map((value) => {
        const raw = String(value || '').trim();
        const key = raw.toLowerCase();
        const isActive = activeTimelineEntityFilter && key === activeTimelineEntityFilter;
        const count = counts instanceof Map ? Number(counts.get(key) || 0) : 0;
        return `<button type="button" class="entity-pill ${isActive ? 'active' : ''}" data-entity-value="${esc(key)}" data-entity-label="${esc(raw)}"><strong>${esc(opts.label || 'Entity')}</strong><span>${esc(raw)}</span>${count > 0 ? `<span class="entity-count">${esc(String(count))} step${count === 1 ? '' : 's'}</span>` : ''}</button>`;
      }).join('');
    }

    function timelineDifference(currentValues, previousValues) {
      const prev = new Set((Array.isArray(previousValues) ? previousValues : []).map((value) => String(value || '').trim().toLowerCase()));
      return (Array.isArray(currentValues) ? currentValues : []).filter((value) => !prev.has(String(value || '').trim().toLowerCase()));
    }

    function timelineSharedStatePreview(node) {
      const preview = node?.state_preview && typeof node.state_preview === 'object' ? node.state_preview : {};
      const chips = [];
      chips.push(`<span class="timeline-meta-pill"><strong>Intent</strong><span>${esc(timelineHumanIntent(node?.intent || ''))}</span></span>`);
      chips.push(`<span class="timeline-meta-pill"><strong>Rows</strong><span>${esc(String(Number(node?.row_count || 0)))}</span></span>`);
      chips.push(`<span class="timeline-meta-pill"><strong>Tool</strong><span>${esc(String(node?.selected_tool || 'not saved'))}</span></span>`);
      if (Number(preview.pivot_candidate_count || 0) > 0) chips.push(`<span class="timeline-meta-pill"><strong>Pivots</strong><span>${esc(String(preview.pivot_candidate_count))}</span></span>`);
      if (Number(preview.matching_active_spl_assets || 0) > 0) chips.push(`<span class="timeline-meta-pill"><strong>Assets</strong><span>${esc(String(preview.matching_active_spl_assets))}</span></span>`);
      return chips.join('');
    }

    function timelineSectionCard(title, body) {
      return `<div class="timeline-section-card"><div class="timeline-section-title">${esc(title)}</div>${body}</div>`;
    }

    function timelinePrimaryEntityValues(node, previousNode) {
      const pivotSourceValues = Array.isArray(node?.pivot_source?.target_values) ? node.pivot_source.target_values : [];
      if (pivotSourceValues.length) return pivotSourceValues.slice(0, 4);
      const ranked = node?.ranked_entities && typeof node.ranked_entities === 'object' ? node.ranked_entities : {};
      const fromRanked = ['source_ips', 'users', 'hosts', 'client_ips'].map((key) => Array.isArray(ranked[key]) ? ranked[key].map((item) => item.value) : []).find((arr) => arr && arr.length);
      if (fromRanked && fromRanked.length) return fromRanked.slice(0, 4);
      if (previousNode && Array.isArray(previousNode?.pivot_source?.target_values) && previousNode.pivot_source.target_values.length) return previousNode.pivot_source.target_values.slice(0, 4);
      return [];
    }

    function timelineMissingSummary(node) {
      if (node?.supported === false) return 'guarded execution approval';
      if (Number(node?.row_count || 0) > 0) return '';
      const pivotLabel = String(node?.pivot_source?.target_label || '').trim();
      if (pivotLabel) return `matching evidence for ${pivotLabel.toLowerCase()} values`;
      return 'matching evidence';
    }

    function timelineInterpretation(node) {
      if (node?.supported === false) return 'The hypothesis could not be tested because the guarded path did not pass validation.';
      if (Number(node?.row_count || 0) <= 0 && Number(node?.depth || 0) > 0) return 'The child pivot executed correctly, but the hypothesis was not supported by returned evidence.';
      if (Number(node?.row_count || 0) <= 0) return 'No evidence matched the initial search scope in this time range.';
      return timelineCleanSummary(node?.saved_summary || node?.summary || 'Evidence was returned for this step.');
    }

    function timelineNarrativeModel(timeline) {
      const root = Array.isArray(timeline) && timeline.length ? timeline[0] : null;
      const latest = Array.isArray(timeline) && timeline.length ? timeline[timeline.length - 1] : null;
      if (!root || !latest) {
        return {
          lines: ['Run an investigation to create a saved reasoning path.', 'Each original finding and pivot will be preserved here.', 'Use the drawer to reopen prior evidence without rerunning Splunk.'],
          investigationType: 'Investigation Memory',
          pattern: 'Awaiting first case',
          recommendations: [],
          disposition: 'Not started',
        };
      }
      const rootIps = timelinePrimaryEntityValues(root).slice(0, 3);
      const lines = [];
      if (String(root.intent || '') === 'failed_login_activity' && rootIps.length) {
        lines.push(`Failed login activity returned ${Number(root.row_count || 0)} row(s) and surfaced ${rootIps.length} high-priority source IP${rootIps.length === 1 ? '' : 's'}.`);
      } else {
        lines.push(`${timelineHumanIntent(root.intent)} returned ${Number(root.row_count || 0)} row(s) in the original step.`);
      }
      if (Number(latest.depth || 0) > 0 && Array.isArray(latest?.pivot_source?.target_values) && latest.pivot_source.target_values.length) {
        lines.push(`A child pivot checked ${latest.pivot_source.target_values.length} carried-forward ${String(latest.pivot_source.target_label || 'entity').toLowerCase()} value(s) discovered earlier.`);
      } else if (Number(latest.depth || 0) > 0) {
        lines.push('A child pivot narrowed the scope using evidence discovered in the previous step.');
      }
      if (Number(latest.row_count || 0) <= 0 && Number(latest.depth || 0) > 0) {
        lines.push('No matching evidence was found in the pivot step, which weakens the compromise hypothesis so far.');
      } else if (Number(latest.row_count || 0) > 0 && Number(latest.depth || 0) > 0) {
        lines.push(`The pivot added ${Number(latest.row_count || 0)} matching row(s), extending the evidence set beyond the original finding.`);
      } else if (Number(root.row_count || 0) > 0) {
        lines.push('The original finding is ready for a targeted follow-up pivot or scope change.');
      }
      const recommendations = [];
      if (String(root.intent || '') === 'failed_login_activity' && Number(latest.row_count || 0) <= 0 && Number(latest.depth || 0) > 0) {
        recommendations.push('Consider checking usernames discovered earlier.');
        recommendations.push('Consider expanding the time range.');
        recommendations.push('Consider additional authentication sources.');
      } else if (Number(latest.row_count || 0) > 0) {
        recommendations.push('Pivot on the strongest returned entity.');
        recommendations.push('Validate the finding in Splunk.');
      } else {
        recommendations.push('Review source coverage before pivoting further.');
      }
      return {
        lines: lines.slice(0, 3),
        investigationType: timelineHumanIntent(root.intent),
        pattern: timelinePatternLabel(timeline),
        recommendations,
        disposition: Number(latest.row_count || 0) <= 0 && Number(latest.depth || 0) > 0 ? 'Suspicious but unconfirmed' : (Number(latest.row_count || 0) > 0 ? 'Evidence present' : 'Awaiting evidence'),
      };
    }

    function timelineCardHtml(node, opts) {
      const currentNodeId = String(opts.currentNodeId || '');
      const latestNodeId = String(opts.latestNodeId || '');
      const caseId = String(opts.caseId || '');
      const counts = opts.entityCounts instanceof Map ? opts.entityCounts : new Map();
      const stepIndex = Number(opts.stepIndex || 0);
      const previousNode = opts.previousNode || null;
      const parentNode = opts.parentNode || null;
      const kind = timelineOrdinalLabel(stepIndex);
      const stepType = timelineStepType(node);
      const status = timelineStatusMeta(node, currentNodeId, latestNodeId);
      const confidence = timelineConfidenceDelta(node, parentNode || previousNode);
      const carriedForward = timelinePrimaryEntityValues(parentNode || previousNode || node, parentNode || previousNode).slice(0, 4);
      const currentPrimary = timelinePrimaryEntityValues(node, parentNode || previousNode).slice(0, 4);
      const newEntities = timelineDifference(currentPrimary, carriedForward).slice(0, 4);
      const missingSummary = timelineMissingSummary(node);
      const previewTitle = String(node?.active_question || node?.title || node?.question || kind);
      const parentLabel = parentNode ? timelineOrdinalLabel(Number(opts.parentIndex || 0)) : '';
      const relationship = parentNode
        ? `Built from ${parentLabel}${timelineElapsedText(node, previousNode) ? ` · ${timelineElapsedText(node, previousNode)}` : ''}`
        : 'Starting point for this investigation';
      const refs = timelineCollectEntityRefs(node).join('|');
      const quickPivotTypes = Array.isArray(node?.pivot_candidates) ? node.pivot_candidates.map((item) => String(item?.target_type || '')) : [];
      const query = String(node?.query || '').trim();
      const noResults = Number(node?.row_count || 0) <= 0;
      const classes = ['timeline-step-card', String(node?.node_id || '') === currentNodeId ? 'current' : '', status.label === 'Restored' ? 'restored' : '', noResults ? 'no-results' : ''].filter(Boolean).join(' ');
      return `
        <article class="${classes}" data-node-id="${esc(String(node?.node_id || ''))}" data-case-id="${esc(caseId)}" data-step-kind="${esc(stepType.toLowerCase().replace(/\\s+/g, '_'))}" data-entity-refs="${esc(refs)}" data-depth="${esc(String(Number(node?.depth || 0)))}">
          <div class="timeline-step-header">
            <div class="timeline-step-heading">
              <div class="timeline-step-labels">
                <span class="timeline-step-kicker">${esc(kind)}</span>
                <span class="timeline-step-badge">${esc(stepType)}</span>
                <span class="timeline-step-badge ${esc(status.className)}">${esc(status.label)}</span>
              </div>
              <div class="timeline-step-question">${esc(previewTitle)}</div>
            </div>
            <div class="timeline-step-time">${esc(timelineFmtStamp(node?.created_at))}${timelineElapsedText(node, previousNode) ? `<br>${esc(timelineElapsedText(node, previousNode))}` : ''}</div>
          </div>
          <div class="timeline-step-why"><strong>Why This Step</strong>${esc(timelineWhyThisStep(node, previousNode))}</div>
          <div class="timeline-step-context">${esc(relationship)}</div>
          <div class="timeline-meta-row ${esc(confidence.className ? `timeline-confidence ${confidence.className}` : '')}">
            ${timelineSharedStatePreview(node)}
            <span class="timeline-meta-pill"><strong>Time Range</strong><span>${esc(timelineTimeRangeLabel(node))}</span></span>
            <span class="timeline-meta-pill"><strong>Confidence</strong><span>${esc(confidence.text)}</span></span>
          </div>
          <div class="timeline-step-summary">${esc(timelineCleanSummary(node?.saved_summary || node?.summary || previewTitle))}</div>
          <div class="timeline-step-grid">
            ${timelineSectionCard('Carried Forward Evidence', renderEntityPills((Array.isArray(node?.pivot_source?.target_values) && node.pivot_source.target_values.length ? node.pivot_source.target_values : carriedForward), counts, { label: String(node?.pivot_source?.target_label || 'Entity') }))}
            ${timelineSectionCard('New In This Step', newEntities.length ? renderEntityPills(newEntities, counts, { label: 'New' }) : '<div class="timeline-section-copy muted">No new high-priority entities were added in this step.</div>')}
            ${timelineSectionCard('Missing Or Not Found', missingSummary ? `<div class="timeline-section-copy">No matching evidence found for <code>${esc(missingSummary)}</code>.</div>` : '<div class="timeline-section-copy muted">No major evidence gaps were called out for this step.</div>')}
            ${timelineSectionCard('Evidence Interpretation', `<div class="timeline-section-copy">${esc(timelineInterpretation(node))}</div>`)}
            ${timelineSectionCard('Pivot Options', Array.isArray(node?.pivot_candidates) && node.pivot_candidates.length ? `<div class="timeline-section-copy">${esc(String(node.pivot_candidates.length))} saved pivot option(s) are available from this step.</div><div class="timeline-pattern-strip">${node.pivot_candidates.slice(0, 2).map((item) => `<span class="timeline-pattern-chip"><strong>Pivot</strong><span>${esc(String(item?.target_label || item?.title || 'Next Step'))}</span></span>`).join('')}</div>` : '<div class="timeline-section-copy muted">No saved pivot candidates were captured on this step.</div>')}
            ${timelineSectionCard('Shared Investigation State', `<div class="timeline-section-copy">${esc(String(node?.search_strategy_summary || 'Saved state includes the executed query, entity extraction, pivot candidates, and result summary.'))}</div>${Array.isArray(node?.mitre_preview) && node.mitre_preview.length ? `<div class="timeline-pattern-strip">${node.mitre_preview.slice(0, 2).map((item) => `<span class="timeline-pattern-chip"><strong>ATT&CK</strong><span>${esc(item)}</span></span>`).join('')}</div>` : ''}`)}
          </div>
          ${query ? `<details class="timeline-inline-spl"><summary>Executed SPL</summary><pre>${esc(query)}</pre></details>` : ''}
          <div class="timeline-step-actions">
            <button type="button" class="btn-secondary" data-timeline-action="restore" data-case-id="${esc(caseId)}" data-node-id="${esc(String(node?.node_id || ''))}">Restore Step</button>
            <button type="button" class="btn-secondary" data-timeline-action="open" data-case-id="${esc(caseId)}" data-node-id="${esc(String(node?.node_id || ''))}">Open In Investigation</button>
            ${quickPivotTypes.includes('source_ip') ? `<button type="button" class="btn-primary" data-timeline-action="pivot-ip" data-node-id="${esc(String(node?.node_id || ''))}">Pivot on IP</button>` : ''}
            ${quickPivotTypes.includes('username') ? `<button type="button" class="btn-secondary" data-timeline-action="pivot-username" data-node-id="${esc(String(node?.node_id || ''))}">Pivot on Username</button>` : ''}
            <button type="button" class="btn-secondary" data-timeline-action="expand-time" data-node-id="${esc(String(node?.node_id || ''))}">Expand Time Range</button>
          </div>
        </article>
      `;
    }

    async function runTimelineAction(action, nodeId, caseId) {
      const timeline = Array.isArray(window.__agtsmithTimelineNodes) ? window.__agtsmithTimelineNodes : [];
      const node = timeline.find((item) => String(item?.node_id || '') === String(nodeId || ''));
      if (!node) return;
      if (action === 'restore') {
        await loadCaseNode(caseId, nodeId);
        return;
      }
      if (action === 'open') {
        await loadCaseNode(caseId, nodeId);
        const drawer = $('advanced-section');
        if (drawer) drawer.open = false;
        clearDrawerUpdate();
        return;
      }
      if (action === 'pivot-ip' || action === 'pivot-username') {
        const targetType = action === 'pivot-ip' ? 'source_ip' : 'username';
        const candidate = Array.isArray(node?.pivot_candidates) ? node.pivot_candidates.find((item) => String(item?.target_type || '') === targetType) : null;
        if (!candidate) return;
        selectFollowup(candidate, Number(candidate?.index || 0), 'Investigation Timeline');
        if (selectedFollowup) {
          const baseQuery = String(node?.query || '').trim();
          const timeRange = node?.time_range && typeof node.time_range === 'object' ? node.time_range : {};
          selectedFollowup.contextOverride = {
            case_id: String(caseId || '').trim(),
            current_node_id: String(node?.node_id || '').trim(),
            parent_node_id: String(node?.parent_node_id || '').trim(),
            root_question: String((timeline[0] && (timeline[0].question || timeline[0].title)) || node?.question || '').trim(),
            base_intent: String(node?.intent || '').trim(),
            base_query_args: {
              query: baseQuery,
              earliest_time: String(timeRange.earliest || '').trim(),
              latest_time: String(timeRange.latest || '').trim(),
              row_limit: 50,
            },
            base_query: baseQuery,
            time_range: {
              earliest: String(timeRange.earliest || '').trim(),
              latest: String(timeRange.latest || '').trim(),
            },
            entities: node?.evidence_entities && typeof node.evidence_entities === 'object' ? node.evidence_entities : {},
            ranked_entities: node?.ranked_entities && typeof node.ranked_entities === 'object' ? node.ranked_entities : {},
            pivot_candidates: Array.isArray(node?.pivot_candidates) ? node.pivot_candidates : [],
            graph_case_state: {
              case_id: String(caseId || '').trim(),
              current_node_id: String(node?.node_id || '').trim(),
              parent_node_id: String(node?.parent_node_id || '').trim(),
              root_question: String((timeline[0] && (timeline[0].question || timeline[0].title)) || node?.question || '').trim(),
              current_question: String(node?.question || node?.title || '').trim(),
              intent: String(node?.intent || '').trim(),
              node_type: String(node?.node_type || '').trim(),
              selected_tool: String(node?.selected_tool || '').trim(),
              time_range: {
                earliest: String(timeRange.earliest || '').trim(),
                latest: String(timeRange.latest || '').trim(),
              },
              query_args: {
                query: baseQuery,
                earliest_time: String(timeRange.earliest || '').trim(),
                latest_time: String(timeRange.latest || '').trim(),
                row_limit: 50,
              },
              rows_returned: Number(node?.row_count || 0),
              evidence_entities: node?.evidence_entities && typeof node.evidence_entities === 'object' ? node.evidence_entities : {},
              ranked_entities: node?.ranked_entities && typeof node.ranked_entities === 'object' ? node.ranked_entities : {},
              pivot_candidates: Array.isArray(node?.pivot_candidates) ? node.pivot_candidates : [],
              summary: String(node?.saved_summary || node?.summary || '').trim(),
            },
          };
        }
        setActiveTrayTab('pivot', { openDrawer: true });
        return;
      }
      if (action === 'expand-time') {
        const baseQuestion = String(node?.active_question || node?.question || '').trim();
        $('question').value = `Expand the time range to the last 72 hours and continue this investigation from: ${baseQuestion}`;
        $('question').focus();
      }
    }

    function applyTimelineVisualFilters() {
      document.querySelectorAll('.timeline-step-card').forEach((card) => {
        const stepKind = String(card.getAttribute('data-step-kind') || '');
        const refs = String(card.getAttribute('data-entity-refs') || '');
        const noResults = card.classList.contains('no-results');
        let matchesMode = true;
        if (activeTimelineStepFilter === 'pivots') matchesMode = stepKind !== 'initial_query';
        if (activeTimelineStepFilter === 'no_results') matchesMode = noResults;
        const matchesEntity = !activeTimelineEntityFilter || refs.split('|').includes(activeTimelineEntityFilter);
        card.classList.toggle('dimmed', !(matchesMode && matchesEntity));
        card.classList.toggle('focused', !!activeTimelineEntityFilter && matchesEntity);
      });
      const filterShell = $('case-active-filter');
      if (filterShell) {
        if (activeTimelineEntityFilter) {
          filterShell.style.display = '';
          filterShell.innerHTML = `Highlighting steps that reference <code>${esc(activeTimelineEntityFilter)}</code>. <button type="button" class="btn-secondary" id="timeline-clear-filter" style="margin-top:0;padding:4px 8px;">Clear Filter</button>`;
          const clearBtn = $('timeline-clear-filter');
          if (clearBtn) clearBtn.onclick = () => {
            activeTimelineEntityFilter = '';
            document.querySelectorAll('.entity-pill').forEach((pill) => pill.classList.remove('active'));
            applyTimelineVisualFilters();
          };
        } else {
          filterShell.style.display = 'none';
          filterShell.innerHTML = '';
        }
      }
    }

    function renderCaseTimeline(result) {
      const badge = $('case-badge');
      const latestBtn = $('case-latest-btn');
      const workspaceLink = $('case-workspace-link');
      const summary = $('case-summary');
      const shell = $('case-timeline-list');
      const narrativeShell = $('drawer-investigation-narrative');
      const patternStrip = $('case-pattern-strip');
      const entityStrip = $('case-entity-strip');
      const decisionBlock = $('case-decision-block');
      const caseContext = result?.case_context && typeof result.case_context === 'object' ? result.case_context : null;
      const timeline = Array.isArray(caseContext?.timeline) ? caseContext.timeline : [];
      const currentNodeId = String(caseContext?.node_id || '').trim();
      const caseId = String(caseContext?.case_id || '').trim();
      window.__agtsmithTimelineNodes = timeline;
      if (!caseId || !timeline.length) {
        badge.textContent = 'New';
        summary.textContent = 'Run an investigation to create a durable analyst timeline. Original findings, deeper pivots, and restored steps will appear here without forcing you to rerun Splunk.';
        shell.innerHTML = '';
        if (narrativeShell) narrativeShell.innerHTML = '';
        if (patternStrip) patternStrip.innerHTML = '';
        if (entityStrip) entityStrip.innerHTML = '';
        if (decisionBlock) decisionBlock.innerHTML = '';
        if (workspaceLink) workspaceLink.href = '/cases';
        if (latestBtn) latestBtn.style.display = 'none';
        return;
      }
      const latestNode = timeline[timeline.length - 1] || null;
      const currentNode = timeline.find((node) => String(node?.node_id || '') === currentNodeId) || latestNode || null;
      const entityCounts = timelineEntityStepCounts(timeline);
      const pivotCount = timeline.filter((node) => Number(node?.depth || 0) > 0).length;
      const nodeIndexMap = new Map(timeline.map((node, index) => [String(node?.node_id || ''), index]));
      const rootCount = timeline.length ? 1 : 0;
      const story = timelineNarrativeModel(timeline);
      badge.textContent = caseId;
      if (workspaceLink) workspaceLink.href = `/cases?case_id=${encodeURIComponent(caseId)}`;
      summary.innerHTML = `This investigation timeline preserves <strong>${timeline.length}</strong> saved step(s): <strong>${rootCount}</strong> original finding and <strong>${pivotCount}</strong> deeper pivot step(s). Click any card to restore that exact state, inspect its evidence, and continue the investigation from there.`;
      if (latestBtn && latestCaseRef && latestCaseRef.case_id === caseId && latestCaseRef.node_id && latestCaseRef.node_id !== currentNodeId) {
        latestBtn.style.display = 'inline-flex';
      } else if (latestBtn) {
        latestBtn.style.display = 'none';
      }
      if (narrativeShell) {
        narrativeShell.innerHTML = `
          <div class="timeline-story-card">
            <div class="timeline-story-head">
              <div>
                <div class="drawer-clone-title" style="margin-bottom:4px;">Investigation Narrative</div>
                <div class="timeline-story-title">${esc(story.investigationType)}</div>
              </div>
              <div class="timeline-pattern-strip">
                <span class="timeline-pattern-chip"><strong>Pattern</strong><span>${esc(story.pattern)}</span></span>
                <span class="timeline-pattern-chip"><strong>Disposition</strong><span>${esc(story.disposition)}</span></span>
              </div>
            </div>
            <div class="timeline-story-copy">${story.lines.map((line) => esc(line)).join('<br>')}</div>
          </div>
        `;
      }
      if (patternStrip) {
        patternStrip.innerHTML = `
          <span class="timeline-pattern-chip"><strong>Investigation Type</strong><span>${esc(story.investigationType)}</span></span>
          <span class="timeline-pattern-chip"><strong>Pattern</strong><span>${esc(story.pattern)}</span></span>
          <span class="timeline-pattern-chip"><strong>Current Focus</strong><span>${esc(timelineOrdinalLabel(Number(nodeIndexMap.get(String(currentNode?.node_id || '')) || 0)))}</span></span>
        `;
      }
      if (entityStrip) {
        const featured = [];
        timeline.forEach((node) => timelinePrimaryEntityValues(node).forEach((value) => { if (value && !featured.includes(value)) featured.push(value); }));
        entityStrip.innerHTML = featured.length
          ? renderEntityPills(featured.slice(0, 8), entityCounts, { label: 'Tracked' })
          : '<div class="timeline-section-copy muted">Tracked entities will appear here once evidence is returned.</div>';
      }
      if (decisionBlock) {
        decisionBlock.innerHTML = `
          <div class="timeline-decision-title">Decision Moment</div>
          <div class="timeline-decision-copy">${Number(latestNode?.row_count || 0) <= 0 && Number(latestNode?.depth || 0) > 0 ? 'No evidence of successful compromise has been observed in the latest pivot. The current chain still supports suspicion, but not confirmation.' : 'The latest step is ready for analyst follow-up, validation in Splunk, or a narrower continuation.'}</div>
          <div class="timeline-decision-actions">
            ${story.recommendations.map((item) => `<span class="timeline-pattern-chip"><strong>Next</strong><span>${esc(item)}</span></span>`).join('')}
          </div>
        `;
      }
      shell.innerHTML = timeline.map((node, index) => {
        const previousNode = index > 0 ? timeline[index - 1] : null;
        const parentIndex = nodeIndexMap.get(String(node?.parent_node_id || ''));
        const parentNode = Number.isInteger(parentIndex) ? timeline[parentIndex] : null;
        return timelineCardHtml(node, {
          currentNodeId,
          latestNodeId: latestNode?.node_id || '',
          caseId,
          entityCounts,
          stepIndex: index,
          previousNode,
          parentNode,
          parentIndex: Number.isInteger(parentIndex) ? parentIndex : 0,
        });
      }).join('');
      document.querySelectorAll('.timeline-filter-chip').forEach((btn) => {
        btn.onclick = () => {
          activeTimelineStepFilter = String(btn.getAttribute('data-case-filter') || 'all');
          document.querySelectorAll('.timeline-filter-chip').forEach((node) => node.classList.toggle('active', node === btn));
          applyTimelineVisualFilters();
        };
      });
      document.querySelectorAll('.timeline-step-card').forEach((card) => {
        card.onclick = async (event) => {
          if (event.target && event.target.closest('[data-timeline-action], .entity-pill, details, summary')) return;
          await loadCaseNode(card.getAttribute('data-case-id') || '', card.getAttribute('data-node-id') || '');
        };
      });
      document.querySelectorAll('[data-timeline-action]').forEach((btn) => {
        btn.onclick = async (event) => {
          event.stopPropagation();
          await runTimelineAction(
            btn.getAttribute('data-timeline-action') || '',
            btn.getAttribute('data-node-id') || '',
            btn.getAttribute('data-case-id') || caseId,
          );
        };
      });
      document.querySelectorAll('.entity-pill[data-entity-value]').forEach((pill) => {
        pill.onclick = (event) => {
          event.stopPropagation();
          const value = String(pill.getAttribute('data-entity-value') || '');
          activeTimelineEntityFilter = activeTimelineEntityFilter === value ? '' : value;
          document.querySelectorAll('.entity-pill').forEach((node) => node.classList.toggle('active', activeTimelineEntityFilter && String(node.getAttribute('data-entity-value') || '') === activeTimelineEntityFilter));
          applyTimelineVisualFilters();
        };
      });
      if (latestBtn) {
        latestBtn.onclick = async () => {
          if (!latestCaseRef?.case_id || !latestCaseRef?.node_id) return;
          await loadCaseNode(latestCaseRef.case_id, latestCaseRef.node_id);
        };
      }
      applyTimelineVisualFilters();
    }

    function markDrawerUpdate(tab, message) {
      const drawer = $('advanced-section');
      if (drawer && drawer.open) {
        clearDrawerUpdate();
        return;
      }
      drawerHasUnread = true;
      drawerUnreadTab = String(tab || activeTrayTab || 'pivot');
      const indicator = $('drawer-update-indicator');
      const text = $('drawer-update-text');
      if (indicator) indicator.classList.add('visible');
      if (text) text.textContent = String(message || 'New drawer content');
      document.querySelectorAll('[data-tray-tab]').forEach((node) => {
        const isTarget = String(node.getAttribute('data-tray-tab') || '') === drawerUnreadTab;
        node.classList.toggle('has-update', isTarget);
      });
    }

    function clearDrawerUpdate() {
      drawerHasUnread = false;
      drawerUnreadTab = '';
      const indicator = $('drawer-update-indicator');
      if (indicator) indicator.classList.remove('visible');
      document.querySelectorAll('[data-tray-tab]').forEach((node) => node.classList.remove('has-update'));
    }

    function drawerPreferredTab(result) {
      const supported = result?.supported !== false;
      const hasPivots = /pivot-card|pivot-action|follow-up target/i.test(String($('pivot-cards')?.innerHTML || ''));
      const hasRows = hasEvidenceRows(result || {});
      const hasSpl = Boolean(String($('spl-query')?.textContent || '').trim());
      if (!supported) return 'review';
      if (hasPivots) return 'pivot';
      if (hasRows) return 'evidence';
      if (hasSpl) return 'spl';
      return 'pivot';
    }

    function selectFollowup(candidate, index, origin) {
      const nextQuestion = String(candidate?.next_question || candidate?.title || candidate?.text || '').trim();
      selectedFollowup = {
        text: nextQuestion,
        index: Number(index || 0),
        origin: String(origin || '').trim(),
        candidate: candidate && typeof candidate === 'object' ? candidate : null,
      };
      if (!selectedFollowup.text) {
        selectedFollowup = null;
        return;
      }
      renderSelectedFollowup();
    }

    function extractExecutedSPL(result) {
      if (result?.query_args?.query) return String(result.query_args.query);
      if (result?.final_adjudication?.selected_args?.query) return String(result.final_adjudication.selected_args.query);
      if (result?.evidence?.query_or_args?.query) return String(result.evidence.query_or_args.query);
      if (Array.isArray(result?.trajectory)) {
        for (let i = result.trajectory.length - 1; i >= 0; i -= 1) {
          const q = result.trajectory[i]?.args?.query;
          if (q) return String(q);
        }
      }
      return '';
    }

    function extractCoverage(result, spl) {
      const source = String(spl || '');
      const indexes = Array.from(new Set(Array.from(source.matchAll(/index\\s*=\\s*([A-Za-z0-9_:-]+)/g)).map((m) => m[1])));
      const sourcetypes = Array.from(new Set(Array.from(source.matchAll(/sourcetype\\s*=\\s*\"?([A-Za-z0-9_:\\/.-]+)\"?/g)).map((m) => m[1])));
      const rawSources = Array.from(new Set(Array.from(source.matchAll(/source\\s*=\\s*\"([^\"]+)\"/g)).map((m) => m[1])));
      const lower = source.toLowerCase();
      const platforms = [];
      if (lower.includes('platform=\"linux\"') || lower.includes('/var/log/auth.log') || lower.includes('/var/log/secure') || lower.includes('linux_secure') || lower.includes(' index=linux')) platforms.push('Linux');
      if (lower.includes('platform=\"windows\"') || lower.includes('xmlwineventlog') || lower.includes('eventcode=4625') || lower.includes(' index=windows')) platforms.push('Windows');
      if (lower.includes('access_combined') || lower.includes('apache')) platforms.push('Apache/Web');
      if (lower.includes('cloudtrail')) platforms.push('AWS CloudTrail');
      if (lower.includes('stream:http')) platforms.push('HTTP Proxy/Stream');
      if (lower.includes('cisco') || lower.includes('asa')) platforms.push('Cisco ASA');
      if (lower.includes('vpcflow')) platforms.push('AWS VPC Flow');
      const summaryText = String(result?.summary || '').toLowerCase();
      const rows = Number(result?.rows_returned || 0);
      let coverageStatus = rows > 0 ? 'Evidence returned' : 'No evidence returned';
      const gaps = [];
      const crossPlatform = source.includes('append [') || new Set(platforms).size > 1;
      if (crossPlatform) coverageStatus = rows > 0 ? 'Cross-platform coverage attempted' : 'Cross-platform coverage attempted with no evidence';
      if (summaryText.includes('windows security logon failures were queried') || summaryText.includes('no windows')) gaps.push('Windows coverage was queried but returned no matching evidence in this time window.');
      if (summaryText.includes('visibility gap') || summaryText.includes('indexing issue') || summaryText.includes('data or indexing issue')) gaps.push('The investigation narrative indicates a telemetry or indexing visibility concern.');
      return {
        indexes,
        sourcetypes,
        rawSources,
        platforms: Array.from(new Set(platforms)),
        coverageStatus,
        gaps,
        crossPlatform,
      };
    }

    function deriveHighestPriorityEntity(result) {
      const entities = Array.isArray(result?.evidence?.top_entities) ? result.evidence.top_entities : [];
      if (entities.length && entities[0] && typeof entities[0] === 'object') {
        const row = entities[0];
        return row.src_ip || row.clientip || row.host || row.user_name || row.TargetUserName || row.Account_Name || row.index || 'Not derived';
      }
      const summary = String(result?.summary || '');
      const ipMatch = summary.match(/\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b/);
      if (ipMatch) return ipMatch[0];
      const hostMatch = summary.match(/host\\s+([A-Za-z0-9_.:-]+)/i);
      if (hostMatch) return hostMatch[1];
      return 'Not derived';
    }

    function reviewClaimSupport(result) {
      if (result?.supported === false) return { value: 'Blocked', note: 'The final plan did not pass guarded execution checks.' };
      if (!result || typeof result !== 'object') return { value: 'Not started', note: 'Run an investigation to see evidence support.' };
      const summary = String(result?.summary || '').toLowerCase();
      const rows = Number(result?.rows_returned || 0);
      if (rows <= 0) return { value: 'No supporting evidence', note: 'The bounded Splunk search completed, but no matching rows were returned.' };
      if (summary.includes('did not confirm') || summary.includes('do not prove') || summary.includes('no evidence of failures') || summary.includes('indirect')) {
        return { value: 'Partial / indirect', note: 'The evidence is related, but the current summary says it does not fully prove the original claim.' };
      }
      return { value: 'Directly supported', note: 'Returned rows support the current investigation conclusion.' };
    }

    function baseSplSearchSegment(spl) {
      const source = String(spl || '').trim();
      if (!source) return '';
      const base = source.split('|')[0].trim();
      if (!base) return '';
      return /^search\b/i.test(base) ? base : `search ${base}`;
    }

    function bestFieldForRowKey(rowKey, spl, row) {
      const key = String(rowKey || '').trim();
      const lowerSpl = String(spl || '').toLowerCase();
      const candidates = {
        user_name: ['user_name', 'user', 'Account_Name', 'TargetUserName', 'dest_user'],
        host: ['host', 'ComputerName', 'dest', 'dvc'],
        src_ip: ['src_ip', 'src', 'clientip', 'Source_Network_Address'],
        clientip: ['clientip', 'src_ip', 'src', 'ip'],
        index: ['index'],
        source: ['source'],
        sourcetype: ['sourcetype'],
        method: ['method'],
        status: ['status'],
        file: ['file'],
        uri_path: ['uri_path', 'uri'],
        uri: ['uri', 'uri_path'],
        user: ['user', 'user_name'],
      };
      const options = candidates[key] || [key];
      for (const candidate of options) {
        const pattern = new RegExp(`(^|[^A-Za-z0-9_])${candidate}([^A-Za-z0-9_]|$)`, 'i');
        if (pattern.test(lowerSpl)) return candidate;
      }
      if (options.length > 1) {
        for (const candidate of options) {
          if (candidate in (row || {})) return candidate;
        }
      }
      return options[0];
    }

    function rowFieldOverride(rowKey, coverage, row) {
      const key = String(rowKey || '').trim();
      const platforms = Array.isArray(coverage?.platforms) ? coverage.platforms.map((item) => String(item || '').toLowerCase()) : [];
      const lowerSources = Array.isArray(coverage?.rawSources) ? coverage.rawSources.map((item) => String(item || '').toLowerCase()) : [];
      const isLinuxAuth = platforms.includes('linux') || lowerSources.some((item) => item.includes('/var/log/auth.log') || item.includes('/var/log/secure'));
      if (isLinuxAuth && key === 'user_name') return 'user';
      return '';
    }

    function collectPivotItems(result) {
      const mitrePivots = Array.isArray(result?.mitre_attack?.next_pivots) ? result.mitre_attack.next_pivots : [];
      const tdirPivots = Array.isArray(result?.tdir_case?.recommended_next_pivots) ? result.tdir_case.recommended_next_pivots : [];
      return (mitrePivots.length ? mitrePivots : tdirPivots).map((item) => String(item || '').trim()).filter(Boolean);
    }

    function collectPivotCandidates(result) {
      const structured = Array.isArray(result?.pivot_context?.pivot_candidates)
        ? result.pivot_context.pivot_candidates.filter((item) => item && typeof item === 'object')
        : [];
      if (structured.length) return structured;
      return collectPivotItems(result).map((text, index) => ({
        id: `legacy_pivot_${index + 1}`,
        index,
        title: text,
        target_label: classifyPivot(text).entity,
        target_values: [],
        execution_mode: 'stateful_followup_question',
        next_question: text,
      }));
    }

    function collectEvidenceRows(result) {
      const raw =
        (Array.isArray(result?.__ui_sample_rows) && result.__ui_sample_rows.length
          ? result.__ui_sample_rows
          : (
            Array.isArray(result?.spl_results_preview) && result.spl_results_preview.length
              ? result.spl_results_preview
              : (
                Array.isArray(result?.evidence?.top_entities)
                  ? result.evidence.top_entities
                  : []
              )
          ));
      return raw.filter((row) => row && typeof row === 'object').slice(0, 6);
    }

    function buildSplunkSearchUrlForRow(result, row, coverage) {
      const splunkBase = String(result?.splunk_search_url_base || '').trim();
      if (!splunkBase || !row || typeof row !== 'object') return '#';
      const originalSpl = extractExecutedSPL(result || {});
      const baseSearch = baseSplSearchSegment(originalSpl);
      const earliest = String(
        result?.query_args?.earliest_time ||
        result?.final_adjudication?.selected_args?.earliest_time ||
        result?.evidence?.time_window?.earliest_time ||
        '-24h@h'
      );
      const latest = String(
        result?.query_args?.latest_time ||
        result?.final_adjudication?.selected_args?.latest_time ||
        result?.evidence?.time_window?.latest_time ||
        'now'
      );
      const preferredFields = ['index', 'host', 'user_name', 'user', 'TargetUserName', 'Account_Name', 'src_ip', 'clientip', 'source', 'sourcetype', 'file', 'method', 'status'];
      const clauses = [];
      const rowIndex = String(row.index || '').trim();
      const fallbackIndex = coverage.indexes[0] || '';
      if (rowIndex) clauses.push(`index=${rowIndex}`);
      else if (fallbackIndex) clauses.push(`index=${fallbackIndex}`);
      preferredFields.forEach((field) => {
        const value = String(row[field] ?? '').trim();
        if (!value || field === 'index') return;
        if (field === 'user_name' && ('user' in row) && String(row.user || '').trim()) return;
        const safe = value.replace(/"/g, '\\"');
        const actualField = rowFieldOverride(field, coverage, row) || bestFieldForRowKey(field, originalSpl, row);
        clauses.push(`${actualField}=\"${safe}\"`);
      });
      const query = `${baseSearch || 'search'} ${clauses.join(' ')} | head 200`.replace(/^search\\s+search\\b/i, 'search');
      const params = new URLSearchParams({
        q: query,
        'display.page.search.mode': 'smart',
        'dispatch.sample_ratio': '1',
        workload_pool: '',
        earliest,
        latest,
        'display.page.search.tab': 'statistics',
        'display.general.type': 'statistics',
      });
      return `${splunkBase}?${params.toString()}`;
    }

    function compactEvidenceTable(rows, result, coverage) {
      if (!rows.length) return '<div class="drawer-empty">No sample entities or row highlights are available yet.</div>';
      const columns = Array.from(new Set(rows.flatMap((row) => Object.keys(row || {})))).slice(0, 4);
      const colorForValue = (column, value) => {
        const text = String(value || '').trim();
        if (!text || text === '—' || text === '-') return esc(text || '—');
        let hash = 0;
        const source = `${String(column || '')}:${text.toLowerCase()}`;
        for (let i = 0; i < source.length; i += 1) hash = ((hash << 5) - hash) + source.charCodeAt(i);
        const hue = Math.abs(hash) % 360;
        const bg = `hsla(${hue}, 64%, 16%, 0.92)`;
        const border = `hsla(${hue}, 72%, 42%, 0.82)`;
        const fg = `hsla(${hue}, 85%, 86%, 1)`;
        return `<span class="drawer-value-tag" style="background:${bg};border-color:${border};color:${fg};">${esc(text)}</span>`;
      };
      const head = columns.map((col) => `<th>${esc(col)}</th>`).join('');
      const body = rows.map((row) => {
        const rowHref = buildSplunkSearchUrlForRow(result, row, coverage);
        return `<tr class="${rowHref !== '#' ? 'drawer-row-link' : ''}"${rowHref !== '#' ? ` data-row-href="${esc(rowHref)}"` : ''}>${columns.map((col) => {
        const text = compactValue(row[col]);
        return `<td>${text ? colorForValue(col, text) : '&mdash;'}</td>`;
      }).join('')}</tr>`;
      }).join('');
      return `<table class="drawer-entity-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
    }

    function buildDrawerPivotMarkup(result) {
      if (!result || typeof result !== 'object') {
        return '<div class="drawer-empty">Run an investigation to see the best next pivot back into Splunk.</div>';
      }
      if (result?.supported === false) {
        return '<div class="drawer-inline-note">This request was blocked before a valid pivot path could be approved. Refine the question first, then return here for Splunk follow-up actions.</div>';
      }
      const pivotCandidates = collectPivotCandidates(result);
      if (!pivotCandidates.length) {
        return '<div class="drawer-inline-note">No next-step pivots are available yet. When evidence review completes, this tab will highlight the best follow-up move back into Splunk.</div>';
      }
      return `<div class="drawer-action-list">${pivotCandidates.slice(0, 3).map((candidate, index) => {
        const meta = pivotPresentation(candidate);
        return `
          <div class="drawer-action-card">
            <div class="drawer-action-head">
              <div>
                <div class="drawer-action-kicker">Best next move ${index + 1}</div>
                <div class="drawer-action-title">${esc(meta.title || String(candidate?.title || ''))}</div>
              </div>
              <span class="drawer-chip">${esc(meta.scope)}</span>
            </div>
            <div class="drawer-action-meta-item"><strong>Why</strong>${esc(meta.why)}</div>
            <div class="drawer-action-meta-item"><strong>Pivot target</strong><code>${esc(meta.targetDisplay)}</code></div>
            ${meta.provenanceText ? `<div class="drawer-action-meta-item"><strong>Why this value</strong>${esc(meta.provenanceText)}</div>` : ''}
            <div class="drawer-action-meta-item"><strong>Expected value</strong>${esc(meta.expected)}</div>
            <div class="drawer-action-buttons">
              <button type="button" class="btn-secondary drawer-pivot-open" data-drawer-pivot-index="${index}">Load Into Follow-Up Drawer</button>
              <button type="button" class="btn-followup drawer-pivot-run" data-drawer-pivot-index="${index}">Run This Pivot</button>
            </div>
          </div>
        `;
      }).join('')}</div>`;
    }

    function buildDrawerEvidenceMarkup(result, coverage) {
      if (!result || typeof result !== 'object') {
        return {
          summary: '<div class="drawer-empty">Run an investigation to see execution status, evidence return, and claim support.</div>',
          coverage: '<div class="drawer-empty">Coverage and entity highlights will appear here after an investigation runs.</div>',
        };
      }
      const support = reviewClaimSupport(result);
      const rows = Number(result?.rows_returned || 0);
      const entity = deriveHighestPriorityEntity(result);
      const trust = `
        <div class="drawer-trust-strip">
          <div class="drawer-trust-card"><div class="drawer-trust-label">Execution</div><div class="drawer-trust-value">${esc(result?.supported === false ? 'Blocked' : 'Complete')}</div><div class="drawer-trust-note">${esc(result?.supported === false ? 'The request never became a valid execution path.' : 'The bounded investigation path executed read-only retrieval.')}</div></div>
          <div class="drawer-trust-card"><div class="drawer-trust-label">Evidence Returned</div><div class="drawer-trust-value">${esc(rows > 0 ? `${rows} row(s)` : 'No rows')}</div><div class="drawer-trust-note">${esc(coverage.coverageStatus || 'Coverage unknown')}</div></div>
          <div class="drawer-trust-card"><div class="drawer-trust-label">Claim Support</div><div class="drawer-trust-value">${esc(support.value)}</div><div class="drawer-trust-note">${esc(support.note)}</div></div>
          <div class="drawer-trust-card"><div class="drawer-trust-label">Best Entity</div><div class="drawer-trust-value">${esc(entity)}</div><div class="drawer-trust-note">${esc(rows > 0 ? 'Highest-salience value derived from the returned evidence preview.' : 'No high-salience entity could be derived yet.')}</div></div>
        </div>
      `;
      const rowsMarkup = compactEvidenceTable(collectEvidenceRows(result), result, coverage);
      const coverageMarkup = `
        <div class="drawer-inline-note">
          <strong>Data path:</strong> ${esc(coverage.platforms.length ? coverage.platforms.join(', ') : 'Not derived')}<br>
          <strong>Indexes:</strong> ${esc(coverage.indexes.length ? coverage.indexes.join(', ') : 'Not derived')}<br>
          <strong>Sourcetypes:</strong> ${esc(coverage.sourcetypes.length ? coverage.sourcetypes.join(', ') : 'Not derived')}
        </div>
        ${rowsMarkup}
      `;
      return { summary: trust, coverage: coverageMarkup };
    }

    function buildDrawerSplMarkup(result, coverage, spl, latestRun) {
      if (!result || typeof result !== 'object') {
        return {
          summary: 'Run an investigation to see the exact query path and why it was chosen.',
          query: '(No Splunk query captured yet)',
          results: '(No SPL result rows captured yet)',
        };
      }
      const rows = Number(result?.rows_returned ?? latestRun?.rows_returned ?? 0);
      const runtime = latestRun?.execution_ms ? `${latestRun.execution_ms} ms` : 'n/a';
      const summary = `
        <div class="drawer-trust-strip">
          <div class="drawer-trust-card"><div class="drawer-trust-label">Goal</div><div class="drawer-trust-value">${esc(result?.intent || 'Unknown')}</div><div class="drawer-trust-note">${esc(String(result?.search_strategy_summary || result?.intent_summary || 'Bounded query strategy selected for this question.'))}</div></div>
          <div class="drawer-trust-card"><div class="drawer-trust-label">Query Runtime</div><div class="drawer-trust-value">${esc(runtime)}</div><div class="drawer-trust-note">${esc(rows > 0 ? `${rows} row(s) returned.` : 'No matching rows returned.')}</div></div>
          <div class="drawer-trust-card"><div class="drawer-trust-label">Search Scope</div><div class="drawer-trust-value">${esc(coverage.indexes.length ? coverage.indexes.join(', ') : 'Derived scope')}</div><div class="drawer-trust-note">${esc(coverage.rawSources.length ? coverage.rawSources.join(', ') : 'No explicit source path extracted')}</div></div>
        </div>
      `;
      const rawSplHref = String($('spl-link')?.getAttribute('href') || '').trim();
      return {
        summary,
        query: spl || '(No Splunk query captured yet)',
        results: $('spl-results')?.textContent || '(No SPL result rows captured yet)',
        splHref: rawSplHref && rawSplHref !== '#' ? rawSplHref : '#',
      };
    }

    function buildDrawerTimelineMarkup(result) {
      if (!result || typeof result !== 'object') {
        return '<div class="drawer-empty">Timeline detail will appear here after the investigation progresses.</div>';
      }
      const items = [
        ['Question accepted', 'The controller validated read-only scope and chose the bounded investigation path.', result?.intent ? `Intent selected: ${result.intent}` : 'Intent not recorded.'],
        ['SPL plan chosen', 'Planner, writer, and reviewers selected the query path used for retrieval.', result?.selected_tool ? `Execution path: ${result.selected_tool}` : 'Execution path not recorded.'],
        ['Evidence returned', Number(result?.rows_returned || 0) > 0 ? `Splunk returned ${String(result?.rows_returned || 0)} row(s) for analyst review.` : 'The search completed without matching rows.', reviewClaimSupport(result).note],
      ];
      if (result?.continuation_reviewer_output?.should_continue === true) {
        items.push(['Recommended next move', 'A deeper follow-up investigation was recommended.', String(result?.continuation_reviewer_output?.next_best_question || 'Review the highest-value next pivot.')]);
      }
      return `<div class="drawer-timeline-mini">${items.map((item, index) => `
        <div class="drawer-timeline-step">
          <div class="drawer-timeline-index">${index + 1}</div>
          <div><div class="drawer-timeline-title">${esc(item[0])}</div><div class="drawer-timeline-copy">${esc(item[1])}<br>${esc(item[2])}</div></div>
          <div class="drawer-timeline-tag">${esc(item[0])}</div>
        </div>
      `).join('')}</div>`;
    }

    function renderPhaseStrip(phases) {
      const shell = $('phase-strip-row');
      if (!shell) return;
      const source = phases && typeof phases === 'object' ? phases : {
        detect: 'planned',
        triage: 'planned',
        investigate: 'planned',
      };
      const ordered = [
        ['detect', source.detect || 'planned'],
        ['triage', source.triage || 'planned'],
        ['investigate', source.investigate || 'planned'],
      ];
      shell.innerHTML = ordered.map(([name, state]) => `
        <div class="phase-pill-mini ${esc(String(state).replaceAll(' ', '_'))}">
          <span class="phase-mini-name">${esc(name)}</span>
          <span class="phase-mini-state">${esc(String(state).replaceAll('_', ' '))}</span>
        </div>
      `).join('');
    }

    function buildDrawerMitreMarkup(result) {
      if (!result || typeof result !== 'object') {
        return '<div class="drawer-empty">ATT&CK context will appear here after evidence review completes.</div>';
      }
      const bundle = (result?.mitre_attack && typeof result.mitre_attack === 'object') ? result.mitre_attack : {};
      const techniques = Array.isArray(bundle?.techniques) ? bundle.techniques : [];
      const nextPivots = Array.isArray(bundle?.next_pivots) ? bundle.next_pivots : [];
      if (!techniques.length && !nextPivots.length) {
        return '<div class="drawer-inline-note">No ATT&CK mapping was produced for this investigation result.</div>';
      }
      return `
        <div class="drawer-technique-grid">
          ${techniques.slice(0, 3).map((item) => `
            <div class="drawer-technique-card ${esc(mitreTone(item?.tactic || item?.kill_chain || ''))}">
              <div class="drawer-technique-kicker">${esc(String(item?.tactic || item?.kill_chain || 'ATT&CK technique'))}</div>
              <div class="drawer-technique-title">${esc(String(item?.technique_id || '').trim())} ${esc(String(item?.technique || '').trim())}</div>
              <div class="drawer-technique-copy">${esc(String(item?.why || item?.rationale || item?.description || 'Mapped from the current evidence and analyst-facing summary.'))}</div>
              <div class="drawer-technique-meta">
                ${item?.confidence ? `<span class="drawer-technique-pill">Confidence ${esc(String(item.confidence))}</span>` : ''}
                ${item?.kill_chain ? `<span class="drawer-technique-pill">${esc(String(item.kill_chain))}</span>` : ''}
              </div>
            </div>
          `).join('')}
        </div>
        ${bundle.frame ? `<div class="drawer-inline-note" style="margin-top:10px;">${esc(bundle.frame)}</div>` : ''}
        ${nextPivots.length ? `<div class="drawer-inline-note" style="margin-top:10px;"><strong>ATT&CK-linked pivot:</strong> ${esc(nextPivots[0])}<br>This stays separate from the Pivot tab so ATT&CK remains context, while Pivot remains the direct action surface back into Splunk.</div>` : ''}
      `;
    }

    function renderCaseHeader(result, coverage, latestRun) {
      const confidence = result?.final_confidence || result?.selected_confidence || 'n/a';
      $('case-header-chips').innerHTML = `
        <div class="utility-pill readonly"><span>Read-Only</span><strong>Splunk investigation mode</strong></div>
        <div class="utility-pill"><span>Case type</span><strong>${esc(result?.intent || 'unknown')}</strong></div>
        <div class="utility-pill"><span>Confidence</span><strong>${esc(String(confidence))}</strong></div>
        <div class="utility-pill"><span>Coverage</span><strong>${esc(coverage.coverageStatus || 'Unknown')}</strong></div>
        <div class="utility-pill"><span>Rows</span><strong>${esc(String(result?.rows_returned ?? latestRun?.rows_returned ?? 'n/a'))}</strong></div>
      `;
      syncUtilityBarVisibility();
      bindSplToggleButtons();
    }

    function investigationOutcomeNote(result) {
      const intent = String(result?.intent || '').toLowerCase();
      const summary = String(result?.summary || '').toLowerCase();
      if (intent === 'failed_login_activity' && (summary.includes('no evidence of failures') || summary.includes('successful authentication attempts'))) {
        return 'Returned rows did not confirm failed-login activity. The query returned authentication-related records, but the current evidence summary says they do not prove failed logins.';
      }
      return '';
    }

    function renderBlockedOutcome(result) {
      const latestRun = Array.isArray(result?.selected_spl_details) && result.selected_spl_details.length
        ? (result.selected_spl_details[result.selected_spl_details.length - 1] || {})
        : {};
      const spl = extractExecutedSPL(result || {});
      const coverage = extractCoverage(result || {}, spl);
      renderCaseHeader(result || {}, coverage, latestRun);
      renderSplEvidence(result || {}, coverage, spl, latestRun);
      renderCoverageVisibility(result || {}, coverage);
      $('decision-support-summary').innerHTML = `
        <div class="support-item"><div class="support-label">Policy outcome</div><div class="support-value">Blocked</div></div>
        <div class="support-item"><div class="support-label">Why</div><div class="support-value">${esc(String(result?.guardrail_reason || result?.final_adjudication?.validation_reason || 'Request failed deterministic validation.'))}</div></div>
      `;
      renderPhaseStrip({ detect: 'blocked', triage: 'planned', investigate: 'planned' });
      $('investigation-timeline').innerHTML = `
        <details class="timeline-phase" open>
          <summary>
            <div class="timeline-phase-main">
              <div class="timeline-phase-name">Detect</div>
              <div class="timeline-phase-summary">The request was accepted, classified, and then stopped by policy.</div>
            </div>
            <div class="timeline-phase-status">blocked</div>
          </summary>
          <div class="timeline-phase-body">
            <div class="timeline-detail-grid">
              <div class="timeline-detail"><div class="timeline-detail-title">Why it stopped</div><div class="timeline-detail-copy">${esc(String(result?.guardrail_reason || result?.final_adjudication?.validation_reason || 'The final query did not pass deterministic validation.'))}</div></div>
              <div class="timeline-detail"><div class="timeline-detail-title">What ran</div><div class="timeline-detail-copy">Planning and review completed, but the bounded execution plan was not allowed to proceed.</div></div>
              <div class="timeline-detail"><div class="timeline-detail-title">What to do next</div><div class="timeline-detail-copy">Refine the question, verify the expected source/index assumptions, or use a narrower environment-supported pivot.</div></div>
            </div>
          </div>
        </details>
      `;
      $('pivot-cards').innerHTML = '<div class="brief-body muted">No follow-up pivots are shown because the request was blocked before a valid investigation path could be approved.</div>';
      $('brief-mitre').innerHTML = '<div class="brief-body muted">ATT&CK framing is hidden for blocked requests. Start with the policy reason and refine the question into an allowed investigation path.</div>';
      $('summary').innerHTML = '<div class="brief-body"><strong>The request was blocked before execution.</strong><br>' + esc(String(result?.guardrail_reason || result?.final_adjudication?.validation_reason || 'The final query did not pass deterministic validation.')) + '<br><br><strong>Suggested next step:</strong> tighten the question around supported indexes, sources, or sourcetypes and run it again.</div>';
      $('tdir-card').style.display = 'none';
      $('tdir-case').textContent = '';
      $('journey').textContent = 'This request did not become an investigation because policy blocked the final execution path.';
      setSplVisibility(false);
      syncDrawerMirrors();
      const preferredTab = drawerPreferredTab(result);
      setActiveTrayTab(preferredTab, { openDrawer: false });
      markDrawerUpdate(preferredTab, preferredTab === 'review' ? 'New blocked-case trace is ready' : 'New drawer details are ready');
    }

    function mitreTone(tactic){
      const value = String(tactic || '').toLowerCase().trim();
      if(value.includes('discovery')) return 'mitre-tone-discovery';
      if(value.includes('credential')) return 'mitre-tone-credential-access';
      if(value.includes('execution')) return 'mitre-tone-execution';
      if(value.includes('defense evasion')) return 'mitre-tone-defense-evasion';
      if(value.includes('collection')) return 'mitre-tone-collection';
      if(value.includes('command and control')) return 'mitre-tone-command-and-control';
      return 'mitre-tone-default';
    }

    function renderMitreBrief(result) {
      const bundle = (result?.mitre_attack && typeof result.mitre_attack === 'object') ? result.mitre_attack : {};
      const items = Array.isArray(bundle?.techniques) ? bundle.techniques : [];
      const progression = Array.isArray(bundle?.possible_progression) ? bundle.possible_progression : [];
      const validation = (bundle?.validation && typeof bundle.validation === 'object') ? bundle.validation : {};
      const frame = String(bundle?.frame || '').trim();
      $('brief-mitre').innerHTML = items.length
        ? `
          ${frame ? `<div class="mitre-card"><div class="mitre-copy">${esc(frame)}</div></div>` : ''}
          ${items.map((item) => `
            <div class="mitre-card ${mitreTone(item.tactic)}">
              <div class="mitre-head">
                <div class="mitre-title">${esc(item.technique || 'Technique')}</div>
                <div class="mitre-tip" tabindex="0">?
                  <div class="mitre-tip-panel">
                    <div class="mitre-tip-line"><strong>${esc(item.technique || 'Technique')}</strong> (${esc(item.technique_id || '')})</div>
                    <div class="mitre-tip-line"><strong>Tactic:</strong> ${esc(item.tactic || 'Unknown')}</div>
                    <div class="mitre-tip-line"><strong>Definition:</strong> ${esc(item.definition || 'No definition available yet.')}</div>
                    <div class="mitre-tip-line"><strong>Why mapped here:</strong> ${esc(item.rationale || 'No rationale available yet.')}</div>
                  </div>
                </div>
              </div>
              <div class="mitre-meta">${esc(item.technique_id || '')} • ${esc(item.tactic || 'Tactic')} • ${esc(item.confidence || 'medium')} confidence</div>
              <div class="mitre-copy">${esc(item.rationale || '')}</div>
            </div>
          `).join('')}
          ${validation.status === 'ok' ? `<div class="mitre-card"><div class="mitre-title">ATT&CK Validation</div><div class="mitre-meta">${esc(validation.agreement || 'partial')} • ${esc(validation.confidence || 'medium')} confidence • ${esc(validation.model || '')}</div><div class="mitre-copy">${esc(validation.rationale || 'The security reasoning model reviewed the ATT&CK mapping and found it directionally sound.')}</div>${validation.kill_chain_context ? `<div class="mitre-copy" style="margin-top:8px;"><strong>Kill-chain context:</strong> ${esc(validation.kill_chain_context)}</div>` : ''}${Array.isArray(validation.alternate_techniques) && validation.alternate_techniques.length ? `<div class="mitre-copy" style="margin-top:8px;"><strong>Alternates considered:</strong><br/>${validation.alternate_techniques.map((item) => `• ${esc(item.technique_id || '')} ${esc(item.technique || '')}: ${esc(item.why || '')}`).join('<br/>')}</div>` : ''}</div>` : ''}
          ${progression.length ? `<div class="mitre-card"><div class="mitre-title">Likely Follow-On Techniques</div><div class="mitre-copy">${progression.map((item) => `• ${esc(item.technique_id || '')} ${esc(item.technique || '')}: ${esc(item.why || '')}`).join('<br/>')}</div></div>` : ''}
        `
        : '<div class="brief-body muted">No ATT&CK mapping was derived for this investigation yet.</div>';
    }

    window.__splAssetManifest = window.__splAssetManifest || [];

    function assetFamilyForIntent(intent) {
      const value = String(intent || '').trim().toLowerCase();
      const families = {
        failed_login_activity: ['failed_login_activity', 'linux_auth_failures', 'windows_auth_failures', 'failed', 'login', 'auth'],
        linux_auth_failures: ['failed_login_activity', 'linux_auth_failures', 'linux', 'auth', 'failed', 'login'],
        windows_auth_failures: ['failed_login_activity', 'windows_auth_failures', 'windows', 'auth', 'failed', 'login'],
        apache_access_top_ips: ['apache_access_top_ips', 'apache', 'access', 'clientip', 'web'],
        aws_cloudtrail_activity: ['aws_cloudtrail_activity', 'cloudtrail', 'aws', 'discovery'],
      };
      return families[value] || [value];
    }

    function matchingActiveAssetsForResult(result) {
      const direct = Array.isArray(result?.matching_active_spl_assets) ? result.matching_active_spl_assets : [];
      if (direct.length) return direct;
      const manifest = Array.isArray(window.__splAssetManifest) ? window.__splAssetManifest : [];
      const family = new Set(assetFamilyForIntent(result?.intent));
      return manifest.filter((row) => {
        const rowIntent = String(row?.intent || '').trim().toLowerCase();
        const tokens = Array.isArray(row?.match_tokens) ? row.match_tokens.map((item) => String(item || '').trim().toLowerCase()) : [];
        if (family.has(rowIntent)) return true;
        return tokens.some((token) => family.has(token));
      }).slice(0, 3);
    }

    async function loadSplAssetManifest() {
      try {
        const resp = await fetch('/api/config/local-learning');
        const data = await resp.json();
        const records = data?.local_learning?.repository?.records;
        window.__splAssetManifest = Array.isArray(records) ? records : [];
      } catch (_) {
        window.__splAssetManifest = [];
      }
    }

    function renderDecisionSupportSummary(result) {
      const reviewer = result?.security_reviewer_output || result?.security_reviewer?.output || {};
      const evidenceReviewer = result?.evidence_reviewer_output || result?.evidence_reviewer?.output || {};
      const continuationReviewer = result?.continuation_reviewer_output || result?.continuation_reviewer?.output || {};
      const adjudication = result?.final_adjudication || {};
      const items = [
        ['Plan confidence', result?.final_confidence || result?.selected_confidence || reviewer.confidence || 'n/a'],
        ['Query safety', reviewer.approved === false ? 'Needs review' : 'Approved'],
        ['Evidence quality', evidenceReviewer.evidence_quality || evidenceReviewer.confidence || 'n/a'],
        ['Final adjudication', adjudication.validation_ok === false ? 'Blocked' : (adjudication.selected_tool || result?.selected_tool || 'Complete')],
        ['Continuation', continuationReviewer.should_continue === true ? 'Recommended' : 'Not recommended'],
      ];
      const matchingAssets = matchingActiveAssetsForResult(result);
      if (matchingAssets.length) {
        const match = matchingAssets[0] || {};
        const assetLabel = match?.use_when || match?.intent || 'Matched local SPL asset';
        items.push(['Active SPL asset', assetLabel]);
      }
      $('decision-support-summary').innerHTML = items.map(([label, value]) => `
        <div class="support-item">
          <div class="support-label">${esc(label)}</div>
          <div class="support-value">${esc(String(value))}</div>
        </div>
      `).join('');
    }

    function renderSplunkTimeline(result, coverage, analystSummary) {
      const tdir = result?.tdir_case || {};
      const phase = tdir.phase_status || {};
      const rows = Number(result?.rows_returned || 0);
      const intent = result?.intent || 'unknown';
      const tool = result?.selected_tool || result?.final_adjudication?.selected_tool || 'unknown';
      const phases = [
        ['Detect', result?.supported === false ? 'blocked' : 'complete', `Question classified as ${intent}.`, 'Accepted the analyst question and selected a bounded Splunk investigation path.', result?.supported === false ? 'The request was blocked by policy or guardrails.' : 'The case was accepted for investigation.'],
        ['Triage', phase.triage || 'complete', `Splunk search path selected with ${coverage.indexes.length || 0} index target(s) and ${coverage.sourcetypes.length || 0} sourcetype hint(s).`, `Executed ${tool} to gather initial evidence.`, rows > 0 ? `${rows} row(s) of evidence were returned for first-pass triage.` : 'No matching evidence was returned for initial triage.'],
        ['Investigate', rows > 0 ? (phase.investigate || 'complete') : 'no_evidence', analystSummary || 'No analyst summary available yet.', `Reviewed the SPL logic and evidence coverage across ${coverage.platforms.join(', ') || 'the targeted sources'}.`, rows > 0 ? 'Evidence was reviewed and follow-on pivots were generated.' : 'The investigation completed without matching evidence, so no deeper case narrative was produced.'],
        ['Respond', phase.respond || 'planned', 'Read-only phase. No containment or response action is executed by default.', 'Surface analyst follow-up pivots only.', 'Response remains planned unless explicitly enabled later.'],
        ['Recover', phase.recover || 'planned', 'Recovery automation is not active in this phase.', 'Preserve investigation context and recommended next moves.', 'Recovery remains future-state for this bounded investigation mode.'],
      ];
      $('investigation-timeline').innerHTML = phases.map((item, idx) => `
        <details class="timeline-phase"${idx < 3 ? ' open' : ''}>
          <summary>
            <div class="timeline-phase-main">
              <div class="timeline-phase-name">${esc(item[0])}</div>
              <div class="timeline-phase-summary">${esc(item[4])}</div>
            </div>
            <div class="timeline-phase-status">${esc(String(item[1]).replaceAll('_', ' '))}</div>
          </summary>
          <div class="timeline-phase-body">
            <div class="timeline-detail-grid">
              <div class="timeline-detail"><div class="timeline-detail-title">Key Evidence</div><div class="timeline-detail-copy">${esc(item[2])}</div></div>
              <div class="timeline-detail"><div class="timeline-detail-title">Relevant Splunk Action</div><div class="timeline-detail-copy">${esc(item[3])}</div></div>
              <div class="timeline-detail"><div class="timeline-detail-title">Analyst-Facing Conclusion</div><div class="timeline-detail-copy">${esc(item[4])}</div></div>
            </div>
          </div>
        </details>
      `).join('');
    }

    function summarizeSplIntent(result, coverage) {
      const indexes = coverage.indexes.length ? coverage.indexes.join(', ') : 'the selected indexes';
      const sourcetypes = coverage.sourcetypes.length ? coverage.sourcetypes.join(', ') : 'available sourcetypes';
      const sources = coverage.rawSources.length ? coverage.rawSources.join(', ') : 'the discovered sources';
      const logic = String(result?.search_strategy_summary || result?.intent_summary || 'The search used the selected Splunk evidence path to confirm or disprove the analyst question.');
      return `
        <strong>What the search did:</strong> ${esc(logic)}<br><br>
        <strong>Data sources queried:</strong> indexes=${esc(indexes)} | sourcetypes=${esc(sourcetypes)} | sources=${esc(sources)}<br><br>
        <strong>What it was testing:</strong> ${esc(String(result?.question || result?.root_question || 'The analyst question'))}<br><br>
        <strong>Coverage:</strong> ${esc(coverage.coverageStatus)}${coverage.crossPlatform ? ' with cross-platform scope.' : '.'}
      `;
    }

    function renderSplEvidence(result, coverage, spl, latestRun) {
      const runtime = latestRun?.execution_ms ? `${latestRun.execution_ms} ms` : 'n/a';
      const rows = String(result?.rows_returned ?? latestRun?.rows_returned ?? 'n/a');
      const tool = result?.selected_tool || result?.final_adjudication?.selected_tool || 'unknown';
      const windowLabel = `${String(result?.query_args?.earliest_time || result?.final_adjudication?.selected_args?.earliest_time || '-24h')} -> ${String(result?.query_args?.latest_time || result?.final_adjudication?.selected_args?.latest_time || 'now')}`;
      const splLink = $('spl-link');
      $('spl-meta-strip').innerHTML = [
        ['Runtime', runtime],
        ['Rows returned', rows],
        ['Execution tool', tool],
        ['Data sources', coverage.sourcetypes.length ? coverage.sourcetypes.join(', ') : (coverage.indexes.join(', ') || 'n/a')],
        ['Time window', windowLabel],
        ['Coverage', coverage.coverageStatus || 'Unknown'],
      ].map(([label, value]) => `
        <div class="brief-metric">
          <div class="brief-metric-label">${esc(label)}</div>
          <div class="brief-metric-value">${esc(String(value))}</div>
        </div>
      `).join('');
      $('spl-analyst-summary').innerHTML = summarizeSplIntent(result, coverage);
      $('spl-query').textContent = spl || '(No Splunk query was captured for this path)';
      $('copy-spl').style.display = spl ? 'inline-flex' : 'none';
      $('brief-supported').textContent = result?.supported === false ? 'Blocked' : ((result?.rows_returned === 0) ? 'No Hits' : 'Complete');
      if (spl) {
        const earliest =
          String(
            result?.query_args?.earliest_time ||
            result?.final_adjudication?.selected_args?.earliest_time ||
            result?.evidence?.time_window?.earliest_time ||
            '-24h@h'
          );
        const latest =
          String(
            result?.query_args?.latest_time ||
            result?.final_adjudication?.selected_args?.latest_time ||
            result?.evidence?.time_window?.latest_time ||
            'now'
          );
        const splunkBase = String(result?.splunk_search_url_base || '');
        const params = new URLSearchParams({
          q: spl,
          'display.page.search.mode': 'smart',
          'dispatch.sample_ratio': '1',
          workload_pool: '',
          earliest,
          latest,
          'display.page.search.tab': 'statistics',
          'display.general.type': 'statistics',
        });
        if (splunkBase) {
          splLink.href = `${splunkBase}?${params.toString()}`;
          splLink.style.display = 'inline';
        } else {
          splLink.href = '#';
          splLink.style.display = 'none';
        }
      } else {
        splLink.href = '#';
        splLink.style.display = 'none';
      }
    }

    function renderCoverageVisibility(result, coverage) {
      const rows = Number(result?.rows_returned || 0);
      const noGapText = 'No explicit telemetry gap was called out in the returned result.';
      const mismatchNote = investigationOutcomeNote(result);
      const items = [
        ['Platforms and indexes searched', `${coverage.platforms.length ? coverage.platforms.join(', ') : 'Not derived'} | ${coverage.indexes.length ? coverage.indexes.join(', ') : 'No explicit index extracted'}`],
        ['Sourcetypes and source paths', `${coverage.sourcetypes.length ? coverage.sourcetypes.join(', ') : 'Not derived'} | ${coverage.rawSources.length ? coverage.rawSources.join(', ') : 'No explicit source path extracted'}`],
        ['Evidence return and coverage status', `${rows > 0 ? 'Evidence rows were returned.' : 'No rows were returned for the expected sources in this window.'} ${coverage.coverageStatus || 'Unknown'}${mismatchNote ? ` ${mismatchNote}` : ''}`],
        ['Visibility gaps and follow-up checks', coverage.gaps.length ? coverage.gaps.join(' ') : noGapText],
      ];
      $('coverage-visibility').innerHTML = items.map(([label, value]) => `
        <div class="coverage-row${label === 'Visibility gaps and follow-up checks' && String(value) !== noGapText ? ' gap' : ''}">
          <div class="coverage-row-title">${esc(label)}</div>
          <div class="coverage-row-copy">${esc(String(value))}</div>
        </div>
      `).join('');
    }

    function classifyPivot(pivotText) {
      const text = String(pivotText || '').trim();
      const lower = text.toLowerCase();
      let entity = 'Derived field';
      if (lower.includes('source ip')) entity = 'Source IP';
      else if (lower.includes('username') || lower.includes('user ')) entity = 'Username';
      else if (lower.includes('host')) entity = 'Host';
      else if (lower.includes('sourcetype')) entity = 'Sourcetype';
      else if (lower.includes('index')) entity = 'Index inventory';
      const why = lower.includes('validate visibility')
        ? 'Validates whether Splunk has the expected telemetry depth before making a stronger claim.'
        : 'Extends the investigation using the highest-value Splunk pivot from the current evidence.';
      const scope = lower.includes('across linux and windows') || lower.includes('cross-platform')
        ? 'Cross-platform'
        : (lower.includes('across') ? 'Broad pivot' : 'Focused pivot');
      const expected = lower.includes('successful')
        ? 'Confirms whether failed access progressed to successful access.'
        : lower.includes('privilege escalation')
          ? 'Tests whether the activity progressed beyond initial access into higher-risk behavior.'
          : 'Expands the evidence set around the most important entity from the current case.';
      return { why, entity, expected, scope, title: text.length > 72 ? `${text.slice(0, 72).trim()}...` : text };
    }

    function pivotPresentation(candidate) {
      const meta = classifyPivot(candidate?.title || candidate?.text || '');
      const targetValues = Array.isArray(candidate?.target_values)
        ? candidate.target_values.map((item) => String(item || '').trim()).filter(Boolean)
        : [];
      const targetRankings = Array.isArray(candidate?.target_rankings)
        ? candidate.target_rankings.filter((item) => item && typeof item === 'object')
        : [];
      const targetLabel = String(candidate?.target_label || meta.entity || 'Derived field');
      const targetDisplay = targetValues.length
        ? `${targetLabel}: ${targetValues.slice(0, 3).join(', ')}`
        : targetLabel;
      const provenanceText = String(candidate?.provenance?.explanation || '').trim();
      const rankingText = targetRankings.length
        ? targetRankings.map((item) => `${String(item.value || '').trim()} (${Number(item.count || 0)})`).filter(Boolean).join(', ')
        : '';
      return {
        ...meta,
        title: String(candidate?.title || meta.title || '').trim() || meta.title,
        targetLabel,
        targetValues,
        targetDisplay,
        provenanceText,
        rankingText,
      };
    }

    function renderPivotCards(result) {
      if (result?.supported === false) {
        $('pivot-cards').innerHTML = '<div class="brief-body muted">Follow-up pivots are hidden because the request did not pass the guarded execution checks.</div>';
        return [];
      }
      const pivotCandidates = collectPivotCandidates(result);
      const primaryTechnique = Array.isArray(result?.mitre_attack?.techniques) && result.mitre_attack.techniques.length
        ? `${result.mitre_attack.techniques[0].technique || 'Technique'} (${result.mitre_attack.techniques[0].technique_id || ''})`.trim()
        : 'Splunk investigation follow-up';
      $('pivot-cards').innerHTML = pivotCandidates.length
        ? pivotCandidates.map((candidate, index) => {
            const meta = pivotPresentation(candidate);
            return `
              <div class="pivot-card">
                <div class="pivot-card-head">
                  <div>
                    <div class="pivot-card-kicker">Pivot ${String(index + 1)}</div>
                    <div class="pivot-card-title">${esc(meta.title)}</div>
                  </div>
                </div>
                <div class="pivot-card-copy">${esc(String(candidate?.title || ''))}</div>
                <div class="pivot-meta-grid">
                  <div class="pivot-meta"><strong>Why this step matters</strong><span>${esc(meta.why)}</span></div>
                  <div class="pivot-meta"><strong>Follow-up target</strong><span><code>${esc(meta.targetDisplay)}</code></span></div>
                  ${meta.provenanceText ? `<div class="pivot-meta"><strong>Why this value</strong><span>${esc(meta.provenanceText)}</span></div>` : ''}
                  <div class="pivot-meta"><strong>Expected value</strong><span>${esc(meta.expected)}</span></div>
                  <div class="pivot-meta"><strong>Estimated scope</strong><span>${esc(meta.scope)}</span></div>
                </div>
                <div class="pivot-actions">
                  <button type="button" class="btn-secondary pivot-open-btn" data-pivot-index="${String(index)}">Open In Drawer</button>
                  <button type="button" class="btn-followup pivot-run-btn" data-pivot-index="${String(index)}">Run Pivot Now</button>
                </div>
              </div>
            `;
          }).join('')
        : '<div class="brief-body muted">No additional Splunk-grounded follow-up steps were derived for this investigation yet.</div>';
      document.querySelectorAll('.pivot-open-btn').forEach((btn) => {
        btn.onclick = () => {
          const idx = Number(btn.getAttribute('data-pivot-index') || '-1');
          const candidate = pivotCandidates[idx] || null;
          if (!candidate) return;
          selectFollowup(candidate, idx, primaryTechnique);
          $('status').textContent = 'Follow-up step opened in the left drawer. Review it there, then run when ready.';
          window.scrollTo({ top: 0, behavior: 'smooth' });
        };
      });
      document.querySelectorAll('.pivot-run-btn').forEach((btn) => {
        btn.onclick = async () => {
          const idx = Number(btn.getAttribute('data-pivot-index') || '-1');
          const candidate = pivotCandidates[idx] || null;
          if (!candidate) return;
          selectFollowup(candidate, idx, primaryTechnique);
          $('question').value = String(candidate?.next_question || candidate?.title || '');
          $('status').textContent = 'Running selected follow-up investigation...';
          window.scrollTo({ top: 0, behavior: 'smooth' });
          await executeInvestigation({
            question: String(candidate?.next_question || candidate?.title || ''),
            pivot_context: result?.pivot_context || null,
            pivot_candidate: candidate,
          });
        };
      });
      return pivotCandidates;
    }

    function hasEvidenceRows(result) {
      if (!result || typeof result !== 'object') return false;
      if (typeof result.rows_returned === 'number' && result.rows_returned > 0) return true;
      if (Array.isArray(result?.selected_spl_details) && result.selected_spl_details.some((row) => typeof row?.rows_returned === 'number' && row.rows_returned > 0)) return true;
      if (Array.isArray(result.__ui_sample_rows) && result.__ui_sample_rows.length) return true;
      if (Array.isArray(result.spl_results_preview) && result.spl_results_preview.length) return true;
      if (Array.isArray(result?.evidence?.top_entities) && result.evidence.top_entities.length) return true;
      if (String(result.summary || '').trim().startsWith('- **What was queried**')) return true;
      return false;
    }

    function renderNoEvidenceOutcome(result) {
      const latestRun = Array.isArray(result?.selected_spl_details) && result.selected_spl_details.length
        ? (result.selected_spl_details[result.selected_spl_details.length - 1] || {})
        : {};
      const spl = extractExecutedSPL(result || {});
      const coverage = extractCoverage(result || {}, spl);
      renderCaseHeader(result || {}, coverage, latestRun);
      renderSplEvidence(result || {}, coverage, spl, latestRun);
      renderCoverageVisibility(result || {}, coverage);
      renderDecisionSupportSummary(result || {});
      renderSplunkTimeline(result || {}, coverage, 'Splunk completed the query, but no rows matched the current time window and filters.');
      $('pivot-cards').innerHTML = '<div class="brief-body muted">No follow-up steps were generated because the completed Splunk search returned no matching evidence. Validate coverage, widen the time range, or refine the search scope.</div>';
      setSplVisibility(false);
      $('summary').innerHTML =
        '<div class="brief-body">' +
        '<strong>No matching evidence was returned.</strong><br>' +
        'Splunk completed the query, but no rows matched the selected time range and filters for this investigation.' +
        '<br><br><strong>Suggested next check:</strong> Widen the time window, verify the expected index/source assumptions, or try a narrower follow-up question.' +
        '</div>';
      $('brief-mitre').innerHTML =
        '<div class="brief-body muted">No ATT&CK mapping was produced because no evidence was returned for this completed investigation.</div>';
      $('tdir-card').style.display = 'none';
      $('tdir-case').textContent = '';
      $('journey').textContent = 'Investigation completed with no matching evidence rows. No ATT&CK classification or deeper pivot chain was produced.';
      renderPhaseStrip({
        detect: 'complete',
        triage: 'complete',
        investigate: 'no_evidence',
      });
      renderCaseTimeline(result || {});
      syncDrawerMirrors();
      {
        const preferredTab = drawerPreferredTab(result);
        setActiveTrayTab(preferredTab, { openDrawer: false });
        markDrawerUpdate(preferredTab, preferredTab === 'evidence' ? 'No-evidence outcome details are ready' : 'New drawer details are ready');
      }
    }

    function syncUtilityBarVisibility() {
      const row = document.querySelector('.workspace-utility-row');
      const chips = $('case-header-chips');
      if (!row || !chips) return;
      row.style.display = chips.textContent.trim() ? '' : 'none';
    }

    function renderModelDecisions(result) {
      if (!result || typeof result !== 'object') {
        $('model-personas').innerHTML = '';
        $('spl-query').textContent = '';
        $('spl-results').textContent = '';
        $('model-decisions').innerHTML = '';
        $('brief-mitre').innerHTML = '<div class="brief-body muted">No ATT&CK mapping was derived for this investigation yet.</div>';
        $('brief-supported').textContent = 'Idle';
        $('case-header-chips').innerHTML = '';
        $('spl-meta-strip').innerHTML = '';
        $('coverage-visibility').innerHTML = '';
        $('pivot-cards').innerHTML = '';
        $('decision-support-summary').innerHTML = '';
        $('investigation-timeline').innerHTML = '';
        renderCaseTimeline(null);
        syncUtilityBarVisibility();
        return;
      }
      const splRuns = Array.isArray(result?.selected_spl_details) ? result.selected_spl_details : [];
      const latestRun = splRuns.length ? (splRuns[splRuns.length - 1] || {}) : {};
      const spl = extractExecutedSPL(result);
      const coverage = extractCoverage(result, spl);
      if (result?.supported === false) {
        renderBlockedOutcome(result || {});
        renderCaseTimeline(result || {});
        $('model-personas').innerHTML = '';
        $('model-decisions').innerHTML = '';
        $('workflow-track').innerHTML = '';
        $('workflow-meta').textContent = '';
        clearContinuationControls();
        return;
      }
      renderCaseHeader(result, coverage, latestRun);
      renderMitreBrief(result);
      renderDecisionSupportSummary(result);
      renderSplEvidence(result, coverage, spl, latestRun);
      renderCoverageVisibility(result, coverage);
      renderPivotCards(result);
      renderSplunkTimeline(result, coverage, String(result?.summary || '').trim());
      renderCaseTimeline(result);
      renderPhaseStrip({
        detect: 'complete',
        triage: String(result?.tdir_case?.phase_status?.triage || 'complete'),
        investigate: String(result?.tdir_case?.phase_status?.investigate || (hasEvidenceRows(result) ? 'complete' : 'no_evidence')),
      });
      setSplVisibility(false);
      const outcomeNote = investigationOutcomeNote(result);
      if (outcomeNote) {
        $('summary').innerHTML =
          '<div class="brief-body"><strong>Returned rows did not confirm the requested activity.</strong><br>' +
          esc(outcomeNote) +
          '<br><br>' + renderSummaryText(result?.summary || '') + '</div>';
      }

      const workflow = Array.isArray(result.model_workflow) ? result.model_workflow : [];
      const workflowStagesPresent = new Set(
        workflow
          .map((step) => String((step && step.stage) || '').trim())
          .filter(Boolean)
      );
      const writer = result.query_writer_output || result.planner?.output || {};
      const reviewer = result.security_reviewer_output || result.security_reviewer?.output || {};
      const peer = result.peer_reviewer_decision || result.peer_reviewer?.output || {};
      const peer2 = result.peer_reviewer_2_decision || result.peer_reviewer_2?.output || {};
      const evidenceReviewer = result.evidence_reviewer_output || result.evidence_reviewer?.output || {};
      const continuationReviewer = result.continuation_reviewer_output || result.continuation_reviewer?.output || {};
      const hasContinuationReviewerData = Boolean(
        continuationReviewer &&
        typeof continuationReviewer === 'object' &&
        (
          continuationReviewer.should_continue !== undefined ||
          String(continuationReviewer.why || '').trim() ||
          String(continuationReviewer.next_best_question || '').trim() ||
          String(continuationReviewer.next_best_spl_or_tool || '').trim() ||
          continuationReviewer.confidence !== undefined ||
          String(continuationReviewer.expected_value_of_next_step || '').trim()
        )
      );
      const adjudication = result.final_adjudication || {};
      const repair = result.query_repair || {};

      const detailLines = [];
      const roleClassMap = {
        query_writer: 'planner',
        planner: 'planner',
        security_reviewer: 'reviewer',
        reviewer: 'reviewer',
        evidence_reviewer: 'reviewer',
        continuation_reviewer: 'reviewer',
        peer_reviewer: 'judge',
        peer_reviewer_1: 'judge',
        peer_reviewer_2: 'judge2',
        controller: 'policy',
        final_summary: 'policy',
        summary: 'policy',
        policy: 'policy'
      };
      const roleNameMap = {
        query_writer: 'SPL Writer',
        planner: 'Planner',
        security_reviewer: 'Security Reviewer',
        reviewer: 'Security Reviewer',
        evidence_reviewer: 'Evidence Reviewer',
        continuation_reviewer: 'Continuation Reviewer',
        peer_reviewer: 'Peer Reviewer 1',
        peer_reviewer_1: 'Peer Reviewer 1',
        peer_reviewer_2: 'Peer Reviewer 2',
        controller: 'Controller',
        final_summary: 'Summary',
        summary: 'Summary',
        policy: 'Policy'
      };
      const preferredRoleOrder = [
        'planner',
        'query_writer',
        'security_reviewer',
        'peer_reviewer',
        'peer_reviewer_1',
        'peer_reviewer_2',
        'evidence_reviewer',
        'continuation_reviewer',
        'controller',
        'final_summary',
        'summary',
      ];
      const roleTimingKeyMap = {
        query_writer: 'writer',
        planner: 'planner',
        security_reviewer: 'security_review',
        reviewer: 'security_review',
        peer_reviewer: 'peer_review_1',
        peer_reviewer_1: 'peer_review_1',
        peer_reviewer_2: 'peer_review_2',
        evidence_reviewer: 'evidence_review',
        continuation_reviewer: 'continuation_review',
        final_summary: 'summarize',
        summary: 'summarize',
      };
      const nodeTimings = (result && typeof result.node_timings_ms === 'object' && result.node_timings_ms) ? result.node_timings_ms : {};
      const workflowNormalized = [];
      for (const stage of preferredRoleOrder) {
        const hit = workflow.find((step) => String((step && step.stage) || '').trim() === stage);
        if (hit) workflowNormalized.push(hit);
      }
      for (const step of workflow) {
        const stage = String((step && step.stage) || '').trim();
        if (!stage) continue;
        if (!preferredRoleOrder.includes(stage)) workflowNormalized.push(step);
      }
      if (!workflowStagesPresent.has('evidence_reviewer') && (result.evidence_reviewer || result.evidence_reviewer_output)) {
        workflowNormalized.push({
          stage: 'evidence_reviewer',
          model: result.evidence_reviewer?.model || '',
          responsibility: 'Assesses evidence quality from executed query results.',
        });
      }
      if (!workflowStagesPresent.has('continuation_reviewer') && (result.continuation_reviewer || result.continuation_reviewer_output)) {
        workflowNormalized.push({
          stage: 'continuation_reviewer',
          model: result.continuation_reviewer?.model || '',
          responsibility: 'Decides if the investigation should continue and proposes the next best pivot.',
        });
      }
      const workflowHtml = [];
      for (const step of workflowNormalized) {
        const stage = String(step.stage || '');
        const model = String(step.model || '');
        const responsibility = String(step.responsibility || '');
        const roleClass = roleClassMap[stage] || 'policy';
        const roleLabel = roleNameMap[stage] || stage || 'Role';
        const respText = responsibility ? ` - ${responsibility}` : '';
        const timingKey = roleTimingKeyMap[stage];
        const timingValue = timingKey ? nodeTimings[timingKey] : null;
        const timingText = timingValue !== null && timingValue !== undefined ? ` (duration=${fmtMs(timingValue)})` : '';
        workflowHtml.push(
          `<div class="role-line ${esc(roleClass)}"><strong>${esc(roleLabel)}:</strong> <span class="role-model">${esc(model || 'not recorded')}</span>${esc(respText)}${esc(timingText)}</div>`
        );
      }

      detailLines.push(`query_writer selected_tool=${writer.selected_tool || ''} intent=${writer.intent || ''} confidence=${writer.confidence ?? ''}`);
      detailLines.push(`planner intent=${result.planner?.output?.intent || ''} strategy=${result.search_strategy_summary || ''} confidence=${result.planner?.output?.confidence ?? ''}`);
      detailLines.push(`security_reviewer approved=${reviewer.approved ?? ''} confidence=${reviewer.confidence ?? ''} revised_tool=${reviewer.revised_selected_tool || ''}`);
      detailLines.push(`peer_reviewer_1 winner=${peer.winner || ''} confidence=${peer.confidence ?? ''}`);
      detailLines.push(`peer_reviewer_2 winner=${peer2.winner || ''} confidence=${peer2.confidence ?? ''} agrees_with_peer1=${peer2.agrees_with_peer1 ?? ''}`);
      detailLines.push(`evidence_reviewer confidence=${fmtValue(evidenceReviewer.confidence)} quality=${fmtValue(evidenceReviewer.evidence_quality)} recommendation=${fmtValue(evidenceReviewer.recommendation)}`);
      if (hasContinuationReviewerData) {
        detailLines.push(`continuation_reviewer should_continue=${fmtValue(continuationReviewer.should_continue)} confidence=${fmtValue(continuationReviewer.confidence)} next_best_question=${fmtValue(continuationReviewer.next_best_question)}`);
      }
      const hasRepairDetails = Boolean(
        repair && typeof repair === 'object' && (
          repair.ok === true ||
          String(repair.repair_reason || '').trim() ||
          String(repair.validation_reason || '').trim() ||
          String(repair.model || '').trim()
        )
      );
      if (hasRepairDetails) {
        detailLines.push(`query_repair applied=${repair.ok ?? false} model=${repair.model || ''} reason=${repair.repair_reason || ''}`);
      }
      detailLines.push(`final_adjudication tool=${adjudication.selected_tool || ''} intent=${adjudication.selected_intent || ''} validation=${adjudication.validation_ok ?? ''} reason=${adjudication.validation_reason || ''}`);

      const personas = [
        {
          cls: 'planner',
          name: 'Planner',
          role: 'Builds the structured search plan before SPL generation.',
          model: result.planner?.model || '',
          detail: `tool=${result.planner?.output?.selected_tool || ''}\nintent=${result.planner?.output?.intent || ''}\nconfidence=${result.planner?.output?.confidence ?? ''}`,
          badge: 'Planner'
        },
        {
          cls: 'planner',
          name: 'SPL Writer',
          role: 'Turns the plan into bounded read-only SPL.',
          model: result.writer?.model || '',
          detail: `tool=${writer.selected_tool || ''}\nintent=${writer.intent || ''}\nconfidence=${writer.confidence ?? ''}`,
          badge: 'Writer'
        },
        {
          cls: 'reviewer',
          name: 'Security Reviewer',
          role: 'Critiques quality and safety.',
          model: result.security_reviewer?.model || '',
          detail: `approved=${reviewer.approved ?? ''}\nconfidence=${reviewer.confidence ?? ''}\nrevised_tool=${reviewer.revised_selected_tool || ''}`,
          badge: 'Reviewer'
        },
        {
          cls: 'judge',
          name: 'Peer Reviewer 1',
          role: 'Adjudicates writer vs reviewer winner.',
          model: result.peer_reviewer?.model || '',
          detail: `winner=${peer.winner || ''}\nconfidence=${peer.confidence ?? ''}`,
          badge: 'Judge-1'
        },
        {
          cls: 'judge2',
          name: 'Peer Reviewer 2',
          role: 'Validates or overrides peer reviewer 1.',
          model: result.peer_reviewer_2?.model || '',
          detail: `winner=${peer2.winner || ''}\nconfidence=${peer2.confidence ?? ''}\nagrees_with_peer1=${peer2.agrees_with_peer1 ?? ''}`,
          badge: 'Judge-2'
        },
        {
          cls: 'reviewer',
          name: 'Evidence Reviewer',
          role: 'Assesses evidence quality from executed query results.',
          model: result.evidence_reviewer?.model || '',
          detail: `confidence=${fmtValue(evidenceReviewer.confidence)}\nquality=${fmtValue(evidenceReviewer.evidence_quality)}\nrecommendation=${compactValue(evidenceReviewer.recommendation)}`,
          badge: 'Evidence'
        },
        {
          cls: 'policy',
          name: 'Final Adjudication',
          role: 'Deterministic gate + selected execution plan.',
          model: '',
          detail: `tool=${adjudication.selected_tool || result.selected_tool || ''}\nintent=${adjudication.selected_intent || result.intent || ''}\nvalidation=${adjudication.validation_ok ?? ''}`,
          badge: 'Policy'
        }
      ];
      if (hasRepairDetails) {
        personas.splice(4, 0, {
          cls: 'policy',
          name: 'Query Repair',
          role: 'One-pass repair when environment validation fails.',
          model: repair.model || '',
          detail: `applied=${repair.ok ?? false}\nreason=${repair.repair_reason || ''}\nvalidation=${repair.validation_reason || ''}`,
          badge: 'Repair'
        });
      }
      if (hasContinuationReviewerData) {
        personas.splice(hasRepairDetails ? 6 : 5, 0, {
          cls: 'reviewer',
          name: 'Continuation Reviewer',
          role: 'Decides whether to continue the investigation and what pivot adds the most value.',
          model: result.continuation_reviewer?.model || '',
          detail: `should_continue=${fmtValue(continuationReviewer.should_continue)}\nconfidence=${fmtValue(continuationReviewer.confidence)}\nwhy=${compactValue(continuationReviewer.why)}\nnext_question=${compactValue(continuationReviewer.next_best_question)}`,
          badge: 'Continue'
        });
      }
      function shortenModelName(model) {
        const text = String(model || '').trim();
        if (!text) return 'not recorded';
        return text.length > 52 ? `${text.slice(0, 52).trim()}...` : text;
      }

      function modelChoiceReason(persona) {
        const name = String(persona?.name || '').toLowerCase();
        if (name.includes('planner')) return 'Higher-context reasoning before any bounded SPL is generated.';
        if (name.includes('writer')) return 'Structured query synthesis for Splunk-safe read-only execution.';
        if (name.includes('security reviewer')) return 'Second-pass safety and quality critique before execution.';
        if (name.includes('peer reviewer')) return 'Adjudication role used when multiple model outputs must be compared.';
        if (name.includes('evidence reviewer')) return 'Post-query evidence assessment to judge strength and actionability.';
        if (name.includes('final adjudication')) return 'Deterministic policy gate, not a model preference.';
        if (name.includes('continuation reviewer')) return 'Selects the highest-value next pivot before another bounded round.';
        if (name.includes('query repair')) return 'Used only when one bounded repair pass is justified.';
        return 'Selected for this stage of the investigation pipeline.';
      }

      function summarizePersonaOutcome(detail) {
        const lines = String(detail || '').split('\\n').map((line) => line.trim()).filter(Boolean);
        if (!lines.length) return 'No recorded output.';
        return lines.slice(0, 2).join(' | ');
      }

      $('model-personas').innerHTML = personas.map((p, idx) =>
        `${idx ? '<div class="persona-arrow" aria-hidden="true">&rarr;</div>' : ''}<div class="persona ${esc(p.cls)}">
          <div class="p-head"><span class="p-name">${esc(p.name)}</span><span class="pill">${esc(p.badge)}</span></div>
          <div class="p-role">${esc(p.role)}</div>
          <div class="p-model">${esc(shortenModelName(p.model))}</div>
          <div class="p-detail">
            <div class="p-why"><div class="p-mini-label">Why this model</div>${esc(modelChoiceReason(p))}</div>
            <div class="p-outcome"><div class="p-mini-label">Stage output</div>${esc(summarizePersonaOutcome(p.detail))}</div>
          </div>
        </div>`
      ).join('');

      const previewRowsRaw =
        (Array.isArray(result?.__ui_sample_rows) && result.__ui_sample_rows.length
          ? result.__ui_sample_rows
          : (
            Array.isArray(result?.spl_results_preview) && result.spl_results_preview.length
              ? result.spl_results_preview
              : (
                Array.isArray(result?.evidence?.top_entities)
                  ? result.evidence.top_entities
                  : []
              )
          ));
      const previewRows = previewRowsRaw.filter((row) => row && typeof row === 'object').slice(0, 50);
      const latestRowsReturned = latestRun.rows_returned;
      const resultRowsReturned = typeof result?.rows_returned === 'number'
        ? result.rows_returned
        : (typeof latestRowsReturned === 'number' ? latestRowsReturned : null);
      $('spl-results').textContent = previewRows.length
        ? JSON.stringify(previewRows, null, 2)
        : (
          resultRowsReturned === 0
            ? '(This SPL returned 0 rows for the selected time range and filters)'
            : (
              (resultRowsReturned ?? 0) > 0
                ? `(This SPL returned ${String(resultRowsReturned)} row(s), but no preview rows were captured for this run)`
                : '(No SPL result rows were captured for this run)'
            )
        );
      const detailHtml = esc(detailLines.join('\\n')).replaceAll('\\n', '<br>');
      $('model-decisions').innerHTML =
        `${workflowHtml.length ? `<div class="decision-subhead">Pipeline Roles</div>${workflowHtml.join('')}` : ''}` +
        `${detailHtml ? `<div class="decision-subhead">Key Outputs</div>${detailHtml}` : ''}`;
      syncDrawerMirrors();
      {
        const preferredTab = drawerPreferredTab(result);
        setActiveTrayTab(preferredTab, { openDrawer: false });
        markDrawerUpdate(preferredTab, preferredTab === 'pivot' ? 'New pivots and evidence are ready' : 'New drawer details are ready');
      }
    }

    function renderInvestigationJourney(result) {
      if (!result || typeof result !== 'object') {
        $('journey').textContent = '';
        return;
      }
      const tdir = result.tdir_case || {};
      const phase = tdir.phase_status || {};
      const pivots = Array.isArray(tdir.recommended_next_pivots) ? tdir.recommended_next_pivots : [];
      const continuation = tdir.continuation_review || result.continuation_reviewer_output || {};
      const loop = tdir.loop_control || result.loop_control || {};
      const decisionLog = Array.isArray(result.decision_log) ? result.decision_log : [];
      const tool = result.selected_tool || tdir.selected_tool || 'n/a';
      const rows = result.rows_returned ?? tdir.rows_returned ?? 'n/a';
      const intent = result.intent || tdir.intent || 'n/a';

      const lines = [];
      lines.push(`1) Detect`);
      lines.push(`- Question accepted and classified as intent: ${intent}`);
      lines.push(`- Guardrails/policy outcome: ${result.supported === false ? 'blocked' : 'supported'}${result.guardrail_reason ? ` (${result.guardrail_reason})` : ''}`);
      lines.push('');
      lines.push(`2) Triage`);
      lines.push(`- Tool path selected: ${tool}`);
      lines.push(`- Query evidence returned rows: ${rows}`);
      lines.push(`- Triage status: ${phase.triage || 'in_progress'}`);
      lines.push('');
      lines.push(`3) Investigate`);
      lines.push(`- Investigation status: ${phase.investigate || 'in_progress'}`);
      lines.push(`- Analyst hypothesis: ${tdir.incident_hypothesis || result.summary || 'No hypothesis provided.'}`);
      lines.push(`- Continuation reviewer: should_continue=${fmtValue(continuation.should_continue)} confidence=${fmtValue(continuation.confidence)}`);
      if (loop.human_approval_required) lines.push(`- Loop control: waiting for analyst approval before another deeper investigation round.`);
      else if (loop.auto_followup_executed) lines.push(`- Loop control: one bounded deeper-investigation round already executed automatically.`);
      else if (loop.stop_reason) lines.push(`- Loop control: ${loop.stop_reason}`);
      if (continuation.why) lines.push(`- Why: ${continuation.why}`);
      if (continuation.next_best_question) lines.push(`- Next best question: ${continuation.next_best_question}`);
      if (continuation.next_best_spl_or_tool) lines.push(`- Next best SPL/tool: ${continuation.next_best_spl_or_tool}`);
      if (pivots.length) {
        lines.push(`- Suggested pivots:`);
        for (const p of pivots.slice(0, 5)) lines.push(`  - ${p}`);
      }
      lines.push('');
      lines.push(`Future: Respond (R)`);
      lines.push(`- Not automated yet in this lab. Future R phase will apply approved containment/response playbooks and SOAR actions.`);
      if (decisionLog.length) {
        lines.push('');
        lines.push('Decision trail (condensed)');
        for (const d of decisionLog.slice(0, 8)) {
          const node = d.node || 'node';
          const reason = d.reason || d.decision || d.selected_tool || '';
          lines.push(`- ${node}: ${reason}`);
        }
      }
      $('journey').textContent = lines.join('\\n');
    }

    function fmtMs(ms) {
      const n = Number(ms || 0);
      if (!Number.isFinite(n) || n <= 0) return 'n/a';
      if (n < 1000) return `${Math.round(n)} ms`;
      return `${(n / 1000).toFixed(2)} s`;
    }

    function renderSummaryText(text) {
      let raw = String(text || '').trim();
      if (!raw.trim()) return '';
      raw = raw.replace(/^Here's a concise summary of the query results in plain English:\\s*/i, '');
      raw = raw.replace(/^Based on the query result:\\s*/i, '');
      raw = raw.replace(/^\\*\\s*What was queried:/i, 'What was queried:');
      let html = esc(raw);
      html = html.replace(/\\*\\*(.+?)\\*\\*/g, '<strong>$1</strong>');
      html = html.replace(/^\\*\\s+/gm, '&#8226; ');
      html = html.replace(
        /(Top findings(?: from the query results)?(?: show that)?)/gi,
        '<span class="summary-lead">$1</span>'
      );
      return html.replace(/\\n/g, '<br>');
    }

    function renderWorkflowTimeline(result) {
      const track = $('workflow-track');
      const meta = $('workflow-meta');
      if (!track || !meta) return;
      track.innerHTML = '';
      meta.textContent = '';
      if (!result || typeof result !== 'object') return;

      const tdir = result?.tdir_case || {};
      const phase = tdir?.phase_status || {};
      const timings = result?.stage_timings_ms || {};
      const nodes = [
        { key: 'detect', label: 'Detect' },
        { key: 'triage', label: 'Triage' },
        { key: 'investigate', label: 'Investigate' },
        { key: 'respond', label: 'Respond' },
        { key: 'recover', label: 'Recover' },
      ];

      const html = [];
      nodes.forEach((node, idx) => {
        const status = String(phase[node.key] || 'planned');
        const ms = timings[node.key];
        html.push(
          `<div class="flow-node ${esc(status)}">` +
          `<div class="n-title">${esc(node.label)}</div>` +
          `<div class="n-status">status=${esc(status)}</div>` +
          `<div class="n-time">duration=${esc(fmtMs(ms))}</div>` +
          `</div>`
        );
        if (idx < nodes.length - 1) html.push('<div class="flow-arrow">&rarr;</div>');
      });
      track.innerHTML = html.join('');

      const total = fmtMs(timings.total);
      const pipeline = String(result.pipeline || tdir.pipeline || 'unknown');
      const roleTimingLabels = [
        ['query_writer', 'planner'],
        ['security_reviewer', 'security_review'],
        ['peer_reviewer_1', 'peer_review_1'],
        ['peer_reviewer_2', 'peer_review_2'],
        ['evidence_reviewer', 'evidence_review'],
        ['continuation_reviewer', 'continuation_review'],
        ['summary', 'summarize'],
      ];
      const roleJourney = roleTimingLabels
        .filter((entry) => entry[1] in timings || entry[1] in (result.node_timings_ms || {}))
        .map((entry) => {
          const stage = entry[0];
          const key = entry[1];
          const ms = (result.node_timings_ms || {})[key];
          return `${stage}=${fmtMs(ms)}`;
        })
        .join(' | ');
      meta.textContent = roleJourney
        ? `pipeline=${pipeline} total=${total}\nroles: ${roleJourney}`
        : `pipeline=${pipeline} total=${total}`;
    }

    function setSplVisibility(showRaw) {
      const rawShell = $('spl-raw-shell');
      const toolbarToggle = $('spl-visibility-toggle');
      const drawerToggle = $('drawer-spl-toggle');
      rawShell.classList.toggle('open', !!showRaw);
      if (toolbarToggle) toolbarToggle.textContent = showRaw ? 'Hide SPL Executed' : 'Show SPL Executed';
      if (drawerToggle) drawerToggle.textContent = showRaw ? 'Hide SPL Executed' : 'Show SPL Executed';
      $('copy-spl').style.display = showRaw && $('spl-query').textContent ? 'inline-flex' : 'none';
    }

    function bindSplToggleButtons() {
      const handler = () => {
        const rawShell = $('spl-raw-shell');
        setSplVisibility(!rawShell.classList.contains('open'));
      };
      const toolbarToggle = $('spl-visibility-toggle');
      if (toolbarToggle) toolbarToggle.onclick = handler;
    }

    function bindAdvancedSummaryControls() {
      const summary = document.querySelector('.advanced-shell > summary');
      if (!summary) return;
      summary.querySelectorAll('[data-tray-tab]').forEach((node) => {
        node.addEventListener('click', (event) => {
          event.preventDefault();
          event.stopPropagation();
          setActiveTrayTab(String(node.getAttribute('data-tray-tab') || 'pivot'), { openDrawer: true, clearUnread: true });
        });
      });
      summary.querySelectorAll('button').forEach((node) => {
        node.addEventListener('click', (event) => {
          event.preventDefault();
          event.stopPropagation();
        });
      });
    }

    function bindAdvancedDrawerMode() {
      const drawer = $('advanced-section');
      const fullToggle = $('advanced-full-toggle');
      if (!drawer || !fullToggle) return;
      const sync = () => {
        const full = drawer.dataset.mode === 'full';
        fullToggle.textContent = full ? '⤡' : '⤢';
        fullToggle.title = full ? 'Return the drawer to normal review height' : 'Expand the drawer into full review mode';
        try {
          sessionStorage.setItem(trayModeStorageKey, drawer.open ? drawer.dataset.mode : 'collapsed');
        } catch (_err) {}
      };
      drawer.addEventListener('toggle', () => {
        if (!drawer.open) drawer.dataset.mode = 'medium';
        if (drawer.open) clearDrawerUpdate();
        sync();
      });
      fullToggle.onclick = () => {
        if (!drawer.open) return;
        drawer.dataset.mode = drawer.dataset.mode === 'full' ? 'medium' : 'full';
        sync();
      };
      let rememberedMode = '';
      try {
        rememberedMode = sessionStorage.getItem(trayModeStorageKey) || '';
      } catch (_err) {}
      if (rememberedMode === 'collapsed') drawer.open = false;
      else if (rememberedMode === 'full') {
        drawer.open = true;
        drawer.dataset.mode = 'full';
      } else {
        drawer.dataset.mode = drawer.dataset.mode || 'medium';
      }
      sync();
    }

    function setActiveTrayTab(tab, options) {
      const drawer = $('advanced-section');
      const body = drawer ? drawer.querySelector('.advanced-body') : null;
      const opts = (options && typeof options === 'object') ? options : {};
      if (drawer && !drawer.open && opts.openDrawer) {
        drawer.open = true;
        drawer.dataset.mode = 'medium';
      }
      activeTrayTab = String(tab || 'pivot');
      document.querySelectorAll('[data-tray-tab]').forEach((node) => {
        node.classList.toggle('active', String(node.getAttribute('data-tray-tab') || '') === activeTrayTab);
      });
      document.querySelectorAll('[data-tray-panel]').forEach((node) => {
        node.classList.toggle('active', String(node.getAttribute('data-tray-panel') || '') === activeTrayTab);
      });
      if (body) body.scrollTop = 0;
      if (opts.clearUnread) clearDrawerUpdate();
      try {
        sessionStorage.setItem(trayTabStorageKey, activeTrayTab);
      } catch (_err) {}
    }

    function syncDrawerMirrors() {
      const result = (lastAskResult && typeof lastAskResult === 'object') ? lastAskResult : null;
      const spl = extractExecutedSPL(result || {});
      const latestRun = Array.isArray(result?.selected_spl_details) && result.selected_spl_details.length
        ? (result.selected_spl_details[result.selected_spl_details.length - 1] || {})
        : {};
      const coverage = extractCoverage(result || {}, spl);
      const pivotContent = $('drawer-pivot-content');
      const evidenceSummary = $('drawer-evidence-summary');
      const evidenceCoverage = $('drawer-evidence-coverage');
      const drawerMitre = $('drawer-mitre-content');
      const drawerTimeline = $('drawer-timeline-content');
      const drawerSplSummary = $('drawer-spl-summary');
      const drawerSplQuery = $('drawer-spl-query');
      const drawerSplResults = $('drawer-spl-results');
      const splLink = $('spl-link');
      const drawerSplLink = $('drawer-spl-link');
      const drawerSplInlineLink = $('drawer-spl-inline-link');
      const splModel = buildDrawerSplMarkup(result, coverage, spl, latestRun);
      renderCaseTimeline(result || {});
      if (pivotContent) {
        pivotContent.innerHTML = buildDrawerPivotMarkup(result);
      }
      if (evidenceSummary) {
        evidenceSummary.innerHTML = buildDrawerEvidenceMarkup(result, coverage).summary;
      }
      if (evidenceCoverage) {
        evidenceCoverage.innerHTML = buildDrawerEvidenceMarkup(result, coverage).coverage;
      }
      if (drawerMitre) {
        drawerMitre.innerHTML = buildDrawerMitreMarkup(result);
      }
      if (drawerTimeline) {
        drawerTimeline.innerHTML = buildDrawerTimelineMarkup(result);
      }
      if (drawerSplSummary) {
        drawerSplSummary.innerHTML = splModel.summary;
      }
      if (drawerSplQuery) {
        drawerSplQuery.textContent = splModel.query;
      }
      if (drawerSplResults) {
        drawerSplResults.textContent = splModel.results;
      }
      const rawSplHref = splLink ? String(splLink.getAttribute('href') || '').trim() : '';
      const splLinkVisible = splLink ? splLink.style.display !== 'none' : false;
      const hasDrawerSpl = Boolean(($('spl-query')?.textContent || '').trim());
      if (drawerSplLink && splLink && splLinkVisible && rawSplHref && rawSplHref !== '#') {
        drawerSplLink.href = splLink.href;
        drawerSplLink.style.display = 'inline-flex';
      } else if (drawerSplLink) {
        drawerSplLink.href = '#';
        drawerSplLink.style.display = 'none';
      }
      if (drawerSplInlineLink && splModel.splHref && splModel.splHref !== '#') {
        drawerSplInlineLink.href = splModel.splHref;
        drawerSplInlineLink.style.display = 'inline-flex';
      } else if (drawerSplInlineLink) {
        drawerSplInlineLink.href = '#';
        drawerSplInlineLink.style.display = 'none';
      }
      document.querySelectorAll('.drawer-pivot-open').forEach((btn) => {
        btn.onclick = () => {
          const idx = Number(btn.getAttribute('data-drawer-pivot-index') || '-1');
          const pivotCandidates = collectPivotCandidates(result || {});
          const candidate = pivotCandidates[idx] || null;
          if (!candidate) return;
          selectFollowup(candidate, idx, 'Pivot');
          $('status').textContent = 'Follow-up step loaded into the left drawer for review.';
        };
      });
      document.querySelectorAll('.drawer-pivot-run').forEach((btn) => {
        btn.onclick = async () => {
          const idx = Number(btn.getAttribute('data-drawer-pivot-index') || '-1');
          const pivotCandidates = collectPivotCandidates(result || {});
          const candidate = pivotCandidates[idx] || null;
          if (!candidate) return;
          selectFollowup(candidate, idx, 'Pivot');
          const nextQuestion = String(candidate?.next_question || candidate?.title || '');
          $('question').value = nextQuestion;
          $('status').textContent = 'Running selected pivot from the investigation drawer...';
          window.scrollTo({ top: 0, behavior: 'smooth' });
          await executeInvestigation({
            question: nextQuestion,
            pivot_context: result?.pivot_context || null,
            pivot_candidate: candidate,
          });
        };
      });
      document.querySelectorAll('.drawer-row-link').forEach((row) => {
        row.onclick = () => {
          const href = String(row.getAttribute('data-row-href') || '').trim();
          if (href && href !== '#') window.open(href, '_blank', 'noopener,noreferrer');
        };
      });
    }

    async function refreshDomainHints() {
      const q = ($('question')?.value || '').trim();
      const shell = $('domain-hints');
      if (!shell) return;
      if (!q) {
        shell.innerHTML = '<div class="muted">Type a question to see likely index/sourcetype targets.</div>';
        return;
      }
      try {
        const resp = await fetch(`/api/environment/hint?question=${encodeURIComponent(q)}`);
        const data = await resp.json();
        const hints = Array.isArray(data?.hints) ? data.hints : [];
        if (!resp.ok) {
          shell.innerHTML = `<div class="muted">hint error: ${esc(data?.error || `http_${resp.status}`)}</div>`;
          return;
        }
        if (!hints.length) {
          shell.innerHTML = '<div class="muted">No strong domain hints found yet; investigation can still run.</div>';
          return;
        }
        shell.innerHTML = hints.map((h) => {
          const idx = String(h.index || '');
          const score = String(h.score ?? '');
          const sts = Array.isArray(h.sourcetypes) ? h.sourcetypes : [];
          const reasons = Array.isArray(h.reasons) ? h.reasons : [];
          return (
            `<div class="domain-item">` +
            `<div><span class="idx">index=${esc(idx)}</span> <span class="badge">score=${esc(score)}</span></div>` +
            `<div class="meta">sourcetypes: ${esc(sts.join(', '))}</div>` +
            `<div class="meta">why: ${esc(reasons.join('; ') || 'keyword/domain match')}</div>` +
            `</div>`
          );
        }).join('');
      } catch (err) {
        shell.innerHTML = `<div class="muted">hint fetch failed: ${esc(String(err))}</div>`;
      }
    }

    function renderTDIRCase(result) {
      const tdir = result?.tdir_case;
      if (!tdir || typeof tdir !== 'object') {
        $('tdir-card').style.display = 'none';
        $('tdir-case').innerHTML = '';
        return;
      }
      const sev = String(tdir.severity || '').toLowerCase();
      const risk = Number(tdir.risk_score || 0);
      let sevClass = 'pill-sev-info';
      if (sev === 'high') sevClass = 'pill-sev-high';
      else if (sev === 'medium') sevClass = 'pill-sev-medium';
      else if (sev === 'low') sevClass = 'pill-sev-low';

      let riskClass = 'pill-risk-low';
      let riskBand = 'low';
      if (risk >= 70) { riskClass = 'pill-risk-high'; riskBand = 'high'; }
      else if (risk >= 40) { riskClass = 'pill-risk-medium'; riskBand = 'medium'; }

      $('tdir-head').innerHTML =
        `<span class="pill ${sevClass}">Severity: ${sev || 'n/a'}</span>` +
        `<span class="pill ${riskClass}">Risk: ${risk} (${riskBand})</span>` +
        `<span class="pill">Pipeline: ${tdir.pipeline || 'n/a'}</span>`;
      $('tdir-meta').textContent =
        `Intent=${tdir.intent || ''} | Tool=${tdir.selected_tool || ''} | Rows=${tdir.rows_returned ?? ''}`;
      $('tdir-card').style.display = 'block';
      const phase = tdir.phase_status || {};
      const phaseOrder = ['detect', 'triage', 'investigate', 'respond', 'recover', 'soar_automation'];
      const phaseHtml = phaseOrder.map((key) => {
        const state = String(phase[key] ?? 'planned');
        return (
          `<div class="phase-pill ${esc(key)} ${esc(state)}">` +
          `<span class="phase-name">${esc(key.replaceAll('_', ' '))}</span>` +
          `<span class="phase-state">${esc(state.replaceAll('_', ' '))}</span>` +
          `</div>`
        );
      }).join('');
      const pivots = Array.isArray(tdir.recommended_next_pivots) ? tdir.recommended_next_pivots : [];
      const pivotHtml = pivots.length
        ? pivots.map((p) => {
            const text = String(p || '').trim();
            const priority = text.toLowerCase().startsWith('priority ');
            return `<li class="tdir-pivot-item${priority ? ' priority' : ''}">${esc(text)}</li>`;
          }).join('')
        : '<li class="tdir-pivot-item">No recommended next pivots were produced for this run.</li>';
      const hypothesis = String(tdir.incident_hypothesis || '').trim() || 'No explicit hypothesis was generated.';
      const responseNote = String(tdir.response_note || '').trim();
      $('tdir-case').innerHTML =
        `<div class="tdir-section">` +
        `<div class="tdir-label">Current Assessment</div>` +
        `<div class="tdir-hypothesis">${esc(hypothesis)}</div>` +
        `</div>` +
        `<div class="tdir-section">` +
        `<div class="tdir-label">Phase Status</div>` +
        `<div class="tdir-phase-grid">${phaseHtml}</div>` +
        `</div>` +
        `<div class="tdir-section takeaway">` +
        `<div class="tdir-kicker">Real Takeaway</div>` +
        `<div class="tdir-title">Recommended Next Pivots</div>` +
        `<div class="tdir-takeaway-copy">The most useful next moves for this investigation are below. These are the highest-value pivots produced from the current evidence, not generic follow-up ideas.</div>` +
        `<ul class="tdir-pivot-list">${pivotHtml}</ul>` +
        (responseNote ? `<div class="tdir-response-note">${esc(responseNote)}</div>` : '') +
        `</div>`;
    }

    function clearContinuationControls() {
      lastAskResult = null;
      pendingContinuationState = null;
      $('continue-shell').style.display = 'none';
      $('continue-copy').textContent = '';
      $('continue-pill').textContent = '';
      $('continue-btn').style.display = 'none';
    }

    function renderContinuationControls(result) {
      const shell = $('continue-shell');
      const copy = $('continue-copy');
      const pill = $('continue-pill');
      if (!shell || !copy || !pill) return;
      const loop = result?.loop_control;
      if (!loop || typeof loop !== 'object' || String(result?.pipeline || '') !== 'agentic_loop') {
        clearContinuationControls();
        return;
      }
      const lines = [];
      lines.push(`depth ${loop.current_depth + 1} of ${loop.max_depth}`);
      lines.push(`auto_used=${loop.auto_continue_used}/${loop.auto_continue_limit}`);
      if (loop.recommended_followup_question) lines.push(`next_question=${loop.recommended_followup_question}`);
      if (loop.recommended_followup_tool) lines.push(`next_tool=${loop.recommended_followup_tool}`);
      if (loop.auto_followup_executed) {
        lines.push(`Auto follow-up already executed in this run.`);
      }
      if (loop.human_approval_required) {
        lines.push(`Further investigation now requires explicit analyst approval.`);
        pendingContinuationState = loop.continuation_request || null;
        $('continue-btn').style.display = 'inline-block';
      } else {
        pendingContinuationState = null;
        $('continue-btn').style.display = 'none';
      }
      if (loop.stop_reason) lines.push(`control=${loop.stop_reason}`);
      pill.textContent = loop.human_approval_required ? 'Awaiting Human Approval' : 'Loop Control Active';
      copy.textContent = lines.join('\\n');
      shell.style.display = 'block';
    }


    function currentRunStage(value, elapsedMs) {
      const pct = Number(value || 0);
      const elapsed = Number(elapsedMs || 0);
      if (pct < 18) return { title: 'Question intake and guardrails', note: 'The controller is checking that the request stays inside read-only investigation scope before any tool can run.', status: 'Checking request scope and selecting the investigation path.', timeline: 'Guardrails are validating the question and choosing the allowed path.' };
      if (pct < 48) return { title: 'Planning and SPL drafting', note: elapsed > 20000 ? 'This delay is usually model-side planning or SPL drafting, not Splunk retrieval.' : 'The planner and writer are building a bounded SPL approach for this question.', status: 'Planner and writer are building the bounded SPL path.', timeline: 'Model roles are planning the search strategy and drafting the first SPL candidate.' };
      if (pct < 76) return { title: 'Splunk retrieval and evidence collection', note: 'The approved read-only path is retrieving evidence or metadata from Splunk.', status: 'Retrieving evidence from Splunk and checking first-pass results.', timeline: 'The bounded plan is executing against Splunk and collecting evidence rows.' };
      if (pct < 92) return { title: 'Evidence review and pivot generation', note: elapsed > 45000 ? 'This run is taking longer than usual. The delay is now more likely in evidence review or peer reasoning than in Splunk retrieval.' : 'Returned evidence is being reviewed and turned into analyst-facing pivots and ATT&CK context.', status: 'Reviewing evidence quality and forming the next analyst actions.', timeline: 'The evidence reviewers are checking the returned rows and deciding what matters.' };
      return { title: 'Final analyst summary', note: elapsed > 45000 ? 'This run is taking longer than usual. You can keep waiting, or cancel in the browser and retry a narrower question or shorter time window.' : 'The final summary is being assembled for the analyst view.', status: 'Finalizing the analyst-facing answer and page sections.', timeline: 'The controller is packaging the final answer, coverage view, and pivots.' };
    }

    function refreshRunningUi() {
      const elapsedMs = runStartAt ? (Date.now() - runStartAt) : 0;
      const elapsedSec = Math.max(0, Math.round(elapsedMs / 1000));
      const stage = currentRunStage(runProgressValue, elapsedMs);
      if ($('run-progress-stage')) $('run-progress-stage').textContent = `Stage: ${stage.title}`;
      if ($('run-progress-elapsed')) $('run-progress-elapsed').textContent = `Elapsed: ${elapsedSec}s`;
      if ($('run-progress-note')) $('run-progress-note').textContent = stage.note;
      $('status').textContent = stage.status;
      $('spl-analyst-summary').innerHTML = `<div class="brief-body muted">${esc(stage.status)}</div>`;
      $('coverage-visibility').innerHTML = `<div class="coverage-row"><div class="coverage-row-title">Coverage</div><div class="coverage-row-copy">${esc(stage.timeline)}</div></div>`;
      $('decision-support-summary').innerHTML = `<div class="support-item"><div class="support-label">Current stage</div><div class="support-value">${esc(stage.title)}</div></div><div class="support-item"><div class="support-label">Delay source</div><div class="support-value">${esc(stage.note)}</div></div>`;
      $('investigation-timeline').innerHTML = `<details class="timeline-phase" open><summary><div class="timeline-phase-main"><div class="timeline-phase-name">Current Stage</div><div class="timeline-phase-summary">${esc(stage.status)}</div></div><div class="timeline-phase-status">running</div></summary><div class="timeline-phase-body"><div class="timeline-detail-grid"><div class="timeline-detail"><div class="timeline-detail-title">What is happening now</div><div class="timeline-detail-copy">${esc(stage.timeline)}</div></div><div class="timeline-detail"><div class="timeline-detail-title">Elapsed time</div><div class="timeline-detail-copy">${esc(String(elapsedSec))} second(s)</div></div><div class="timeline-detail"><div class="timeline-detail-title">What you can do</div><div class="timeline-detail-copy">${esc(elapsedMs > 45000 ? 'This run is taking longer than usual. You can keep waiting, or cancel in the browser and retry a narrower question or shorter time window.' : 'Wait for completion. If this keeps growing, the delay is likely model-side rather than Splunk-side.')}</div></div></div></div></details>`;
      $('summary').innerHTML = `<div class="brief-body muted">${esc(stage.status)} ${esc(stage.note)}</div>`;
      const phaseState = runProgressValue < 18
        ? { detect: 'in_progress', triage: 'planned', investigate: 'planned' }
        : runProgressValue < 48
          ? { detect: 'complete', triage: 'in_progress', investigate: 'planned' }
          : { detect: 'complete', triage: 'complete', investigate: 'in_progress' };
      renderPhaseStrip(phaseState);
      syncDrawerMirrors();
    }
    async function executeInvestigation(options = {}) {
      function setRunProgress(value, label='') {
        runProgressValue = Math.max(0, Math.min(100, Number(value || 0)));
        $('run-progress-wrap').style.display = 'block';
        $('run-progress-bar').style.width = `${runProgressValue}%`;
        $('run-progress-pct').textContent = `${Math.round(runProgressValue)}%`;
        if (label) $('run-progress-label').textContent = label;
        refreshRunningUi();
      }

      function startRunProgress() {
        if (runProgressTimer) clearInterval(runProgressTimer);
        runStartAt = Date.now();
        if (cancelRunBtn) cancelRunBtn.style.display = 'inline-flex';
        setRunProgress(2, 'Starting investigation...');
        runProgressTimer = setInterval(() => {
          if (runProgressValue < 18) {
            setRunProgress(runProgressValue + 2.2, 'Checking read-only scope...');
            return;
          }
          if (runProgressValue < 48) {
            setRunProgress(runProgressValue + 1.6, 'Planning and drafting SPL...');
            return;
          }
          if (runProgressValue < 76) {
            setRunProgress(runProgressValue + 0.8, 'Retrieving evidence from Splunk...');
            return;
          }
          if (runProgressValue < 92) {
            setRunProgress(runProgressValue + 0.35, 'Reviewing evidence and pivots...');
            return;
          }
          if (runProgressValue < 96) {
            setRunProgress(runProgressValue + 0.08, 'Finalizing analyst summary...');
            return;
          }
          refreshRunningUi();
        }, 1000);
      }

      function stopRunProgress(finalOk, cancelled=false) {
        if (runProgressTimer) {
          clearInterval(runProgressTimer);
          runProgressTimer = null;
        }
        const elapsedMs = runStartAt ? (Date.now() - runStartAt) : 0;
        const elapsedSec = Math.max(0, Math.round(elapsedMs / 1000));
        if (cancelRunBtn) cancelRunBtn.style.display = 'none';
        $('run-progress-wrap').style.display = 'block';
        if (cancelled) {
          runProgressValue = Math.max(runProgressValue || 0, 1);
          $('run-progress-label').textContent = 'Investigation cancelled in browser.';
          $('run-progress-pct').textContent = `${Math.round(runProgressValue)}%`;
          $('run-progress-bar').style.width = `${runProgressValue}%`;
          if ($('run-progress-stage')) $('run-progress-stage').textContent = 'Stage: Browser cancellation';
          if ($('run-progress-elapsed')) $('run-progress-elapsed').textContent = `Elapsed: ${elapsedSec}s`;
          if ($('run-progress-note')) $('run-progress-note').textContent = 'The browser stopped waiting for this run. The server may still complete it in the background. Retry a narrower question, reduce the time window, or target a more specific platform or index if needed.';
        } else {
          runProgressValue = 100;
          $('run-progress-label').textContent = finalOk ? 'Investigation complete.' : 'Investigation failed.';
          $('run-progress-pct').textContent = '100%';
          $('run-progress-bar').style.width = '100%';
          if ($('run-progress-stage')) $('run-progress-stage').textContent = `Stage: ${finalOk ? 'Completed' : 'Stopped before completion'}`;
          if ($('run-progress-elapsed')) $('run-progress-elapsed').textContent = `Elapsed: ${elapsedSec}s`;
          if ($('run-progress-note')) $('run-progress-note').textContent = finalOk
            ? 'The run finished and the final investigation view is now rendered below.'
            : 'The run stopped before a final investigation view could be completed. Check the status and output for the failure reason, then retry a narrower question or shorter time window if needed.';
        }
        runStartAt = 0;
      }

      runBtn.disabled = true;
      lastAskResult = null;
      $('status').textContent = 'Starting investigation...';
      startRunProgress();
      $('case-header-chips').innerHTML = `
        <div class="utility-pill readonly"><span>Read-Only</span><strong>Splunk investigation mode</strong></div>
        <div class="utility-pill"><span>Status</span><strong>Running</strong></div>
      `;
      syncUtilityBarVisibility();
      bindSplToggleButtons();
      $('model-personas').innerHTML = '';
      $('spl-meta-strip').innerHTML = '';
      $('spl-analyst-summary').innerHTML = '<div class="brief-body muted">Starting investigation and selecting the bounded path.</div>';
      $('spl-link').style.display = 'none';
      $('copy-spl').style.display = 'none';
      $('spl-query').textContent = '';
      $('spl-results').textContent = '';
      $('coverage-visibility').innerHTML = '<div class="coverage-row"><div class="coverage-row-title">Coverage</div><div class="coverage-row-copy">The page will show whether the delay is in planning, Splunk retrieval, or evidence review.</div></div>';
      $('pivot-cards').innerHTML = '<div class="brief-body muted">Recommended next steps will appear after Splunk evidence is returned and reviewed.</div>';
      $('decision-support-summary').innerHTML = '<div class="support-item"><div class="support-label">Current stage</div><div class="support-value">Question intake and guardrails</div></div><div class="support-item"><div class="support-label">Delay source</div><div class="support-value">The system is validating scope before any model or Splunk call runs.</div></div>';
      $('model-decisions').innerHTML = '';
      $('workflow-track').innerHTML = '';
      $('workflow-meta').textContent = '';
      $('investigation-timeline').innerHTML = '<details class="timeline-phase" open><summary><div class="timeline-phase-main"><div class="timeline-phase-name">Current Stage</div><div class="timeline-phase-summary">Checking request scope and selecting the investigation path.</div></div><div class="timeline-phase-status">running</div></summary><div class="timeline-phase-body"><div class="timeline-detail-grid"><div class="timeline-detail"><div class="timeline-detail-title">What is happening now</div><div class="timeline-detail-copy">Guardrails are validating the question and choosing the allowed path.</div></div><div class="timeline-detail"><div class="timeline-detail-title">Elapsed time</div><div class="timeline-detail-copy">0 second(s)</div></div><div class="timeline-detail"><div class="timeline-detail-title">What you can do</div><div class="timeline-detail-copy">Wait for completion. The page will explain whether any delay is coming from planning, Splunk retrieval, or evidence review.</div></div></div></div></details>';
      $('tdir-card').style.display = 'none';
      $('tdir-case').textContent = '';
      $('journey').textContent = '';
      $('output').textContent = '';
      $('brief-mitre').innerHTML = '<div class="brief-body muted">ATT&CK context will appear after evidence review completes.</div>';
      $('summary').innerHTML = '<div class="brief-body muted">The system is checking scope, building the bounded SPL path, and then retrieving evidence.</div>';
      $('brief-supported').textContent = 'Running';
      setSplVisibility(false);
      syncDrawerMirrors();
      setActiveTrayTab('pivot', { openDrawer: false });
      clearContinuationControls();
      try {
        const payload = {
          question: options.question || $('question').value,
          session_id: $('session').value,
          max_steps: Number($('maxsteps').value || 3),
          write_artifact: Boolean($('artifact').checked),
          pipeline: $('pipeline').value,
          approved_deeper_investigation: Boolean(options.approved_deeper_investigation),
          continuation_state: options.continuation_state || null,
          pivot_context: options.pivot_context || null,
          pivot_candidate: options.pivot_candidate || null,
        };
        runAbortController = new AbortController();
        const resp = await fetch('/api/ask', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify(payload),
          signal: runAbortController.signal
        });
        setRunProgress(94, 'Finalizing investigation output...');
        const data = await resp.json();
        if (!resp.ok) {
          $('status').innerHTML = '<span class="warn">Error</span>';
          renderInvestigationJourney(data.result || data || {});
          renderWorkflowTimeline(data.result || data || {});
          $('output').textContent = JSON.stringify(data, null, 2);
          renderContinuationControls(data.result || {});
          runAbortController = null;
          stopRunProgress(false);
        } else {
          lastAskResult = data.result || {};
          if (lastAskResult && typeof lastAskResult === 'object') {
            lastAskResult = {
              ...lastAskResult,
              splunk_search_url_base: data.splunk_search_url_base || lastAskResult.splunk_search_url_base || '',
            };
          }
          if (lastAskResult?.case_context?.case_id && lastAskResult?.case_context?.node_id) {
            latestCaseRef = {
              case_id: String(lastAskResult.case_context.case_id),
              node_id: String(lastAskResult.case_context.node_id),
            };
          }
          inspectingSavedNode = false;
          if (Array.isArray(data.sample_rows)) {
            lastAskResult.__ui_sample_rows = data.sample_rows;
          }
          const result = lastAskResult || {};
          $('status').textContent = hasEvidenceRows(result) ? 'Complete' : 'Complete (No Hits)';
          if (hasEvidenceRows(result)) {
            $('summary').innerHTML = renderSummaryText(result?.summary || '');
            renderModelDecisions(result || {});
            renderTDIRCase(result || {});
            renderInvestigationJourney(result || {});
            renderWorkflowTimeline(result || {});
            renderContinuationControls(result || {});
          } else {
            renderNoEvidenceOutcome(result || {});
            $('model-personas').innerHTML = '';
            $('model-decisions').innerHTML = '';
            $('workflow-track').innerHTML = '';
            $('workflow-meta').textContent = '';
            clearContinuationControls();
          }
          $('output').textContent = JSON.stringify(data, null, 2);
          stopRunProgress(true);
        }
      } catch (e) {
        const aborted = e && e.name === 'AbortError';
        if (aborted) {
          $('status').textContent = 'Cancelled in browser. The server may still finish the current request.';
          $('brief-supported').textContent = 'Cancelled';
          $('summary').innerHTML = '<div class="brief-body muted">The browser stopped waiting for this run. Retry a narrower question, shorten the time window, or target a more specific platform or data source.</div>';
          stopRunProgress(false, true);
        } else {
          $('status').innerHTML = '<span class="warn">Request failed</span>';
          $('summary').innerHTML = '<div class="brief-body muted">The run stopped before a final investigation view could be completed. Retry a narrower question, shorten the time window, or target a more specific platform or data source.</div>';
          $('journey').textContent = 'Unable to build investigation journey because the request failed before a structured result was returned.';
          $('output').textContent = String(e);
          stopRunProgress(false);
        }
      } finally {
        runAbortController = null;
        runBtn.disabled = false;
        if (cancelRunBtn) cancelRunBtn.style.display = 'none';
      }
    }

    window.executeInvestigation = executeInvestigation;
    runBtn.onclick = async () => {
      await executeInvestigation({});
    };
    continueBtn.onclick = async () => {
      if (!pendingContinuationState) return;
      await executeInvestigation({
        question: (lastAskResult && (lastAskResult.root_question || lastAskResult.question)) || $('question').value,
        approved_deeper_investigation: true,
        continuation_state: pendingContinuationState,
      });
    };
    $('selected-followup-run').onclick = async () => {
      if (!selectedFollowup || !selectedFollowup.text) return;
      $('question').value = selectedFollowup.text;
      $('status').textContent = 'Running selected follow-up investigation...';
      window.scrollTo({top: 0, behavior: 'smooth'});
      await executeInvestigation({
        question: selectedFollowup.text,
        pivot_context: selectedFollowup.contextOverride || lastAskResult?.pivot_context || null,
        pivot_candidate: selectedFollowup.candidate || null,
      });
    };
    $('selected-followup-clear').onclick = () => {
      selectedFollowup = null;
      renderSelectedFollowup();
      $('status').textContent = 'Follow-up drawer cleared.';
    };
    $('pipeline').addEventListener('change', updatePipelineHelp);
    $('artifact').addEventListener('change', updateArtifactLabel);
    $('copy-spl').onclick = async () => {
      const text = $('spl-query').textContent || '';
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        $('status').textContent = 'SPL copied to clipboard.';
      } catch (_err) {
        $('status').textContent = 'Unable to copy SPL from the browser.';
      }
    };
    $('control-details').open = false;
    updatePipelineHelp();
    $('artifact').checked = false;
    updateArtifactLabel();
    bindSplToggleButtons();
    bindAdvancedSummaryControls();
    bindAdvancedDrawerMode();
    setSplVisibility(false);
    syncUtilityBarVisibility();
    renderSelectedFollowup();
    loadSplAssetManifest();
    syncDrawerMirrors();
    try {
      const rememberedTab = sessionStorage.getItem(trayTabStorageKey) || 'pivot';
      setActiveTrayTab(rememberedTab, { openDrawer: false });
    } catch (_err) {
      setActiveTrayTab('pivot', { openDrawer: false });
    }
    let hintTimer = null;
    $('question').addEventListener('input', () => {
      if (hintTimer) clearTimeout(hintTimer);
      hintTimer = setTimeout(refreshDomainHints, 220);
    });
    refreshDomainHints();
    if (cancelRunBtn) {
      cancelRunBtn.onclick = () => {
        if (runAbortController) runAbortController.abort();
      };
    }
    if (drawerJsonToggleBtn) {
      drawerJsonToggleBtn.onclick = () => {
        const out = $('output');
        if (!out) return;
        const showing = out.style.display !== 'none';
        out.style.display = showing ? 'none' : 'block';
        drawerJsonToggleBtn.textContent = showing ? 'Show JSON' : 'Hide JSON';
      };
    }
    try {
      const params = new URLSearchParams(window.location.search);
      const initialCaseId = String(params.get('case_id') || '').trim();
      const initialNodeId = String(params.get('node_id') || '').trim();
      if (initialCaseId && initialNodeId) {
        latestCaseRef = { case_id: initialCaseId, node_id: initialNodeId };
        loadCaseNode(initialCaseId, initialNodeId);
      }
    } catch (_err) {}
  </script>
</body>
</html>
"""


DOCS_SHELL_HTML = """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{title}</title>
  <link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg?v=agtsmith1\" />
  <link rel=\"icon\" href=\"/favicon.ico?v=agtsmith1\" />
  <style>
    :root {{
      --bg:#0f172a; --card:#111827; --card2:#0b1220; --muted:#9ca3af; --fg:#e5e7eb;
      --line:#1f2937; --link:#93c5fd; --accent:#22c55e;
    }}
    html {{
      min-height:100%;
      background: linear-gradient(140deg,#0b1220 0%,#111827 65%,#0a1f16 100%);
      background-repeat:no-repeat;
      background-size:cover;
    }}
    body {{
      margin:0;
      min-height:100vh;
      font-family: "Trebuchet MS", "Segoe UI", "Helvetica Neue", Helvetica, sans-serif;
      background: linear-gradient(140deg,#0b1220,#111827 65%,#0a1f16);
      background-repeat:no-repeat;
      background-size:cover;
      color:var(--fg);
    }}
    .wrap {{ max-width: 1740px; min-height:calc(100vh - 48px); margin: 24px auto; padding: 0 28px 32px; box-sizing:border-box; }}
    .topnav {{
      position:relative;
      z-index:220;
      display:flex;
      flex-wrap:nowrap;
      gap:4px;
      margin-bottom:16px;
      justify-content:flex-start;
      align-items:stretch;
      padding:6px;
      border:1px solid rgba(34,66,92,.44);
      border-radius:22px;
      background:linear-gradient(180deg, rgba(7,18,31,.82), rgba(5,12,23,.72));
      box-shadow:0 18px 34px rgba(0,0,0,.18), inset 0 1px 0 rgba(255,255,255,.03);
      backdrop-filter:blur(16px);
    }}
    .nav-item {{
      position:relative;
      display:flex;
      flex-direction:column;
      justify-content:center;
      gap:2px;
      min-width:0;
      flex:1 1 0;
      text-decoration:none;
      border:1px solid transparent;
      border-radius:16px;
      padding:8px 9px 9px;
      background:linear-gradient(180deg, rgba(255,255,255,.015), rgba(255,255,255,.008));
      color:#dce9f8;
      box-shadow:inset 0 1px 0 rgba(255,255,255,.018);
      transition:transform .16s ease, border-color .16s ease, box-shadow .16s ease, background .16s ease, color .16s ease;
      overflow:hidden;
    }}
    .nav-item-dropdown {{ overflow:visible; z-index:221; }}
    .nav-trigger {{
      display:flex;
      flex-direction:column;
      justify-content:center;
      gap:2px;
      min-width:0;
      text-decoration:none;
      color:inherit;
    }}
    .nav-item::after{{ content:""; position:absolute; left:12px; right:12px; bottom:0; height:2px; border-radius:999px; background:linear-gradient(90deg, rgba(96,165,250,.82), rgba(45,212,191,.82)); opacity:0; transform:scaleX(.5); transition:opacity .16s ease, transform .16s ease; }}
    .nav-item:hover {{ border-color:rgba(81,127,163,.46); background:linear-gradient(180deg, rgba(18,35,53,.74), rgba(9,21,34,.66)); transform:translateY(-1px); box-shadow:0 10px 18px rgba(2,6,23,.16), inset 0 1px 0 rgba(255,255,255,.03); color:#f8fbff; }}
    .nav-item:hover::after{{ opacity:.58; transform:scaleX(1); }}
    .nav-item.active {{ border-color:rgba(61,105,136,.5); background:linear-gradient(180deg, rgba(17,37,57,.92), rgba(10,24,39,.9)); color:#ecfdf5; box-shadow:0 12px 22px rgba(2,6,23,.18), inset 0 1px 0 rgba(255,255,255,.04); }}
    .nav-item.active::after{{ opacity:1; transform:scaleX(1); }}
    .nav-kicker {{ font-size:9px; color:#7ea2c1; text-transform:uppercase; letter-spacing:.12em; font-weight:800; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
    .nav-item.active .nav-kicker {{ color:#8fd3ff; }}
    .nav-label {{ font-size:13px; font-weight:900; line-height:1.15; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
    .nav-submenu {{
      position:absolute;
      top:calc(100% + 10px);
      left:0;
      min-width:320px;
      display:grid;
      gap:0;
      padding:8px;
      border:1px solid rgba(46,82,110,.8);
      border-radius:16px;
      background:linear-gradient(180deg, rgba(10,22,36,.98), rgba(6,14,24,.96));
      box-shadow:0 18px 34px rgba(0,0,0,.32), inset 0 1px 0 rgba(255,255,255,.03);
      opacity:0;
      visibility:hidden;
      transform:translateY(6px);
      transition:opacity .14s ease, transform .14s ease, visibility .14s ease;
      z-index:260;
    }}
    .nav-item-dropdown:hover .nav-submenu,
    .nav-item-dropdown:focus-within .nav-submenu {{
      opacity:1;
      visibility:visible;
      transform:translateY(0);
    }}
    .nav-submenu-item {{
      display:grid;
      gap:3px;
      padding:10px 12px;
      border-radius:10px;
      text-decoration:none;
      color:#e5eef8;
      transition:background .14s ease, transform .14s ease;
    }}
    .nav-submenu-item:hover {{
      background:linear-gradient(180deg, rgba(18,37,57,.92), rgba(10,24,39,.88));
      transform:translateX(1px);
    }}
    .nav-submenu-title {{
      font-size:13px;
      font-weight:900;
      line-height:1.2;
      color:#eff6ff;
    }}
    .nav-submenu-copy {{
      font-size:12px;
      line-height:1.4;
      color:#9fb4cc;
    }}
    .layout {{ display:grid; grid-template-columns: 320px minmax(0, 1fr); gap:0; align-items:start; }}
    .card {{
      background: linear-gradient(180deg, rgba(17,24,39,.96), rgba(13,20,34,.96));
      border:1px solid #213246;
      border-radius: 12px;
      padding: 16px;
      box-shadow: 0 8px 20px rgba(0,0,0,.20);
    }}
    .docs-sidebar {{
      position: sticky;
      top: 10px;
      padding: 12px 14px 18px 0;
      border-right: 1px solid #1c3145;
      margin-right: 18px;
      align-self:start;
    }}
    .docs-main {{
      min-width: 0;
      background: linear-gradient(180deg, rgba(17,24,39,.96), rgba(13,20,34,.96));
      border:1px solid #213246;
      border-radius: 12px;
      padding: 18px;
      box-shadow: 0 8px 20px rgba(0,0,0,.20);
    }}
    .docs-main details {{
      margin:14px 0 18px;
      border:1px solid #355772;
      border-radius:16px;
      background:linear-gradient(180deg, rgba(7,23,38,.96), rgba(8,28,41,.92));
      overflow:hidden;
      box-shadow:0 12px 24px rgba(0,0,0,.16);
    }}
    .docs-main details > summary {{
      position:relative;
      cursor:pointer;
      list-style:none;
      padding:14px 18px 14px 48px;
      color:#ecfeff;
      font-weight:900;
      line-height:1.45;
      background:linear-gradient(135deg, rgba(6,78,59,.88), rgba(8,47,73,.94));
      border-bottom:1px solid rgba(70,116,144,.28);
    }}
    .docs-main details > summary::-webkit-details-marker {{ display:none; }}
    .docs-main details > summary::before {{
      content:"+";
      position:absolute;
      left:16px;
      top:50%;
      transform:translateY(-50%);
      width:20px;
      height:20px;
      display:grid;
      place-items:center;
      border-radius:999px;
      background:rgba(236,254,255,.14);
      color:#f0fdfa;
      font-size:15px;
      font-weight:900;
      border:1px solid rgba(236,254,255,.18);
    }}
    .docs-main details[open] > summary::before {{ content:"−"; }}
    .docs-main details > :not(summary) {{
      margin-left:18px;
      margin-right:18px;
    }}
    .docs-main details > p:last-child,
    .docs-main details > ul:last-child,
    .docs-main details > ol:last-child,
    .docs-main details > pre:last-child,
    .docs-main details > h3:last-child {{
      margin-bottom:18px;
    }}
    .docs-rail-title {{
      margin:0 0 6px;
      font-size:22px;
      color:#eef4fb;
    }}
    .docs-rail-sub {{
      margin:0 0 12px;
      color:#8ea4ba;
      font-size:13px;
      line-height:1.5;
    }}
    h1 {{ margin:0 0 8px; font-size:24px; }}
    h2 {{ margin:14px 0 8px; font-size:18px; }}
    h3 {{ margin:12px 0 7px; font-size:16px; }}
    p {{ line-height:1.6; margin: 8px 0; }}
    .muted {{ color: var(--muted); font-size:13px; }}
    ul, ol {{ margin:8px 0 10px; padding-left: 22px; line-height:1.55; }}
    li {{ margin:4px 0; }}
    a {{ color:var(--link); }}
    pre {{
      white-space: pre-wrap;
      background:#020617;
      border:1px solid var(--line);
      border-radius:10px;
      padding:12px;
      overflow:auto;
      line-height:1.45;
      font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
      font-size:13px;
    }}
    .mermaid {{
      background:#020617;
      border:1px solid var(--line);
      border-radius:12px;
      padding:12px;
      overflow:auto;
      margin:10px 0 14px;
    }}
    code {{
      background:var(--card2);
      border:1px solid var(--line);
      border-radius:4px;
      padding:1px 4px;
      font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
      font-size: 90%;
    }}
    .doc-link {{
      display:block;
      padding:7px 10px;
      border-radius:8px;
      text-decoration:none;
      color:var(--fg);
      border:1px solid transparent;
      font-size:13px;
    }}
    .doc-link:hover {{ background:#0d1d32; border-color:#2f4a68; }}
    .doc-link.active {{ background:#0f2a3d; border-color:#3c7aa3; color:#dbeafe; }}
    .doc-link-title {{
      display:block;
      font-weight:700;
      color:#e5eef8;
      margin-bottom:2px;
    }}
    .doc-link-meta {{
      display:block;
      color:#8ea4ba;
      font-size:11.5px;
      line-height:1.35;
    }}
    .doc-group {{
      margin-top:10px;
      border:0;
      border-radius:0;
      background:transparent;
      overflow:visible;
    }}
    .doc-group[open] {{ background:transparent; }}
    .section-title {{
      margin:0;
      padding:8px 0;
      color:#c8d1dc;
      font-size:12px;
      text-transform:uppercase;
      letter-spacing:.7px;
      font-weight:700;
      list-style:none;
      cursor:pointer;
      border-bottom:0;
      background:transparent;
    }}
    .doc-group summary::-webkit-details-marker {{ display:none; }}
    .section-title::after {{
      content: "▾";
      float:right;
      color:#7ea6c9;
      font-size:12px;
      transform: translateY(1px);
    }}
    .doc-group:not([open]) .section-title::after {{ content: "▸"; }}
    .section-links {{
      padding:2px 0 4px 10px;
      margin-left:6px;
      border-left:1px solid #22384d;
    }}
    .search {{
      width:100%; box-sizing:border-box; margin:8px 0 10px; background:var(--card2);
      color:var(--fg); border:1px solid #374151; border-radius:8px; padding:9px;
      font-size:14px;
    }}
    .doc-brand-title {{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:12px;
      margin-bottom:8px;
    }}
    .doc-brand-icon {{
      width:28px;
      height:28px;
      border-radius:7px;
      border:1px solid #27415a;
      background:#07111f;
      flex:0 0 auto;
    }}
    .hero {{ display:grid; grid-template-columns: 1fr 1fr; gap:12px; }}
    .guide-grid {{ display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap:12px; margin-top:12px; }}
    .guide-card {{
      background:#0b1626;
      border:1px solid #24384f;
      border-radius:12px;
      padding:14px;
    }}
    .guide-card h2 {{
      margin:0 0 6px;
      font-size:17px;
      color:#e5eef8;
    }}
    .guide-card p {{
      margin:0 0 10px;
      color:#9cb0c4;
      font-size:13px;
      line-height:1.55;
    }}
    .guide-links {{
      display:flex;
      flex-direction:column;
      gap:8px;
    }}
    .guide-link {{
      display:block;
      text-decoration:none;
      border:1px solid #294560;
      background:#0d1c2d;
      border-radius:10px;
      padding:10px 11px;
      color:#dbeafe;
    }}
    .guide-link:hover {{ border-color:#5ea6d6; background:#102338; }}
    .guide-link strong {{
      display:block;
      margin-bottom:3px;
      font-size:13px;
    }}
    .guide-link span {{
      display:block;
      color:#9bb1c6;
      font-size:12px;
      line-height:1.4;
    }}
    .badge {{ display:inline-block; border:1px solid #2e4658; background:#0a2330; border-radius:999px; padding:4px 10px; font-size:12px; color:#b9e6ff; }}
    .statline {{ display:flex; gap:10px; flex-wrap:wrap; margin:8px 0 10px; }}
    .env-list {{ display:flex; flex-direction:column; gap:10px; margin-top:10px; }}
    .env-card {{
      background: var(--card2);
      border:1px solid var(--line);
      border-radius:10px;
      padding:0;
      min-width:0;
    }}
    .env-card summary {{
      cursor:pointer;
      list-style:none;
      padding:10px 12px;
      border-radius:10px;
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:10px;
      background:#0a1b2d;
    }}
    .env-card summary::-webkit-details-marker {{ display:none; }}
    .env-card .env-body {{ padding:10px 12px; border-top:1px solid #213246; }}
    .env-sublist {{ display:flex; flex-direction:column; gap:8px; }}
    .env-subcard {{
      background: linear-gradient(180deg, rgba(8,22,38,0.92), rgba(6,17,30,0.92));
      border:1px solid #213246;
      border-radius:10px;
      overflow:hidden;
    }}
    .env-subcard summary {{
      cursor:pointer;
      list-style:none;
      padding:10px 12px;
      display:flex;
      justify-content:space-between;
      align-items:flex-start;
      gap:10px;
      background:#0a1626;
    }}
    .env-subcard summary::-webkit-details-marker {{ display:none; }}
    .env-subbody {{ padding:10px 12px; border-top:1px solid #213246; overflow-x:auto; }}
    .env-submeta {{ display:flex; flex-wrap:wrap; gap:8px; align-items:center; }}
    .env-preview {{ color:#b7cadb; font-size:12px; line-height:1.45; margin-top:4px; }}
    .env-title {{
      font-weight:700;
      color:#dbeafe;
      font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
      overflow-wrap:anywhere;
    }}
    .mono {{
      font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
      overflow-wrap:anywhere;
    }}
    .kv {{ margin:5px 0; line-height:1.45; }}
    .env-table {{
      width:100%;
      border-collapse:collapse;
      margin-top:8px;
      font-size:13px;
      min-width:980px;
      table-layout:auto;
    }}
    .env-table th, .env-table td {{
      border:1px solid #213246;
      padding:6px 8px;
      text-align:left;
      vertical-align:top;
    }}
    .env-table th {{ background:#091726; color:#bfdbfe; }}
    .env-table th:first-child, .env-table td:first-child {{ white-space:nowrap; width:180px; }}
    .env-table th:nth-child(3), .env-table td:nth-child(3),
    .env-table th:nth-child(4), .env-table td:nth-child(4) {{ white-space:nowrap; width:92px; }}
    .svg-wrap {{
      overflow:auto;
      border:1px solid var(--line);
      border-radius:10px;
      background:
        radial-gradient(circle at top left, rgba(34,197,94,.08), transparent 32%),
        radial-gradient(circle at bottom right, rgba(59,130,246,.12), transparent 34%),
        linear-gradient(180deg, #030712, #07111f);
      padding:16px;
    }}
    .arch-hero {{
      display:block;
      margin-bottom:14px;
    }}
    .arch-hero-card {{
      min-width:0;
      border:1px solid #24384f;
      border-radius:16px;
      padding:16px 18px;
      background:linear-gradient(180deg, rgba(8,21,37,.96), rgba(7,17,31,.92));
      box-shadow:0 16px 34px rgba(0,0,0,.26);
    }}
    .arch-kicker {{
      margin:0 0 8px;
      color:#7dd3fc;
      text-transform:uppercase;
      letter-spacing:.9px;
      font-size:11px;
      font-weight:700;
    }}
    .arch-hero h2 {{
      margin:0 0 8px;
      font-size:30px;
      line-height:1.1;
      color:#f8fbff;
    }}
    .arch-hero p {{
      margin:0;
      color:#b8c7d9;
      line-height:1.75;
      font-size:14px;
    }}
    .arch-hero-lead {{
      max-width:1040px;
    }}
    .arch-visio {{
      margin-bottom:14px;
      border:1px solid #22384d;
      border-radius:18px;
      background:linear-gradient(180deg, rgba(8,21,37,.96), rgba(7,17,31,.92));
      box-shadow:0 14px 28px rgba(0,0,0,.22);
      overflow:auto;
      padding:10px;
    }}
    .arch-visio-svg {{
      display:block;
      width:100%;
      min-width:1080px;
      height:auto;
    }}
    .arch-visio-caption {{
      margin:8px 4px 0;
      color:#8fb0cb;
      font-size:12px;
      line-height:1.55;
    }}
    .arch-endpoint-grid {{
      display:grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap:10px;
      align-items:stretch;
    }}
    .arch-endpoint-card {{
      min-width:0;
      border-radius:18px;
      padding:16px;
      border:1px solid #234159;
      background:linear-gradient(180deg, rgba(11,22,38,.96), rgba(7,17,31,.92));
      box-shadow:0 14px 28px rgba(0,0,0,.22);
      position:relative;
      overflow:hidden;
    }}
    .arch-endpoint-card::before {{
      content:"";
      position:absolute;
      inset:0 0 auto 0;
      height:4px;
      background:linear-gradient(90deg, #22c55e, #38bdf8);
    }}
    .arch-endpoint-topline {{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:10px;
      margin-bottom:8px;
    }}
    .arch-endpoint-card h3 {{
      margin:0;
      color:#f5f9ff;
      font-size:18px;
      line-height:1.2;
    }}
    .arch-endpoint-kicker {{
      margin:0 0 10px;
      color:#8fd8ff;
      font-size:11px;
      text-transform:uppercase;
      letter-spacing:.8px;
      font-weight:700;
    }}
    .arch-endpoint-copy {{
      margin:0;
      color:#bfd0df;
      font-size:12px;
      line-height:1.6;
    }}
    .arch-endpoint-meta {{
      margin-top:10px;
      padding-top:10px;
      border-top:1px solid rgba(36,64,88,.8);
      color:#8fb0cb;
      font-size:11px;
      line-height:1.45;
    }}
    .arch-step-badge {{
      display:inline-flex;
      align-items:center;
      justify-content:center;
      min-width:28px;
      height:28px;
      padding:0 8px;
      border-radius:999px;
      border:1px solid #2e506e;
      background:#0a1626;
      color:#dbeafe;
      font-size:11px;
      font-weight:800;
      flex:0 0 auto;
    }}
    .arch-connection-band {{
      display:grid;
      grid-template-columns: repeat(13, minmax(0, 1fr));
      gap:8px;
      align-items:center;
      margin:12px 0;
    }}
    .arch-connection-link {{
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:40px;
      border-radius:999px;
      border:1px solid #24435d;
      background:linear-gradient(180deg, rgba(8,21,37,.94), rgba(7,17,31,.88));
      color:#7dd3fc;
      font-size:12px;
      font-weight:800;
      text-transform:uppercase;
      letter-spacing:.06em;
      text-align:center;
      padding:0 6px;
    }}
    .arch-connection-link.arrow {{
      font-size:22px;
      font-weight:900;
      letter-spacing:0;
      color:#a5f3fc;
      text-shadow:0 0 18px rgba(125,211,252,.2);
    }}
    .arch-handoff-grid {{
      display:grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap:10px;
      margin-top:12px;
    }}
    .arch-handoff-card {{
      border:1px solid #22384d;
      border-radius:14px;
      padding:12px 13px;
      background:linear-gradient(180deg, rgba(11,22,38,.96), rgba(7,17,31,.9));
      color:#ccdae7;
      font-size:12px;
      line-height:1.55;
    }}
    .arch-handoff-card strong {{
      display:block;
      margin-bottom:6px;
      color:#f5f9ff;
      font-size:12px;
      text-transform:uppercase;
      letter-spacing:.6px;
    }}
    .arch-map {{
      display:grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap:14px;
      align-items:stretch;
    }}
    .arch-box {{
      min-width:0;
      border-radius:18px;
      padding:16px 18px;
      background:linear-gradient(180deg, rgba(15,23,42,.98), rgba(11,18,32,.94));
      border:1px solid #244058;
      box-shadow:0 16px 32px rgba(0,0,0,.28);
      position:relative;
      overflow:hidden;
    }}
    .arch-box::before {{
      content:"";
      position:absolute;
      inset:0 0 auto 0;
      height:4px;
      background:linear-gradient(90deg, #22c55e, #38bdf8);
    }}
    .arch-box.secondary {{
      border-color:#254866;
      background:linear-gradient(180deg, rgba(11,18,32,.98), rgba(8,17,31,.94));
    }}
    .arch-box.tertiary {{
      border-color:#244862;
      background:linear-gradient(180deg, rgba(10,22,38,.98), rgba(7,17,31,.94));
    }}
    .arch-box h3 {{
      margin:0 0 12px;
      font-size:18px;
      color:#f2f7fd;
      position:relative;
    }}
    .arch-box ul {{
      margin:0;
      padding-left:18px;
    }}
    .arch-box li {{
      margin:8px 0;
      color:#d7e0ea;
      line-height:1.55;
    }}
    .arch-note {{
      margin-top:14px;
      padding:10px 12px 0;
      border-top:1px solid #243245;
      color:#a7b8c9;
      font-size:12px;
      line-height:1.5;
    }}
    .arch-box-label {{
      display:inline-flex;
      align-items:center;
      border-radius:999px;
      border:1px solid #27415a;
      background:#081525;
      color:#8fd8ff;
      padding:4px 9px;
      font-size:11px;
      text-transform:uppercase;
      letter-spacing:.7px;
      margin-bottom:10px;
      font-weight:700;
    }}
    .arch-subgrid {{
      display:grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap:12px;
      align-items:stretch;
      margin-top:12px;
    }}
    .arch-tier {{
      margin-bottom:12px;
    }}
    .arch-tier-label {{
      display:flex;
      align-items:center;
      gap:10px;
      margin:0 0 10px;
      color:#9fc2dd;
      font-size:11px;
      text-transform:uppercase;
      letter-spacing:.8px;
      font-weight:700;
    }}
    .arch-tier-label::after {{
      content:"";
      height:1px;
      flex:1 1 auto;
      background:linear-gradient(90deg, rgba(56,189,248,.7), rgba(34,197,94,.18));
    }}
    .arch-flow-ribbon {{
      display:grid;
      grid-template-columns: minmax(0, 1fr) 34px minmax(0, 1fr) 34px minmax(0, 1fr) 34px minmax(0, 1fr) 34px minmax(0, 1fr);
      gap:12px;
      align-items:stretch;
      margin-top:14px;
      padding:12px 14px;
      border:1px solid #22384d;
      border-radius:14px;
      background:linear-gradient(180deg, rgba(8,21,37,.94), rgba(7,17,31,.88));
    }}
    .arch-flow-step {{
      display:flex;
      flex-direction:column;
      justify-content:space-between;
      min-height:108px;
      padding:12px;
      border-radius:14px;
      border:1px solid #2a4661;
      background:linear-gradient(180deg, #0b1728, #08111f);
      color:#deecfb;
      box-shadow: inset 0 1px 0 rgba(255,255,255,.03);
    }}
    .arch-flow-step-title {{
      font-size:13px;
      font-weight:800;
      line-height:1.35;
      color:#f2f8ff;
      margin-bottom:8px;
    }}
    .arch-flow-step-copy {{
      font-size:12px;
      line-height:1.5;
      color:#b5c7d8;
    }}
    .arch-flow-step-tag {{
      align-self:flex-start;
      margin-top:10px;
      border-radius:999px;
      border:1px solid #27415a;
      background:#081525;
      color:#8fd8ff;
      padding:4px 8px;
      font-size:10px;
      text-transform:uppercase;
      letter-spacing:.7px;
      font-weight:700;
    }}
    .arch-flow-arrow-node {{
      display:flex;
      align-items:center;
      justify-content:center;
      align-self:center;
      min-height:42px;
      border-radius:999px;
      border:1px solid #24435d;
      background:linear-gradient(180deg, rgba(8,21,37,.94), rgba(7,17,31,.88));
      color:#7dd3fc;
      font-size:18px;
      font-weight:900;
      box-shadow:0 10px 18px rgba(0,0,0,.18);
    }}
    .arch-loop-strip {{
      display:flex;
      flex-wrap:wrap;
      gap:10px;
      align-items:center;
      margin-top:12px;
      padding:10px 12px;
      border:1px dashed #24435d;
      border-radius:14px;
      background:linear-gradient(180deg, rgba(7,17,31,.88), rgba(5,13,24,.84));
    }}
    .arch-loop-chip {{
      display:inline-flex;
      align-items:center;
      min-height:32px;
      padding:6px 10px;
      border-radius:999px;
      border:1px solid #264560;
      background:#081525;
      color:#deecfb;
      font-size:12px;
      line-height:1.3;
      font-weight:700;
    }}
    .arch-loop-arrow {{
      color:#7dd3fc;
      font-size:17px;
      font-weight:900;
      line-height:1;
    }}
    .arch-interop-grid {{
      display:grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap:12px;
      margin-top:14px;
    }}
    .arch-interop-card {{
      border:1px solid #22384d;
      border-radius:14px;
      padding:12px 13px;
      background:linear-gradient(180deg, rgba(11,22,38,.96), rgba(7,17,31,.9));
    }}
    .arch-interop-title {{
      margin:0 0 8px;
      color:#eef6ff;
      font-size:13px;
      font-weight:800;
      text-transform:uppercase;
      letter-spacing:.6px;
    }}
    .arch-interop-line {{
      margin:6px 0;
      color:#c7d4e2;
      font-size:12px;
      line-height:1.5;
    }}
    .arch-interop-line strong {{
      color:#f4f8fd;
      font-weight:800;
    }}
    .arch-pill-row {{
      display:flex;
      flex-wrap:wrap;
      gap:8px;
      margin-top:12px;
    }}
    .arch-pill {{
      display:inline-flex;
      align-items:center;
      border-radius:999px;
      border:1px solid #2c4660;
      background:linear-gradient(180deg, #091726, #08111f);
      color:#dbeafe;
      padding:4px 10px;
      font-size:12px;
      line-height:1.2;
    }}
    .arch-panels {{ display:grid; grid-template-columns: repeat(3,minmax(0,1fr)); gap:12px; margin-top:14px; }}
    .arch-panel {{ background:linear-gradient(180deg, rgba(11,18,32,.96), rgba(8,17,31,.92)); border:1px solid #213246; border-radius:14px; padding:14px; }}
    .arch-panel h3 {{ margin-top:0; margin-bottom:10px; font-size:16px; color:#eff6ff; }}
    .arch-panel p, .arch-panel li {{ color:#c4d1df; }}
    .arch-detail-shell {{
      margin-top:16px;
      border:1px solid #22384d;
      border-radius:14px;
      background:linear-gradient(180deg, rgba(8,21,37,.92), rgba(7,17,31,.88));
      padding:12px 14px;
    }}
    .arch-detail-shell summary {{
      cursor:pointer;
      color:#e8f2fc;
      font-weight:800;
      font-size:14px;
      list-style:none;
    }}
    .arch-detail-shell summary::-webkit-details-marker {{ display:none; }}
    .arch-detail-sub {{
      color:#97adc2;
      font-size:12px;
      margin-top:4px;
      line-height:1.5;
    }}
    .arch-detail-body {{
      margin-top:14px;
    }}
    .guided {{
      margin-top: 14px;
      background: var(--card2);
      border:1px solid var(--line);
      border-radius:10px;
      padding:10px;
    }}
    .guided summary {{
      cursor:pointer;
      font-weight:700;
      color:#dbeafe;
      margin-bottom:8px;
    }}
    .guided .guided-body {{
      margin-top:8px;
    }}
    .step {{
      margin: 10px 0;
      border:1px solid #243245;
      border-radius:8px;
      padding:8px;
      background:#07111f;
    }}
    .step-title {{
      font-weight:700;
      color:#dbeafe;
      margin-bottom:4px;
      font-size:13px;
    }}
    .mini-flow {{
      margin-top:8px;
      display:flex;
      flex-wrap:wrap;
      align-items:center;
      gap:6px;
    }}
    .mini-node {{
      display:inline-block;
      background:#0b2130;
      border:1px solid #1d4f66;
      border-radius:6px;
      color:#dbeafe;
      padding:4px 8px;
      font-family: "Consolas", "SFMono-Regular", Menlo, monospace;
      font-size:11px;
      line-height:1.3;
    }}
    .mini-arrow {{
      color:#93c5fd;
      font-weight:700;
      font-size:14px;
      line-height:1;
    }}
    .welcome-modal-backdrop {{
      position:fixed;
      inset:0;
      display:none;
      align-items:center;
      justify-content:center;
      padding:20px;
      background:rgba(2,6,23,.62);
      backdrop-filter:blur(8px);
      z-index:120;
    }}
    .welcome-modal-backdrop.open {{ display:flex; }}
    .welcome-modal {{
      width:min(540px,94vw);
      border:1px solid #294560;
      border-radius:22px;
      padding:22px;
      background:linear-gradient(165deg,#091727,#07111f 58%,#0b1d17);
      box-shadow:0 28px 60px rgba(0,0,0,.42);
    }}
    .welcome-kicker {{
      display:inline-flex;
      align-items:center;
      gap:8px;
      padding:6px 10px;
      border-radius:999px;
      border:1px solid #294560;
      background:#0b2130;
      color:#bde6ff;
      font-size:12px;
      font-weight:800;
    }}
    .welcome-title {{
      margin:14px 0 8px;
      font-size:28px;
      line-height:1.05;
      letter-spacing:.2px;
      color:#f8fafc;
    }}
    .welcome-copy {{
      margin:0 0 16px;
      color:#a8bfd7;
      font-size:14px;
      line-height:1.65;
    }}
    .welcome-actions {{
      display:flex;
      gap:10px;
      flex-wrap:wrap;
      align-items:center;
    }}
    .welcome-btn {{
      appearance:none;
      border:1px solid #315a79;
      border-radius:14px;
      padding:12px 16px;
      background:linear-gradient(180deg,#16324a,#102435);
      color:#dbeafe;
      font-weight:900;
      cursor:pointer;
      font-size:14px;
    }}
    .welcome-btn.primary {{
      border:0;
      background:linear-gradient(135deg,#22c55e,#16a34a);
      color:#03230f;
    }}
    .shell-footer {{
      display:flex;
      justify-content:flex-end;
      margin-top:14px;
      color:#8ca3b8;
      font-size:12px;
    }}
    .shell-version {{
      display:inline-flex;
      align-items:center;
      gap:8px;
      padding:8px 12px;
      border:1px solid rgba(42,68,92,.72);
      border-radius:999px;
      background:linear-gradient(180deg, rgba(6,16,28,.82), rgba(4,11,20,.72));
      box-shadow:inset 0 1px 0 rgba(255,255,255,.03);
    }}
    @media (max-width: 980px) {{
      .layout {{ grid-template-columns: 1fr; gap:14px; }}
      .docs-sidebar {{
        position: relative;
        border-right:0;
        margin-right:0;
        padding-right:0;
      }}
      .hero {{ grid-template-columns: 1fr; }}
      .guide-grid {{ grid-template-columns: 1fr; }}
      .arch-hero {{ grid-template-columns: 1fr; }}
      .arch-summary-grid {{ grid-template-columns: 1fr; }}
      .arch-visio {{ grid-template-columns: 1fr; }}
      .arch-endpoint-grid {{ grid-template-columns: 1fr; }}
      .arch-connection-band {{ grid-template-columns: 1fr; }}
      .arch-handoff-grid {{ grid-template-columns: 1fr; }}
      .arch-map {{ grid-template-columns: 1fr; }}
      .arch-subgrid {{ grid-template-columns: 1fr; }}
      .arch-flow-ribbon {{ grid-template-columns: 1fr; }}
      .arch-flow-arrow-node {{ min-height:28px; }}
      .arch-interop-grid {{ grid-template-columns: 1fr; }}
      .arch-panels {{ grid-template-columns: 1fr; }}
      .env-list {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body data-smith-user="{onboarding_user}" data-smith-role="{onboarding_role}">
  <div class=\"wrap\">
    {nav}
    {body}
    <div class=\"shell-footer\"><span class=\"shell-version\">A.G.E.N.T. Smith {app_version}</span></div>
  </div>
  {onboarding_modal}
  <script type="module">
    import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
    mermaid.initialize({{ startOnLoad: true, theme: 'dark', securityLevel: 'loose' }});
    window.mermaid = mermaid;
  </script>
  <script>
    (() => {{
      const role = document.body.getAttribute('data-smith-role') || '';
      const username = document.body.getAttribute('data-smith-user') || '';
      const path = window.location.pathname || '';
      if(role !== 'admin' || !username || path !== '/') {{
        return;
      }}
      const snoozeKey = `smith-admin-config-snooze:${{username}}`;
      const skipKey = `smith-admin-config-skip:${{username}}`;
      if(window.localStorage.getItem(snoozeKey) === '1') {{
        return;
      }}
      if(window.sessionStorage.getItem(skipKey) === '1') {{
        return;
      }}
      const backdrop = document.getElementById('smith-welcome-modal');
      if(!backdrop) {{
        return;
      }}
      const open = () => backdrop.classList.add('open');
      const close = () => backdrop.classList.remove('open');
      window.setTimeout(open, 220);
      const goBtn = document.getElementById('smith-welcome-go');
      const skipBtn = document.getElementById('smith-welcome-skip');
      const snoozeBtn = document.getElementById('smith-welcome-snooze');
      if(goBtn) {{
        goBtn.onclick = () => {{
          close();
          window.location.href = '/configure';
        }};
      }}
      if(skipBtn) {{
        skipBtn.onclick = () => {{
          window.sessionStorage.setItem(skipKey, '1');
          fetch('/api/session/onboarding', {{
            method:'POST',
            headers:{{'Content-Type':'application/json'}},
            body: JSON.stringify({{ action:'skip' }})
          }}).finally(() => close());
        }};
      }}
      if(snoozeBtn) {{
        snoozeBtn.onclick = () => {{
          window.localStorage.setItem(snoozeKey, '1');
          close();
        }};
      }}
      backdrop.addEventListener('click', (event) => {{
        if(event.target === backdrop) {{
          window.sessionStorage.setItem(skipKey, '1');
          close();
        }}
      }});
    }})();
  </script>
</body>
</html>
"""


def _safe_docs_path(path_value: str) -> Path | None:
    if not path_value:
        return None
    resolved = (DOCS_ROOT / path_value).resolve()
    try:
        resolved.relative_to(DOCS_ROOT.resolve())
    except Exception:
        return None
    if not resolved.exists() or not resolved.is_file():
        return None
    return resolved


def _list_docs_files() -> list[str]:
    files: list[str] = []
    if not DOCS_ROOT.exists():
        return files
    for p in DOCS_ROOT.rglob("*"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(DOCS_ROOT))
        if rel.startswith("logs/"):
            continue
        if rel == "build_log.md":
            continue
        if p.suffix.lower() not in {".md", ".json", ".csv", ".txt"}:
            continue
        files.append(rel)
    return sorted(files)


DOC_SECTION_ORDER = [
    "Start Here",
    "Business View",
    "Platform Details",
    "Architecture",
    "Operator Guides",
    "Reference",
]

DOC_LABELS: dict[str, tuple[str, str]] = {
    "whitepapers/project_one_page_white_paper.md": (
        "What A.G.E.N.T. Smith Is",
        "Best first read for leaders and new users.",
    ),
    "project_overview.md": (
        "Documentation Guide",
        "Where to start and where to go next.",
    ),
    "whitepapers/executive_white_paper.md": (
        "Executive Summary",
        "Business value, controls, and readiness framing.",
    ),
    "whitepapers/technical_deep_dive.md": (
        "Technical Deep Dive",
        "Architecture, runtime flow, controls, and planned expansion.",
    ),
    "architecture/system_design.md": (
        "System Design",
        "Current platform shape and planned extensions.",
    ),
    "architecture/network_diagram.md": (
        "Network Diagram",
        "Hosts, trust boundaries, ports, and future components.",
    ),
    "architecture/tdir_core_blueprint.md": (
        "TDIR Blueprint",
        "Current Detect, Triage, and Investigate operating model.",
    ),
    "runbooks/health_check.md": (
        "Health Check",
        "Short post-install health check for an already-configured runtime.",
    ),
    "runbooks/initial_setup.md": (
        "Initial Setup Guide",
        "Step-by-step setup for a new machine and new operator.",
    ),
    "runbooks/demo_walkthrough.md": (
        "Demo Walkthrough",
        "Recommended presentation path for stakeholders.",
    ),
    "runbooks/daily_ops.md": (
        "Daily Operations",
        "Routine checks for the current deployment.",
    ),
    "model_strategy.md": (
        "Model Strategy",
        "Why each model role exists and how they are used.",
    ),
    "splunk_integration.md": (
        "Splunk Integration",
        "How Splunk MCP access and retrieval are wired.",
    ),
    "langgraph_plan.md": (
        "LangGraph Notes",
        "Historical implementation notes and reference context.",
    ),
}


def _doc_label(path: str) -> tuple[str, str]:
    if path in DOC_LABELS:
        return DOC_LABELS[path]
    stem = Path(path).stem.replace("_", " ").replace("-", " ").strip().title()
    return stem, path


def _doc_section(path: str) -> str:
    if path == "whitepapers/project_one_page_white_paper.md":
        return "Start Here"
    if path == "project_overview.md":
        return "Start Here"
    if path == "whitepapers/executive_white_paper.md":
        return "Business View"
    if path == "whitepapers/technical_deep_dive.md":
        return "Platform Details"
    if path in {"model_strategy.md", "splunk_integration.md"}:
        return "Platform Details"
    if path == "langgraph_plan.md":
        return "Reference"
    if path.startswith("architecture/"):
        return "Architecture"
    if path in {
        "runbooks/daily_ops.md",
        "runbooks/demo_walkthrough.md",
        "runbooks/weekly_maintenance.md",
        "runbooks/spl_quality_pass.md",
    }:
        return "Reference"
    if path.startswith("runbooks/"):
        return "Operator Guides"
    if path.startswith("reference/"):
        return "Reference"
    return "Platform Details"


def _group_docs(files: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for f in files:
        grouped[_doc_section(f)].append(f)
    for key in grouped:
        grouped[key] = sorted(grouped[key], key=lambda p: (_doc_label(p)[0].lower(), p.lower()))
    ordered: dict[str, list[str]] = {}
    for section in DOC_SECTION_ORDER:
        if grouped.get(section):
            ordered[section] = grouped[section]
    for section in sorted(grouped.keys()):
        if section not in ordered:
            ordered[section] = grouped[section]
    return ordered


def _render_docs_sidebar(active_path: str = "") -> str:
    files = _list_docs_files()
    grouped = _group_docs(files)
    sections: list[str] = []
    for section, section_files in grouped.items():
        items = []
        for path in section_files:
            active = " active" if path == active_path else ""
            qp = quote(path)
            label, desc = _doc_label(path)
            items.append(
                f'<a class="doc-link{active}" href="/docs/view?path={qp}" '
                f'data-doc-path="{html.escape(path)}" data-doc-label="{html.escape(label)}">'
                f'<span class="doc-link-title">{html.escape(label)}</span>'
                f'<span class="doc-link-meta">{html.escape(desc)}</span>'
                "</a>"
            )
        open_attr = " open" if section != "Reference" else ""
        sections.append(
            f'<details class="doc-group"{open_attr}>'
            f'<summary class="section-title">{html.escape(section)}</summary>'
            f'<div class="section-links">{"".join(items)}</div>'
            "</details>"
        )
    return "\n".join(sections)


def _render_markdown_simple(text: str) -> str:
    lines = text.splitlines()
    out: list[str] = []
    in_code = False
    code_lang = ""
    in_ul = False
    in_ol = False

    def render_inline(value: str) -> str:
        placeholders: dict[str, str] = {}
        token_index = 0

        def stash(rendered: str) -> str:
            nonlocal token_index
            token = f"__INLINE_TOKEN_{token_index}__"
            token_index += 1
            placeholders[token] = rendered
            return token

        def _code_repl(match: re.Match[str]) -> str:
            return stash(f"<code>{html.escape(match.group(1))}</code>")

        def _link_repl(match: re.Match[str]) -> str:
            label = render_inline(match.group(1))
            href = html.escape(match.group(2), quote=True)
            return stash(f'<a href="{href}">{label}</a>')

        value = re.sub(r"`([^`]+)`", _code_repl, value)
        value = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", _link_repl, value)
        rendered = html.escape(value)
        for token, replacement in placeholders.items():
            rendered = rendered.replace(token, replacement)
        return rendered

    def close_lists() -> None:
        nonlocal in_ul, in_ol
        if in_ul:
            out.append("</ul>")
            in_ul = False
        if in_ol:
            out.append("</ol>")
            in_ol = False

    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()

        if stripped.startswith("```"):
            close_lists()
            if not in_code:
                code_lang = stripped[3:].strip().lower()
                if code_lang == "mermaid":
                    out.append('<div class="mermaid">')
                else:
                    out.append("<pre><code>")
                in_code = True
            else:
                if code_lang == "mermaid":
                    out.append("</div>")
                else:
                    out.append("</code></pre>")
                in_code = False
                code_lang = ""
            continue

        if in_code:
            out.append(html.escape(line))
            continue

        if not stripped:
            close_lists()
            out.append("")
            continue

        if (
            stripped.startswith("<details")
            or stripped.startswith("</details")
            or stripped.startswith("<summary")
            or stripped.startswith("</summary")
        ):
            close_lists()
            out.append(stripped)
            continue

        if stripped.startswith("### "):
            close_lists()
            out.append(f"<h3>{render_inline(stripped[4:])}</h3>")
            continue
        if stripped.startswith("## "):
            close_lists()
            out.append(f"<h2>{render_inline(stripped[3:])}</h2>")
            continue
        if stripped.startswith("# "):
            close_lists()
            out.append(f"<h1>{render_inline(stripped[2:])}</h1>")
            continue

        if stripped.startswith("- "):
            if in_ol:
                out.append("</ol>")
                in_ol = False
            if not in_ul:
                out.append("<ul>")
                in_ul = True
            out.append(f"<li>{render_inline(stripped[2:])}</li>")
            continue

        if len(stripped) > 2 and stripped[0].isdigit() and stripped[1] == "." and stripped[2] == " ":
            if in_ul:
                out.append("</ul>")
                in_ul = False
            if not in_ol:
                out.append("<ol>")
                in_ol = True
            out.append(f"<li>{render_inline(stripped[3:])}</li>")
            continue

        close_lists()
        out.append(f"<p>{render_inline(stripped)}</p>")

    close_lists()
    if in_code:
        if code_lang == "mermaid":
            out.append("</div>")
        else:
            out.append("</code></pre>")
    rendered = "\n".join(out)
    rendered = rendered.replace("<pre><code>\n", "<pre><code>")
    rendered = rendered.replace('<div class="mermaid">\n', '<div class="mermaid">')
    return rendered


def _architecture_svg() -> str:
    return """
<div class="arch-tier">
  <div class="arch-tier-label">Primary Runtime</div>
  <div class="arch-map" role="img" aria-label="A.G.E.N.T. Smith architecture map">
    <section class="arch-box">
      <div class="arch-box-label">Orchestration</div>
      <h3>Controller Node (Linux host, for example a Raspberry Pi)</h3>
      <ul>
        <li><code>web_ui_server.py</code> serves the LAN UI on port <code>8787</code>.</li>
        <li>Runs the minimal, multi-model, and agentic investigation flows.</li>
        <li>Applies guardrails, query-policy checks, and deterministic execution gates.</li>
        <li>Handles MCP client calls, evidence packaging, and response assembly.</li>
        <li>Agentic controller logic enforces bounded pivots and completion decisions.</li>
        <li>Docs portal reads <code>docs/</code> directly and publishes the current platform narrative.</li>
      </ul>
      <div class="arch-note">Trust boundary: Splunk tools execute only after deterministic checks pass. Unsafe or non-read-only requests are blocked before execution.</div>
    </section>
    <section class="arch-box secondary">
      <div class="arch-box-label">Reasoning Layer</div>
      <h3>LLM Host (Windows + RTX 3090)</h3>
      <ul>
        <li>Remote Ollama API on <code>:11434</code>.</li>
        <li>Planner uses Qwen to interpret the question and produce a structured search plan.</li>
        <li>SPL Writer uses DeepSeek to turn that plan into bounded read-only SPL.</li>
        <li>Security Reviewer uses Foundation-Sec for security-oriented quality and safety critique.</li>
        <li>Peer Reviewer 1 only runs when the reviewer does not cleanly approve the writer output.</li>
        <li>Peer Reviewer 2 verifies or overrides that adjudication when it is needed.</li>
        <li>Evidence Reviewer uses Foundation-Sec to check executed rows against the claim set.</li>
        <li>Continuation Reviewer uses Foundation-Sec to decide whether another bounded pivot is warranted.</li>
        <li>Controller model supports bounded orchestration in the agentic path.</li>
        <li>Final Summary uses Foundation-Sec to produce the analyst-facing narrative.</li>
      </ul>
      <div class="arch-pill-row">
        <span class="arch-pill">write</span>
        <span class="arch-pill">review</span>
        <span class="arch-pill">adjudicate</span>
        <span class="arch-pill">verify</span>
        <span class="arch-pill">evidence-check</span>
        <span class="arch-pill">continue?</span>
        <span class="arch-pill">summarize</span>
      </div>
    </section>
    <section class="arch-box tertiary">
      <div class="arch-box-label">Grounding Layer</div>
      <h3>Analyst Data Domains</h3>
      <ul>
        <li>Windows authentication and endpoint-relevant telemetry.</li>
        <li>Linux auth, sudo, and related host activity.</li>
        <li>Apache web activity including <code>access_combined</code>.</li>
        <li>Index, sourcetype, tag, metadata, and known-field inventory used for environment-aware planning.</li>
      </ul>
      <div class="arch-note">All retrieval paths are read-only in the current platform build.</div>
    </section>
  </div>
</div>
<div class="arch-tier" style="margin-top:14px;">
  <div class="arch-tier-label">Interconnectivity</div>
  <div class="arch-flow-ribbon" aria-label="Architecture flow sequence">
    <div class="arch-flow-step">
      <div>
        <div class="arch-flow-step-title">1. Analyst question enters A.G.E.N.T. Smith</div>
        <div class="arch-flow-step-copy">The browser sends the investigation request to the Pi-hosted control plane through the authenticated web UI.</div>
      </div>
      <div class="arch-flow-step-tag">UI to controller</div>
    </div>
    <div class="arch-flow-arrow-node" aria-hidden="true">&rarr;</div>
    <div class="arch-flow-step">
      <div>
        <div class="arch-flow-step-title">2. Controller engages model roles</div>
        <div class="arch-flow-step-copy">The controller sends the question, RAG context, and constraints to the remote reasoning stack for planning and review.</div>
      </div>
      <div class="arch-flow-step-tag">control to reasoning</div>
    </div>
    <div class="arch-flow-arrow-node" aria-hidden="true">&rarr;</div>
    <div class="arch-flow-step">
      <div>
        <div class="arch-flow-step-title">3. Environment context grounds the plan</div>
        <div class="arch-flow-step-copy">Index, sourcetype, tag, metadata, and known-field awareness feed back into the model decision path so SPL is shaped by the real environment.</div>
      </div>
      <div class="arch-flow-step-tag">grounding loop</div>
    </div>
    <div class="arch-flow-arrow-node" aria-hidden="true">&rarr;</div>
    <div class="arch-flow-step">
      <div>
        <div class="arch-flow-step-title">4. Splunk MCP executes bounded retrieval</div>
        <div class="arch-flow-step-copy">After deterministic validation, the controller calls the approved read-only MCP tool against Splunk and gets structured results back.</div>
      </div>
      <div class="arch-flow-step-tag">validated execution</div>
    </div>
    <div class="arch-flow-arrow-node" aria-hidden="true">&rarr;</div>
    <div class="arch-flow-step">
      <div>
        <div class="arch-flow-step-title">5. Evidence returns to UI and storage</div>
        <div class="arch-flow-step-copy">Returned rows are reviewed, continuation is assessed, the summary is rendered to the analyst, and optional artifacts are written for later inspection.</div>
      </div>
      <div class="arch-flow-step-tag">results and persistence</div>
    </div>
  </div>
  <div class="arch-loop-strip" aria-label="Architecture feedback loops">
    <span class="arch-loop-chip">Data Domains</span>
    <span class="arch-loop-arrow" aria-hidden="true">&rarr;</span>
    <span class="arch-loop-chip">Planner and Security Review Prompts</span>
    <span class="arch-loop-arrow" aria-hidden="true">&rarr;</span>
    <span class="arch-loop-chip">Deterministic Policy Gate</span>
    <span class="arch-loop-arrow" aria-hidden="true">&rarr;</span>
    <span class="arch-loop-chip">Splunk MCP Retrieval</span>
    <span class="arch-loop-arrow" aria-hidden="true">&rarr;</span>
    <span class="arch-loop-chip">Evidence Reviewer</span>
    <span class="arch-loop-arrow" aria-hidden="true">&rarr;</span>
    <span class="arch-loop-chip">Continuation Reviewer</span>
    <span class="arch-loop-arrow" aria-hidden="true">&rarr;</span>
    <span class="arch-loop-chip">Analyst UI and Artifacts</span>
  </div>
  <div class="arch-interop-grid">
    <div class="arch-interop-card">
      <div class="arch-interop-title">Control Path</div>
      <div class="arch-interop-line"><strong>Browser</strong> -> <strong>Pi Controller</strong> for authenticated request handling.</div>
      <div class="arch-interop-line"><strong>Pi Controller</strong> -> <strong>optional edge helper</strong> -> <strong>primary inference host</strong> for staged routing and reasoning roles.</div>
    </div>
    <div class="arch-interop-card">
      <div class="arch-interop-title">Grounding Path</div>
      <div class="arch-interop-line"><strong>Data Domains</strong> -> <strong>planner/security-review prompts</strong> for environment-aware SPL generation using known fields where available.</div>
      <div class="arch-interop-line"><strong>RAG snippets</strong> -> <strong>query repair and critique</strong> for higher-quality searches.</div>
    </div>
    <div class="arch-interop-card">
      <div class="arch-interop-title">Execution Path</div>
      <div class="arch-interop-line"><strong>Validated plan</strong> -> <strong>Splunk MCP</strong> -> <strong>Splunk Platform</strong>.</div>
      <div class="arch-interop-line"><strong>Structured results</strong> -> <strong>evidence reviewer</strong> -> <strong>continuation reviewer</strong> -> <strong>summary model</strong>.</div>
    </div>
    <div class="arch-interop-card">
      <div class="arch-interop-title">Persistence Path</div>
      <div class="arch-interop-line"><strong>Documentation</strong> stays in <code>docs/</code> and feeds the web portal.</div>
      <div class="arch-interop-line"><strong>Runtime outputs</strong> can be written to <code>artifacts/runs/</code> without polluting docs.</div>
    </div>
  </div>
</div>
<div class="arch-tier" style="margin-top:14px;">
  <div class="arch-tier-label">Platform Surfaces</div>
  <div class="arch-subgrid">
    <section class="arch-box secondary">
      <div class="arch-box-label">Retrieval Layer</div>
      <h3>Splunk Server</h3>
      <ul>
        <li>MCP endpoint: <code>:8089/services/mcp</code></li>
        <li>Read-only tools in current use: <code>splunk_run_query</code>, <code>splunk_get_indexes</code>, <code>splunk_get_metadata</code>, <code>splunk_get_info</code></li>
        <li>Queries are executed only after model output clears deterministic validation.</li>
      </ul>
    </section>
    <section class="arch-box">
      <div class="arch-box-label">Persistence Layer</div>
      <h3>Artifacts and Documentation</h3>
      <ul>
        <li>Documentation is maintained under <code>docs/</code> and exposed in the web UI.</li>
        <li>Runtime artifacts are stored separately under <code>artifacts/runs/</code>.</li>
        <li>The architecture page describes implemented behavior first; planned items are documented separately.</li>
      </ul>
    </section>
  </div>
</div>
"""


def _docs_index_body() -> str:
    sidebar = _render_docs_sidebar()
    body = f"""
<div class=\"layout\">
  <aside class=\"docs-sidebar\">
    <h1 class=\"docs-rail-title\">Documentation</h1>
    <p class=\"docs-rail-sub\">Organized for leaders first, operators second, deep reference last.</p>
    <input id=\"doc-filter\" class=\"search\" type=\"text\" placeholder=\"Filter docs by topic or title...\" />
    {sidebar}
  </aside>
  <main class=\"docs-main\">
    <h1>A.G.E.N.T. Smith Documentation</h1>
    <div class=\"hero\">
      <div class=\"card\">
        <h2>Start Here</h2>
        <p>If you are new to A.G.E.N.T. Smith, begin with the business overview and then move into the technical architecture only if you need deeper detail.</p>
        <p><a href=\"/docs\">Open the business overview</a></p>
      </div>
      <div class=\"card\">
        <h2>How To Use This Section</h2>
        <p><span class=\"badge\">Audience-first layout</span></p>
        <p>Business readers should start with overview and roadmap material. Technical readers should then move into architecture, flow, and operator guides.</p>
      </div>
    </div>
    <div class=\"guide-grid\">
      <div class=\"guide-card\">
        <h2>What Is This?</h2>
        <p>Use these if you want the business story, problem statement, current value, and roadmap direction.</p>
        <div class=\"guide-links\">
          <a class=\"guide-link\" href=\"/docs/view?path=whitepapers/project_one_page_white_paper.md\"><strong>What A.G.E.N.T. Smith Is</strong><span>Fastest explanation for non-technical readers.</span></a>
          <a class=\"guide-link\" href=\"/docs/view?path=runbooks/initial_setup.md\"><strong>Initial Setup Guide</strong><span>Step-by-step install and configuration for a new machine.</span></a>
          <a class=\"guide-link\" href=\"/docs/view?path=whitepapers/executive_white_paper.md\"><strong>Executive Summary</strong><span>Value, controls, and readiness framing for leadership.</span></a>
          <a class=\"guide-link\" href=\"/docs/view?path=project_overview.md\"><strong>Documentation Guide</strong><span>Reading order and major entry points.</span></a>
        </div>
      </div>
      <div class=\"guide-card\">
        <h2>How Does It Work?</h2>
        <p>Use these if you need architecture, runtime flow, or current-versus-planned design detail.</p>
        <div class=\"guide-links\">
          <a class=\"guide-link\" href=\"/docs/view?path=whitepapers/technical_deep_dive.md\"><strong>Technical Deep Dive</strong><span>Best technical overview of runtime flow and controls.</span></a>
          <a class=\"guide-link\" href=\"/docs/view?path=architecture/system_design.md\"><strong>System Design</strong><span>Current system shape and planned extensions.</span></a>
          <a class=\"guide-link\" href=\"/architecture\"><strong>Architecture Graph</strong><span>Visual map of components, roles, and trust boundaries.</span></a>
        </div>
      </div>
      <div class=\"guide-card\">
        <h2>What Can It Do Today?</h2>
        <p>Use these if you want the implemented operating model, data domains, and day-to-day workflow entry points.</p>
        <div class=\"guide-links\">
          <a class=\"guide-link\" href=\"/docs/view?path=architecture/tdir_core_blueprint.md\"><strong>TDIR Blueprint</strong><span>Current Detect, Triage, and Investigate capability.</span></a>
          <a class=\"guide-link\" href=\"/environment\"><strong>Data Domains</strong><span>Indexes, sourcetypes, and environment-aware query grounding.</span></a>
          <a class=\"guide-link\" href=\"/investigation\"><strong>Investigation UI</strong><span>Main analyst-facing workflow surface.</span></a>
        </div>
      </div>
      <div class=\"guide-card\">
        <h2>How Do We Operate It?</h2>
        <p>Use these if you are bringing up the platform, running a demo, or managing the current environment.</p>
        <div class=\"guide-links\">
          <a class=\"guide-link\" href=\"/docs/view?path=runbooks/health_check.md\"><strong>Health Check</strong><span>Short post-install validation for an already-configured runtime.</span></a>
          <a class=\"guide-link\" href=\"/docs/view?path=runbooks/demo_walkthrough.md\"><strong>Demo Walkthrough</strong><span>Presentation path for stakeholders.</span></a>
          <a class=\"guide-link\" href=\"/docs/view?path=runbooks/daily_ops.md\"><strong>Daily Operations</strong><span>Routine operational checks.</span></a>
        </div>
      </div>
    </div>
  </main>
</div>
<script>
  const filter = document.getElementById('doc-filter');
  if (filter) {{
    filter.addEventListener('input', () => {{
      const q = filter.value.trim().toLowerCase();
      document.querySelectorAll('.doc-link[data-doc-path]').forEach((el) => {{
        const txt = ((el.getAttribute('data-doc-path') || '') + ' ' + (el.getAttribute('data-doc-label') || '')).toLowerCase();
        el.style.display = txt.includes(q) ? 'block' : 'none';
      }});
    }});
  }}
</script>
"""
    return body


def _docs_view_body(path_value: str) -> str:
    doc_path = _safe_docs_path(path_value)
    sidebar = _render_docs_sidebar(path_value)
    if doc_path is None:
        return f"""
<div class=\"layout\">
  <aside class=\"docs-sidebar\">
    <h1 class=\"docs-rail-title\">Documentation</h1>
    <p class=\"docs-rail-sub\">Browse by topic. The navigation stays visible while reading.</p>
    {sidebar}
  </aside>
  <main class=\"docs-main\">
    <h1>Not Found</h1>
    <p class=\"muted\">Invalid docs path: <code>{html.escape(path_value)}</code></p>
    <p><a href=\"/docs\">Back to Documentation Landing</a></p>
    <p><a href=\"/docs/index\">Open Docs Index</a></p>
  </main>
</div>
"""

    text = doc_path.read_text(encoding="utf-8", errors="replace")
    rel = str(doc_path.relative_to(DOCS_ROOT))
    if doc_path.suffix.lower() == ".md":
        rendered = _render_markdown_simple(text)
    else:
        rendered = f"<pre>{html.escape(text)}</pre>"

    qpath = quote(rel)
    if rel == "whitepapers/project_one_page_white_paper.md":
        rendered = rendered.replace(
            "<h1>A.G.E.N.T. Smith</h1>",
            (
                '<h1 class="doc-brand-title">'
                '<span>A.G.E.N.T. Smith</span>'
                '<img class="doc-brand-icon" src="/favicon.svg?v=agtsmith1" alt="A.G.E.N.T. Smith icon" />'
                "</h1>"
            ),
            1,
        )
    return f"""
<div class=\"layout\">
  <aside class=\"docs-sidebar\">
    <h1 class=\"docs-rail-title\">Documentation</h1>
    <p class=\"docs-rail-sub\">Browse by topic. The navigation stays visible while reading.</p>
    <a class=\"doc-link\" href=\"/docs\">Back to documentation landing</a>
    <a class=\"doc-link\" href=\"/docs/index\">Open docs index</a>
    <a class=\"doc-link\" href=\"/docs/raw?path={qpath}\">Raw view</a>
    {sidebar}
  </aside>
  <main class=\"docs-main\">
    {rendered}
  </main>
</div>
"""


def _favicon_preview_body() -> str:
    return """
<div class=\"card\">
  <h1>A.G.E.N.T. Smith Favicon Preview</h1>
  <p class=\"muted\">Large preview for visual verification.</p>
  <div style=\"display:flex; gap:14px; flex-wrap:wrap; align-items:flex-start;\">
    <div class=\"card\" style=\"max-width:420px;\">
      <h3>320px</h3>
      <img src=\"/favicon.svg?v=agtsmith1\" alt=\"A.G.E.N.T. Smith favicon\" width=\"320\" height=\"320\" style=\"background:#020617; border:1px solid #223245; border-radius:10px;\" />
    </div>
    <div class=\"card\" style=\"max-width:220px;\">
      <h3>128px</h3>
      <img src=\"/favicon.svg?v=agtsmith1\" alt=\"A.G.E.N.T. Smith favicon\" width=\"128\" height=\"128\" style=\"background:#020617; border:1px solid #223245; border-radius:10px;\" />
    </div>
  </div>
  <p><a href=\"/favicon.svg?v=agtsmith1\">Open raw SVG</a></p>
</div>
"""


def _architecture_page_body() -> str:
    return f"""
<div class="card">
  <div class="arch-hero">
    <div class="arch-hero-card">
      <div class="arch-kicker">Architecture</div>
      <h2>A.G.E.N.T. Smith - TLDR</h2>
      <p class="arch-hero-lead">A.G.E.N.T. Smith is a guarded Splunk analyst copilot built to help people investigate faster without giving up control, evidence quality, or transparency. It takes natural-language security questions, uses environment-aware context to improve SPL generation, keeps every retrieval path read-only, shows the analyst what query ran and why, and records operator activity so the workflow remains explainable and reviewable. The project is intentionally focused on practical analyst augmentation rather than blind autonomy: better investigations, better SPL, real-data grounding, and clear guardrails first, with optional edge-assisted routing and a separate offline LangGraph eval loop used to test workflow changes before they become the default runtime.</p>
    </div>
  </div>
  <div class="svg-wrap">
    <div class="arch-tier">
      <div class="arch-tier-label">Connected Device Diagram</div>
      <div class="arch-visio" role="img" aria-label="A.G.E.N.T. Smith connected device diagram">
        <svg class="arch-visio-svg" viewBox="0 0 1500 520" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <defs>
            <linearGradient id="archBoxBlue" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#0c1f34"/>
              <stop offset="100%" stop-color="#0a1525"/>
            </linearGradient>
            <linearGradient id="archBoxGreen" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#0f2d27"/>
              <stop offset="100%" stop-color="#0a1a1d"/>
            </linearGradient>
            <linearGradient id="archBoxAmber" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stop-color="#3b2506"/>
              <stop offset="100%" stop-color="#181108"/>
            </linearGradient>
            <marker id="archArrow" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto">
              <path d="M0,0 L10,5 L0,10 z" fill="#7dd3fc"/>
            </marker>
            <marker id="archArrowOptional" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto">
              <path d="M0,0 L10,5 L0,10 z" fill="#fbbf24"/>
            </marker>
          </defs>

          <path d="M190 170 L315 170" stroke="#7dd3fc" stroke-width="4" fill="none" marker-end="url(#archArrow)"/>
          <path d="M605 170 L760 170" stroke="#7dd3fc" stroke-width="4" fill="none" marker-end="url(#archArrow)"/>
          <path d="M1100 170 L1260 170" stroke="#7dd3fc" stroke-width="4" fill="none" marker-end="url(#archArrow)"/>

          <path d="M605 170 C675 170 695 57 760 57 L810 57" stroke="#fbbf24" stroke-width="4" stroke-dasharray="10 8" fill="none" marker-end="url(#archArrowOptional)"/>
          <path d="M1085 57 C1180 57 1180 150 1100 170" stroke="#fbbf24" stroke-width="4" stroke-dasharray="10 8" fill="none" marker-end="url(#archArrowOptional)"/>

          <rect x="40" y="110" rx="22" ry="22" width="150" height="120" fill="url(#archBoxBlue)" stroke="#27506c" stroke-width="2"/>
          <rect x="315" y="90" rx="22" ry="22" width="290" height="160" fill="url(#archBoxBlue)" stroke="#27506c" stroke-width="2"/>
          <rect x="760" y="90" rx="22" ry="22" width="340" height="160" fill="url(#archBoxGreen)" stroke="#2b5a52" stroke-width="2"/>
          <rect x="1260" y="90" rx="22" ry="22" width="190" height="160" fill="url(#archBoxBlue)" stroke="#27506c" stroke-width="2"/>
          <rect x="810" y="5" rx="22" ry="22" width="275" height="96" fill="url(#archBoxAmber)" stroke="#7a5a1d" stroke-width="2"/>

          <text x="58" y="138" fill="#8fd8ff" font-size="11" font-weight="700" letter-spacing=".08em">USER DEVICE</text>
          <text x="58" y="168" fill="#f5f9ff" font-size="20" font-weight="800">Analyst</text>
          <text x="58" y="192" fill="#f5f9ff" font-size="20" font-weight="800">Browser</text>
          <text x="58" y="218" fill="#8fb0cb" font-size="12">Authenticated UI</text>

          <text x="338" y="118" fill="#8fd8ff" font-size="12" font-weight="700" letter-spacing=".08em">CONTROL PLANE</text>
          <text x="338" y="150" fill="#f5f9ff" font-size="23" font-weight="800">Linux Controller Host</text>
          <text x="338" y="178" fill="#bfd0df" font-size="12">Web UI, LangGraph, validation,</text>
          <text x="338" y="198" fill="#bfd0df" font-size="12">audit, docs, Splunk MCP client.</text>
          <text x="338" y="226" fill="#8fb0cb" font-size="12">Always present</text>

          <text x="788" y="118" fill="#9bf7cf" font-size="12" font-weight="700" letter-spacing=".08em">PRIMARY INFERENCE</text>
          <text x="788" y="150" fill="#f5f9ff" font-size="24" font-weight="800">Primary Ollama Host</text>
          <text x="788" y="178" fill="#bfd0df" font-size="13">Qwen plans, DeepSeek writes, Foundation-Sec</text>
          <text x="788" y="198" fill="#bfd0df" font-size="13">reviews evidence, continuation, and summary.</text>
          <text x="788" y="226" fill="#8fb0cb" font-size="13">Main model endpoint</text>

          <text x="1278" y="118" fill="#8fd8ff" font-size="12" font-weight="700" letter-spacing=".08em">DATA PLANE</text>
          <text x="1278" y="150" fill="#f5f9ff" font-size="22" font-weight="800">Splunk + MCP</text>
          <text x="1278" y="178" fill="#bfd0df" font-size="13">Read-only retrieval,</text>
          <text x="1278" y="198" fill="#bfd0df" font-size="13">metadata, evidence.</text>
          <text x="1278" y="226" fill="#8fb0cb" font-size="13">Source of truth</text>

          <text x="830" y="31" fill="#fde68a" font-size="12" font-weight="700" letter-spacing=".08em">OPTIONAL EDGE HELPER</text>
          <text x="830" y="57" fill="#f5f9ff" font-size="18" font-weight="800">Small Edge LLM Device</text>
          <text x="830" y="79" fill="#d6c089" font-size="12">Routing, split-query hints,</text>
          <text x="830" y="95" fill="#d6c089" font-size="12">confidence checks</text>

          <text x="228" y="156" fill="#7dd3fc" font-size="12" font-weight="700">HTTP UI</text>
          <text x="645" y="152" fill="#7dd3fc" font-size="12" font-weight="700">Primary model path</text>
          <text x="1152" y="148" fill="#7dd3fc" font-size="11" font-weight="700">Read-only retrieval</text>
          <text x="630" y="52" fill="#fde68a" font-size="12" font-weight="700">Edge helper enabled path</text>

          <rect x="40" y="300" rx="14" ry="14" width="1420" height="170" fill="#091726" stroke="#24435d" stroke-width="1.5"/>
          <text x="64" y="328" fill="#9fc2dd" font-size="12" font-weight="700" letter-spacing=".08em">FLOW NOTES</text>
          <text x="64" y="356" fill="#bfd0df" font-size="13">1. Browser always talks to the controller.</text>
          <text x="64" y="384" fill="#bfd0df" font-size="13">2. LangGraph on the controller coordinates model calls and any</text>
          <text x="82" y="404" fill="#bfd0df" font-size="13">optional edge-helper branch when enabled.</text>
          <text x="64" y="432" fill="#bfd0df" font-size="13">3. Primary inference host remains mandatory for the main reasoning stack.</text>
          <text x="64" y="454" fill="#bfd0df" font-size="13">4. Only the controller can call Splunk MCP, and only after deterministic validation succeeds.</text>
        </svg>
        <div class="arch-visio-caption">The optional edge helper is a separate role from the Linux controller host. It only appears in the request path when explicitly enabled in Configuration; otherwise the controller sends the grounded prompt directly to the primary inference host.</div>
      </div>
    </div>

    <div class="arch-tier" style="margin-top:14px;">
      <div class="arch-tier-label">Endpoints and Connections</div>
      <div class="arch-endpoint-grid" role="img" aria-label="A.G.E.N.T. Smith endpoint interaction map">
        <section class="arch-endpoint-card">
          <div class="arch-endpoint-kicker">Entry Point</div>
          <div class="arch-endpoint-topline">
            <h3>Analyst Browser</h3>
            <span class="arch-step-badge">1</span>
          </div>
          <p class="arch-endpoint-copy">Accept question. The analyst opens the Investigation UI and submits a natural-language request.</p>
          <div class="arch-endpoint-meta">HTTP UI session<br/>Browser -&gt; <code>/api/ask</code></div>
        </section>
        <section class="arch-endpoint-card">
          <div class="arch-endpoint-kicker">Controller</div>
          <div class="arch-endpoint-topline">
            <h3>Linux Controller Host</h3>
            <span class="arch-step-badge">2</span>
          </div>
          <p class="arch-endpoint-copy">Assemble context. The controller receives the request, adds RAG, environment profile, known fields, policy constraints, and decides whether the optional edge hop is active.</p>
          <div class="arch-endpoint-meta">Receives <code>/api/ask</code><br/>Question -&gt; grounded prompt</div>
        </section>
        <section class="arch-endpoint-card">
          <div class="arch-endpoint-kicker">Optional Routing</div>
          <div class="arch-endpoint-topline">
            <h3>Optional Edge Helper</h3>
            <span class="arch-step-badge">3</span>
          </div>
          <p class="arch-endpoint-copy">Only present if enabled. A small edge-hosted model can classify the question, suggest split-query handling, or emit a confidence hint before the main planner runs. If disabled, this hop does not exist.</p>
          <div class="arch-endpoint-meta">Conditional endpoint<br/>Controller -&gt; edge helper when enabled</div>
        </section>
        <section class="arch-endpoint-card">
          <div class="arch-endpoint-kicker">Reasoning</div>
          <div class="arch-endpoint-topline">
            <h3>Primary Ollama Host</h3>
            <span class="arch-step-badge">4</span>
          </div>
          <p class="arch-endpoint-copy">Run the main model roles. Qwen plans, DeepSeek writes bounded SPL, Foundation-Sec handles the security-facing review path, and peer adjudication remains available when needed. This host remains the primary reasoning engine whether or not the edge helper exists.</p>
          <div class="arch-endpoint-meta">Remote API on <code>:11434</code><br/>Controller -&gt; primary inference host</div>
        </section>
        <section class="arch-endpoint-card">
          <div class="arch-endpoint-kicker">Retrieval</div>
          <div class="arch-endpoint-topline">
            <h3>Splunk MCP Endpoint</h3>
            <span class="arch-step-badge">5</span>
          </div>
          <p class="arch-endpoint-copy">Validate before touch, then retrieve and review. Only approved read-only calls execute here, and returned rows feed evidence review.</p>
          <div class="arch-endpoint-meta">Tools: query, metadata, indexes, info<br/>Approved plan -&gt; rows -&gt; evidence</div>
        </section>
        <section class="arch-endpoint-card">
          <div class="arch-endpoint-kicker">Data and Output</div>
          <div class="arch-endpoint-topline">
            <h3>Splunk + Data Domains</h3>
            <span class="arch-step-badge">6</span>
          </div>
          <p class="arch-endpoint-copy">Return findings. Results are rendered to the analyst while Data Domains and personalization improve future SPL for this environment.</p>
          <div class="arch-endpoint-meta">Indexes, sourcetypes, fields, artifacts<br/>Summary -&gt; UI + optional artifacts</div>
        </section>
      </div>
      <div class="arch-connection-band" aria-label="Primary connection path">
        <div class="arch-connection-link">UI request</div>
        <div class="arch-connection-link arrow">&rarr;</div>
        <div class="arch-connection-link">controller context</div>
        <div class="arch-connection-link arrow">&rarr;</div>
        <div class="arch-connection-link">optional edge routing</div>
        <div class="arch-connection-link arrow">&rarr;</div>
        <div class="arch-connection-link">role prompts</div>
        <div class="arch-connection-link arrow">&rarr;</div>
        <div class="arch-connection-link">validated plan</div>
        <div class="arch-connection-link arrow">&rarr;</div>
        <div class="arch-connection-link">read-only mcp</div>
        <div class="arch-connection-link arrow">&rarr;</div>
        <div class="arch-connection-link">rows + grounding</div>
      </div>
    </div>

    <div class="arch-tier" style="margin-top:14px;">
      <div class="arch-tier-label">What Moves Across The System</div>
      <div class="arch-handoff-grid">
        <div class="arch-handoff-card"><strong>What moves to the edge helper</strong>Only if enabled: compact routing context, cross-platform hints, and bounded split-query questions. No direct Splunk execution authority exists here.</div>
        <div class="arch-handoff-card"><strong>What moves to Ollama</strong>Question, data-domain hints, SPL guidance, known-field examples, and policy constraints.</div>
        <div class="arch-handoff-card"><strong>What moves to Splunk MCP</strong>Only the validated read-only tool call selected by the controller after deterministic checks.</div>
        <div class="arch-handoff-card"><strong>What comes back from Splunk</strong>Structured rows, counts, entities, and metadata used for evidence review and continuation decisions.</div>
        <div class="arch-handoff-card"><strong>What the analyst sees</strong>Evidence-backed summary, executed SPL, returned results, TDIR state, and optional deeper-investigation approval.</div>
      </div>
    </div>
  </div>

  <details class="arch-detail-shell">
    <summary>Show Detailed Component Inventory</summary>
    <div class="arch-detail-sub">Use this for the lower-level role inventory, trust boundaries, and implementation notes. The connected-device diagram and endpoint map above are the primary architecture views.</div>
    <div class="arch-detail-body">
      <div class="arch-panels">
        <div class="arch-panel">
          <h3>Control Plane</h3>
          <ul>
            <li>LangGraph executes orchestration and policy checks on the Linux controller host.</li>
            <li>LAN access is gated by login/session auth before any UI or API execution.</li>
            <li>Model outputs remain advisory until deterministic validation passes.</li>
            <li>If the optional edge helper is disabled, the controller sends questions straight to the primary inference host.</li>
            <li>Deeper Investigation Control enforces one automatic continuation pass, duplicate-pivot blocking, confidence/depth limits, and analyst approval beyond that point.</li>
          </ul>
        </div>
        <div class="arch-panel">
          <h3>Reasoning Roles</h3>
          <ul>
            <li>Optional Edge Helper only runs when explicitly enabled in runtime configuration.</li>
            <li>Its narrow role is routing, split-query hints, and cheap confidence pre-checks.</li>
            <li>Planner uses Qwen to interpret the analyst question and propose the bounded search strategy.</li>
            <li>SPL Writer uses DeepSeek to generate bounded read-only SPL from that plan.</li>
            <li>Security Reviewer uses Foundation-Sec for security-oriented critique and safety review.</li>
            <li>Peer Reviewer 1 and 2 stay available for adjudication when the reviewer contests or materially revises the writer output.</li>
            <li>Evidence Reviewer uses Foundation-Sec to check returned rows against the claim set.</li>
            <li>Continuation Reviewer uses Foundation-Sec to decide whether another bounded pivot is warranted.</li>
            <li>Final Summary uses Foundation-Sec to produce the analyst-facing narrative.</li>
          </ul>
        </div>
        <div class="arch-panel">
          <h3>Data Plane</h3>
          <ul>
            <li>Splunk MCP provides the read-only retrieval tools used in the current build.</li>
            <li>Coverage includes Windows, Linux, and Apache access logs.</li>
            <li>Environment profiles and personalized skillpacks keep SPL tied to local indexes, sourcetypes, and known fields.</li>
            <li>Documentation stays in <code>docs/</code>; runtime artifacts are written to <code>artifacts/runs/</code>.</li>
          </ul>
        </div>
      </div>
      <div class="arch-panels">
        <div class="arch-panel">
          <h3>Current vs Planned</h3>
          <ul>
            <li>Current: Detect, triage, investigate, summarize, and preserve optional artifacts.</li>
            <li>Current: bounded continuation with analyst approval for deeper follow-up.</li>
            <li>Current: edge-helper configuration is baked into setup and runtime config, but it remains inactive unless enabled by the operator.</li>
            <li>Current: offline LangGraph eval and topology experiments run beside the live runtime and do not alter the default path automatically.</li>
            <li>Planned: Respond and Recover workflow guidance beyond manual runbooks.</li>
            <li>Planned: SOAR-connected automation in a later phase.</li>
          </ul>
        </div>
        <div class="arch-panel">
          <h3>Trust Boundaries</h3>
          <ul>
            <li>The browser can ask questions but cannot execute Splunk directly.</li>
            <li>The optional edge helper can suggest routing, but it cannot execute Splunk or bypass controller policy checks.</li>
            <li>The primary model stack can recommend plans but cannot bypass controller policy checks.</li>
            <li>Only the controller can call Splunk MCP, and only after deterministic validation succeeds.</li>
            <li>Artifacts are optional outputs and remain separate from the documentation source tree.</li>
          </ul>
        </div>
        <div class="arch-panel">
          <h3>Persistence</h3>
          <ul>
            <li><code>docs/</code> contains the operator and architecture narrative shown in the portal.</li>
            <li><code>artifacts/runs/</code> stores optional runtime outputs for later inspection.</li>
            <li><code>artifacts/evals/langgraph/</code> stores the gold corpus, eval prompts, and topology experiment outputs used for offline optimization.</li>
            <li>Data Domains and personalization are built from the live environment and not baked into the vanilla deploy image.</li>
          </ul>
        </div>
      </div>
    </div>
  </details>

  <details class="guided">
    <summary>Show Endpoint-Level Walkthrough</summary>
    <div class="guided-body">
      <p class="muted">Default path for the <code>Multi-Model Reviewer</code> pipeline: optional edge helper when enabled, planner, writer, reviewer, optional peer review, deterministic validation, execution.</p>
      <div class="step">
        <div class="step-title">Browser -&gt; Controller</div>
        <div>The analyst question enters the authenticated web UI and is posted to <code>/api/ask</code>.</div>
        <div class="mini-flow">
          <span class="mini-node">Analyst Browser</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Linux Controller Host</span>
        </div>
      </div>
      <div class="step">
        <div class="step-title">Controller -&gt; Optional Edge Helper</div>
        <div>If enabled, the controller can call the small edge model for routing or split-query hints. If disabled, the controller bypasses this step and proceeds directly to the primary inference host.</div>
        <div class="mini-flow">
          <span class="mini-node">Grounded Prompt</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Optional Edge Helper</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Primary Ollama Host</span>
        </div>
      </div>
      <div class="step">
        <div class="step-title">Controller -&gt; Primary Ollama Host</div>
        <div>The controller sends the grounded prompt to the main model stack for planning, writing, critique, adjudication, evidence review, and summary.</div>
        <div class="mini-flow">
          <span class="mini-node">Grounded Prompt</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Primary Ollama Roles</span>
        </div>
      </div>
      <div class="step">
        <div class="step-title">Controller -&gt; Splunk MCP</div>
        <div>Only after deterministic validation passes does the controller send the approved read-only tool call to Splunk MCP.</div>
        <div class="mini-flow">
          <span class="mini-node">Approved Plan</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Splunk MCP</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Splunk Platform</span>
        </div>
      </div>
      <div class="step">
        <div class="step-title">Splunk -&gt; Evidence</div>
        <div>Returned rows are packaged, checked by the evidence reviewer, and then assessed for deeper follow-up.</div>
        <div class="mini-flow">
          <span class="mini-node">Structured Rows</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Evidence Review</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Continuation Decision</span>
        </div>
      </div>
      <div class="step">
        <div class="step-title">Controller -&gt; Analyst</div>
        <div>The final summary, executed SPL, returned rows, and optional artifacts are rendered back into the Investigation UI.</div>
        <div class="mini-flow">
          <span class="mini-node">Summary + Results</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Investigation UI</span><span class="mini-arrow">&rarr;</span><span class="mini-node">Analyst</span>
        </div>
      </div>
      <p class="muted">If the selected pipeline is <code>Agentic Loop</code>, the controller can insert one bounded automatic follow-up round after evidence review and then requires analyst approval before any deeper continuation.</p>
    </div>
  </details>
</div>
"""


def _langgraph_graph_page_body() -> str:
    graph = describe_multi_model_graph()
    canonical = graph.get("canonical", {})
    active = graph.get("active", {})
    topology_settings = graph.get("topology_settings", {})
    notes = graph.get("notes", []) if isinstance(graph.get("notes", []), list) else []
    latest_overlay_html, executed_nodes = _latest_stage_overlay()
    canonical_mermaid = _graph_mermaid(canonical, title="Canonical LangGraph Topology", use_subgraphs=True)
    active_mermaid = _graph_mermaid(active, title="Active LangGraph Topology", executed_nodes=executed_nodes, use_subgraphs=True)
    canonical_mermaid_modal = _graph_mermaid(canonical, title="Canonical LangGraph Topology", direction="LR", use_subgraphs=True, expanded=True, subgraph_direction="TB")
    active_mermaid_modal = _graph_mermaid(active, title="Active LangGraph Topology", executed_nodes=executed_nodes, direction="LR", use_subgraphs=True, expanded=True, subgraph_direction="TB")
    canonical_mermaid_json = json.dumps(canonical_mermaid_modal)
    active_mermaid_json = json.dumps(active_mermaid_modal)
    flag_badges = "".join(
        f'<div class="lg-flag {"enabled" if bool(value) else "disabled"}"><span>{html.escape(str(key))}</span><strong>{html.escape("on" if bool(value) else "off")}</strong></div>'
        for key, value in topology_settings.items()
    )
    note_items = "".join(f"<li>{html.escape(str(item))}</li>" for item in notes)
    return f"""
<div class="card">
  <style>
    .lg-shell{{display:grid;gap:18px;}}
    .lg-hero{{border:1px solid #27415a;border-radius:18px;background:linear-gradient(180deg,#091423,#07111f);padding:18px;display:grid;gap:10px;}}
    .lg-kicker{{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#8fd8ff;font-weight:700;}}
    .lg-hero h1{{margin:0;font-size:34px;line-height:1.1;}}
    .lg-hero p{{margin:0;color:#dbeafe;line-height:1.7;}}
    .lg-grid{{display:grid;grid-template-columns:1fr 1fr;gap:18px;}}
    .lg-card{{border:1px solid #27415a;border-radius:18px;background:linear-gradient(180deg,#091423,#07111f);padding:18px;display:grid;gap:12px;}}
    .lg-card h2{{margin:0;font-size:20px;}}
    .lg-card .muted{{margin:0;color:#9fc2dd;line-height:1.6;}}
    .lg-flags{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;}}
    .lg-flag{{border:1px solid #254059;border-radius:14px;padding:10px 12px;background:#07111f;display:flex;justify-content:space-between;gap:12px;align-items:center;}}
    .lg-flag span{{font-size:12px;color:#bfd0df;word-break:break-word;}}
    .lg-flag strong{{font-size:13px;text-transform:uppercase;letter-spacing:.05em;}}
    .lg-flag.enabled{{border-color:#166534;background:#062313;color:#dcfce7;}}
    .lg-flag.disabled{{border-color:#5b4557;background:#1a1220;color:#f5d0fe;}}
    .lg-run-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;}}
    .lg-run-card{{border:1px solid #27415a;border-radius:14px;background:#07111f;padding:12px;display:grid;gap:8px;}}
    .lg-run-head{{display:flex;justify-content:space-between;gap:10px;align-items:center;}}
    .lg-run-stage{{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#8fd8ff;font-weight:700;}}
    .lg-run-ms{{font-size:12px;color:#9fc2dd;}}
    .lg-run-title{{font-size:13px;color:#f8fafc;font-weight:700;line-height:1.5;}}
    .lg-run-detail{{font-size:12px;color:#bfd0df;line-height:1.5;}}
    .lg-meta{{font-size:12px;color:#9fc2dd;line-height:1.6;overflow-wrap:anywhere;}}
    .lg-table-wrap{{overflow:auto;}}
    .lg-table{{width:100%;border-collapse:collapse;font-size:12px;}}
    .lg-table th,.lg-table td{{border-bottom:1px solid #203549;padding:9px 10px;text-align:left;color:#dbeafe;vertical-align:top;}}
    .lg-table th{{font-size:11px;color:#8fd8ff;text-transform:uppercase;letter-spacing:.08em;}}
    .lg-muted{{color:#9fc2dd;line-height:1.6;}}
    .lg-notes{{margin:0;padding-left:18px;color:#dbeafe;line-height:1.7;}}
    .lg-actions{{display:flex;gap:10px;flex-wrap:wrap;}}
    .lg-actions code{{background:#07111f;border:1px solid #254059;border-radius:10px;padding:8px 10px;display:inline-block;color:#dbeafe;}}
    .lg-graph-card{{position:relative;}}
    .lg-expand-btn{{justify-self:start;background:linear-gradient(180deg,#16324a,#102435);color:#dbeafe;border:1px solid #315a79;border-radius:12px;padding:9px 12px;font-weight:700;cursor:pointer;}}
    .lg-expand-btn:hover{{filter:brightness(1.05);}}
    .lg-graph-preview{{border:1px solid #27415a;border-radius:16px;background:radial-gradient(circle at top,#0b1730 0%,#07111f 72%);padding:14px;min-height:260px;display:grid;align-items:center;overflow:hidden;}}
    .lg-graph-preview .mermaid{{width:100%;max-width:100%;display:grid;justify-items:center;}}
    .lg-modal{{position:fixed;inset:0;background:rgba(2,8,15,.82);backdrop-filter:blur(4px);display:none;align-items:center;justify-content:center;padding:10px 10px;z-index:1200;}}
    .lg-modal.open{{display:flex;}}
    .lg-modal-panel{{width:min(3200px,99.2vw);max-height:94vh;overflow:hidden;border:1px solid #315a79;border-radius:26px;background:linear-gradient(180deg,#0b1528,#07111f);padding:22px;display:grid;gap:16px;box-shadow:0 40px 100px rgba(2,8,15,.62), inset 0 1px 0 rgba(255,255,255,.04);}}
    .lg-modal-head{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;}}
    .lg-modal-head h2{{margin:0;font-size:28px;line-height:1.1;}}
    .lg-modal-copy{{margin:6px 0 0;color:#b7cde2;line-height:1.6;max-width:1000px;}}
    .lg-modal-close{{background:linear-gradient(180deg,#18354f,#102435);color:#dbeafe;border:1px solid #4f82a8;border-radius:14px;padding:10px 14px;font-weight:700;cursor:pointer;box-shadow:0 10px 20px rgba(2,8,15,.18);}}
    .lg-modal-graph{{border:1px solid #325574;border-radius:22px;background:radial-gradient(circle at top,#10213b 0%,#09111f 70%);padding:32px;min-height:84vh;display:grid;align-items:center;justify-items:center;overflow:hidden;box-shadow:inset 0 1px 0 rgba(255,255,255,.04);background-image:radial-gradient(circle at top,#10213b 0%,#09111f 70%),linear-gradient(rgba(143,216,255,.06) 1px, transparent 1px),linear-gradient(90deg, rgba(143,216,255,.06) 1px, transparent 1px);background-size:auto, 28px 28px, 28px 28px;}}
    .lg-modal-graph .mermaid{{width:100%;max-width:100%;display:grid;justify-items:center;}}
    .lg-graph-preview svg,.lg-modal-graph svg{{width:100% !important;max-width:100% !important;height:auto !important;display:block;margin:0 auto;}}
    .lg-modal-graph .label foreignObject div,.lg-modal-graph .nodeLabel{{font-weight:700 !important;letter-spacing:.01em;}}
    .lg-modal-graph .cluster rect{{rx:22px;ry:22px;}}
    .lg-legend{{display:flex;gap:10px;flex-wrap:wrap;}}
    .lg-legend-item{{display:inline-flex;align-items:center;gap:8px;border:1px solid #254059;border-radius:999px;background:#07111f;padding:7px 10px;color:#dbeafe;font-size:12px;}}
    .lg-legend-swatch{{width:12px;height:12px;border-radius:999px;display:inline-block;}}
    @media (max-width: 1100px) {{ .lg-grid{{grid-template-columns:1fr;}} }}
    @media (max-width: 1100px) {{ .lg-modal-panel{{width:min(99vw,1600px);}} .lg-modal-graph{{min-height:70vh;padding:20px;}} }}
  </style>
  <div class="lg-shell">
    <section class="lg-hero">
      <div class="lg-kicker">Control Center</div>
      <h1>LangGraph Graph</h1>
      <p>This page has three layers. <strong>Live runtime</strong> shows what the controller can do right now. <strong>Possible topology</strong> shows the full graph and the currently active graph. <strong>Offline experiments</strong> show how alternative graph settings performed when evals were run.</p>
      <div class="lg-actions">
        <code>make langgraph-gold-build</code>
        <code>make langgraph-eval-prompts</code>
        <code>make langgraph-topology-eval</code>
        <code>make langgraph-topology-optimize</code>
      </div>
      <div class="lg-legend">
        <div class="lg-legend-item"><span class="lg-legend-swatch" style="background:#10253d;border:1px solid #5db0ff;"></span>Planner / Control Entry</div>
        <div class="lg-legend-item"><span class="lg-legend-swatch" style="background:#132e28;border:1px solid #36c690;"></span>Writer</div>
        <div class="lg-legend-item"><span class="lg-legend-swatch" style="background:#2f2410;border:1px solid #f5b942;"></span>Review Stages</div>
        <div class="lg-legend-item"><span class="lg-legend-swatch" style="background:#352016;border:1px solid #ff8a4c;"></span>Validation</div>
        <div class="lg-legend-item"><span class="lg-legend-swatch" style="background:#13233b;border:1px solid #4da3ff;"></span>Execution</div>
        <div class="lg-legend-item"><span class="lg-legend-swatch" style="background:#24163a;border:1px solid #b388ff;"></span>Summary / Finalize</div>
      </div>
    </section>

    <section class="lg-card">
      <div class="badge" style="margin-bottom:8px;">Live Runtime</div>
      <h2>Current Topology Flags</h2>
      <p class="muted">These flags determine the active graph layout used by the live controller-hosted LangGraph workflow.</p>
      <div class="lg-flags">{flag_badges}</div>
    </section>

    <div class="lg-grid">
      <section class="lg-card lg-graph-card">
        <div class="badge" style="margin-bottom:8px;">Possible Topology</div>
        <h2 title="Canonical Graph shows the full possible workflow, including optional branches that may be disabled or skipped in the active runtime.">Canonical Graph</h2>
        <p class="muted">Full possible graph, including conditional branches that may be bypassed in the active runtime.</p>
        <button class="lg-expand-btn" type="button" data-lg-open="canonical" title="Canonical Graph shows the full possible workflow, including optional branches that may be disabled or skipped in the active runtime.">Expand graph</button>
        <div class="lg-graph-preview">{canonical_mermaid}</div>
      </section>
      <section class="lg-card lg-graph-card">
        <div class="badge" style="margin-bottom:8px;">Live Topology</div>
        <h2 title="Active Graph shows the workflow after applying current runtime settings and highlights the nodes that ran in the latest execution when available.">Active Graph</h2>
        <p class="muted">Graph after applying the current topology flags. Highlighted nodes ran in the latest multi-model artifact when one exists.</p>
        <button class="lg-expand-btn" type="button" data-lg-open="active" title="Active Graph shows the workflow after applying current runtime settings and highlights the nodes that ran in the latest execution when available.">Expand graph</button>
        <div class="lg-graph-preview">{active_mermaid}</div>
      </section>
    </div>

    <section class="lg-card">
      <div class="badge" style="margin-bottom:8px;">Latest Live Run</div>
      <h2>Latest Executed Path</h2>
      <p class="muted">This comes from the newest multi-model run artifact and shows the actual stage order, timings, and whether peer review was skipped.</p>
      {latest_overlay_html}
    </section>

    <div class="lg-grid">
      <section class="lg-card">
        <div class="badge" style="margin-bottom:8px;">Offline Experiments</div>
        <h2>Experiment Topology Ranking</h2>
        <p class="muted">Offline eval results appear here after <code>make langgraph-topology-eval</code> has been run against a gold corpus and prompt set.</p>
        {_experiment_summary_block()}
      </section>
      <section class="lg-card">
        <h2>How To Read This</h2>
        <ul class="lg-notes">{note_items}</ul>
      </section>
    </div>
  </div>
  <div id="lg-graph-modal" class="lg-modal" aria-hidden="true">
    <div class="lg-modal-panel" role="dialog" aria-modal="true" aria-labelledby="lg-graph-modal-title">
      <div class="lg-modal-head">
        <div>
          <h2 id="lg-graph-modal-title">Graph</h2>
          <p id="lg-graph-modal-copy" class="lg-modal-copy"></p>
        </div>
        <button id="lg-graph-modal-close" class="lg-modal-close" type="button">Close</button>
      </div>
      <div id="lg-graph-modal-body" class="lg-modal-graph"></div>
    </div>
  </div>
  <script>
    (() => {{
      const modal = document.getElementById('lg-graph-modal');
      const modalBody = document.getElementById('lg-graph-modal-body');
      const modalTitle = document.getElementById('lg-graph-modal-title');
      const modalCopy = document.getElementById('lg-graph-modal-copy');
      const closeBtn = document.getElementById('lg-graph-modal-close');
      if(!modal || !modalBody || !modalTitle || !modalCopy || !closeBtn) return;
      const graphHtml = {{
        canonical: {{
          title: 'Canonical Graph',
          copy: 'Full possible LangGraph topology, including branches that may be skipped in the active runtime.',
          html: {canonical_mermaid_json}
        }},
        active: {{
          title: 'Active Graph',
          copy: 'Current topology after applying the active runtime flags. Highlighted nodes reflect the latest executed path when available.',
          html: {active_mermaid_json}
        }}
      }};
      async function renderModal(which) {{
        const entry = graphHtml[which];
        if(!entry) return;
        modalTitle.textContent = entry.title;
        modalCopy.textContent = entry.copy;
        modalBody.innerHTML = entry.html;
        modal.classList.add('open');
        modal.setAttribute('aria-hidden', 'false');
        const mermaid = window.mermaid;
        const graphNode = modalBody.querySelector('.mermaid');
        if(graphNode) {{
          graphNode.removeAttribute('data-processed');
        }}
        if(mermaid && typeof mermaid.run === 'function' && graphNode) {{
          await mermaid.run({{ nodes: [graphNode] }});
        }}
      }}
      document.querySelectorAll('[data-lg-open]').forEach((btn) => {{
        btn.addEventListener('click', () => renderModal(btn.getAttribute('data-lg-open')));
      }});
      function closeModal() {{
        modal.classList.remove('open');
        modal.setAttribute('aria-hidden', 'true');
        modalBody.innerHTML = '';
      }}
      closeBtn.addEventListener('click', closeModal);
      modal.addEventListener('click', (event) => {{
        if(event.target === modal) closeModal();
      }});
      document.addEventListener('keydown', (event) => {{
        if(event.key === 'Escape' && modal.classList.contains('open')) closeModal();
      }});
    }})();
  </script>
</div>
"""


def _load_environment_profile_payload() -> dict[str, Any]:
    try:
        if ENV_PROFILE_PATH.exists():
            raw = ENV_PROFILE_PATH.read_text(encoding="utf-8")
            data = json.loads(raw)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _artifacts_page_body() -> str:
    if not ARTIFACTS_ROOT.exists():
        return """
<div class=\"card\">
  <h1>Artifact Repository</h1>
  <p class=\"muted\">Artifact directory does not exist yet.</p>
  <p>Create artifacts by running demos, evaluations, or profile refresh tasks.</p>
</div>
"""
    groups = sorted([p for p in ARTIFACTS_ROOT.iterdir() if p.is_dir()], key=lambda x: x.name)
    cards: list[str] = []
    summary_cards: list[str] = []
    group_explain = {
        "audit": "Operator activity and local query audit trail.",
        "environment": "Data Domains snapshots and environment-profile outputs used to ground SPL.",
        "learning": "SPL Optimization AI Engine registry, reusable SPL assets, and optimization logs.",
        "runs": "Investigation runs, evidence traces, and optional runtime outputs.",
        "knowledge": "Environment-aware SPL guidance and personalization artifacts.",
    }
    group_labels = {
        "audit": "Operator Audit",
        "environment": "Environment Snapshots",
        "learning": "Optimization Assets",
        "runs": "Investigations",
        "knowledge": "Personalization",
    }
    for d in groups:
        files = sorted([f for f in d.rglob("*") if f.is_file()], key=lambda x: str(x))
        sample = files[:10]
        label = group_labels.get(d.name, d.name.replace("_", " ").title())
        sample_items = "".join(
            f"<li><a href=\"/artifacts/raw?path={quote(str(f.relative_to(ARTIFACTS_ROOT)))}\">{html.escape(str(f.relative_to(ARTIFACTS_ROOT)))}</a></li>"
            for f in sample
        )
        summary_cards.append(
            "<div class=\"artifact-work-card\">"
            f"<div class=\"artifact-work-title\">{html.escape(label)}</div>"
            f"<div class=\"artifact-work-copy\">{html.escape(group_explain.get(d.name, 'Operational artifact group.'))}</div>"
            f"<div class=\"artifact-work-meta\">{len(files)} file(s)</div>"
            "</div>"
        )
        cards.append(
            "<details class=\"env-card artifact-card\">"
            "<summary>"
            f"<span class=\"env-title\">{html.escape(label)}</span>"
            f"<span class=\"badge\">files={len(files)}</span>"
            "</summary>"
            "<div class=\"env-body\">"
            f"<p class=\"muted\">{html.escape(group_explain.get(d.name, 'Operational artifact group.'))}</p>"
            f"<ul>{sample_items or '<li class=\"muted\">(empty)</li>'}</ul>"
            "</div>"
            "</details>"
        )
    return (
        "<div class=\"card artifact-shell\">"
        "<style>"
        ".artifact-shell{display:grid;gap:16px}"
        ".artifact-hero{border:1px solid #244660;border-radius:18px;background:linear-gradient(160deg,#08182a,#091726 52%,#0a1d17);padding:18px}"
        ".artifact-hero h1{margin:0 0 8px;font-size:28px;line-height:1.05}"
        ".artifact-hero p{margin:0;color:#a8c0d8;font-size:14px;line-height:1.6}"
        ".artifact-work-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}"
        ".artifact-work-card{border:1px solid #27415a;border-radius:14px;background:#071523;padding:14px}"
        ".artifact-work-title{font-size:12px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:#7dd3fc;margin-bottom:6px}"
        ".artifact-work-copy{color:#dbeafe;font-size:13px;line-height:1.5}"
        ".artifact-work-meta{margin-top:8px;color:#9fb4cc;font-size:12px}"
        ".artifact-section{border:1px solid #23445f;border-radius:18px;background:linear-gradient(180deg,#081525,#06111d);padding:18px}"
        ".artifact-card ul{margin:10px 0 0;padding-left:18px}"
        ".artifact-card li{margin:6px 0;color:#dbeafe}"
        ".artifact-card a{color:#93c5fd;text-decoration:none}"
        ".artifact-card a:hover{text-decoration:underline}"
        "@media (max-width:980px){.artifact-work-grid{grid-template-columns:1fr 1fr}}"
        "@media (max-width:640px){.artifact-work-grid{grid-template-columns:1fr}}"
        "</style>"
        "<div class=\"artifact-hero\">"
        "<h1>Artifact Repository</h1>"
        "<p>Use this page to answer one question quickly: what has the platform actually produced? Investigations, optimization assets, operator audit, and environment snapshots are grouped here by workflow instead of by raw filesystem structure.</p>"
        f"<div class=\"learning-notes\" style=\"margin-top:10px;\"><div>Artifact root: <code>{html.escape(str(ARTIFACTS_ROOT.relative_to(PROJECT_ROOT)))}</code></div></div>"
        "</div>"
        "<section class=\"artifact-section\">"
        "<h2 style=\"margin:0 0 12px;font-size:18px;\">Workflow Buckets</h2>"
        f"<div class=\"artifact-work-grid\">{''.join(summary_cards) if summary_cards else '<div class=\"muted\">No artifact groups found.</div>'}</div>"
        "</section>"
        "<section class=\"artifact-section\">"
        "<h2 style=\"margin:0 0 12px;font-size:18px;\">Browse Stored Files</h2>"
        "<p class=\"muted\">Open a workflow bucket below to inspect the files it currently contains.</p>"
        f"<div class=\"env-list\">{''.join(cards) if cards else '<p class=\"muted\">No artifact groups found.</p>'}</div>"
        "</section>"
        "</div>"
    )


def _active_spl_asset_matches_for_intent(intent: str) -> list[dict[str, Any]]:
    value = str(intent or "").strip().lower()
    if not value:
        return []

    family_map: dict[str, set[str]] = {
        "failed_login_activity": {"failed_login_activity", "linux_auth_failures", "windows_auth_failures"},
        "linux_auth_failures": {"failed_login_activity", "linux_auth_failures"},
        "windows_auth_failures": {"failed_login_activity", "windows_auth_failures"},
        "apache_access_top_ips": {"apache_access_top_ips", "apache_web"},
        "aws_cloudtrail_activity": {"aws_cloudtrail_activity", "cloudtrail", "aws_discovery"},
    }
    acceptable = family_map.get(value, {value})
    try:
        summary = learning_registry_summary()
        repository = summary.get("repository", {}) if isinstance(summary, dict) else {}
        rows = repository.get("records", []) if isinstance(repository, dict) else []
        if not isinstance(rows, list):
            return []
        matches: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            row_intent = str(row.get("intent", "")).strip().lower()
            match_tokens = {str(item).strip().lower() for item in row.get("match_tokens", []) if str(item).strip()}
            if row_intent in acceptable or acceptable.intersection(match_tokens):
                matches.append(row)
        return matches[:3]
    except Exception:
        return []


def _environment_page_body() -> str:
    profile = _load_environment_profile_payload()
    if not profile:
        refresh_meta = _environment_profile_refresh_status()
        if _running_in_container():
            return f"""
<div class=\"card\">
  <style>
    .env-work-panel{{border:1px solid #27415a;border-radius:14px;background:#071523;padding:14px;margin:12px 0;}}
    .env-actions{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px;}}
    .env-action-btn{{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:11px 16px;border-radius:14px;border:1px solid #33506a;background:linear-gradient(180deg,#16324a,#102435);color:#e0f2fe;font-size:13px;font-weight:800;cursor:pointer;box-shadow:0 12px 24px rgba(8,23,37,.22), inset 0 1px 0 rgba(255,255,255,.05);transition:transform .16s ease, filter .16s ease, border-color .16s ease;}}
    .env-action-btn:hover{{transform:translateY(-1px);filter:brightness(1.04);border-color:#60a5fa;}}
    .env-action-btn:disabled{{cursor:not-allowed;opacity:.6;transform:none;filter:none;}}
    .env-action-btn.green{{border-color:#1f7a44;background:linear-gradient(180deg,#22c55e,#15803d);color:#04140c;box-shadow:0 12px 24px rgba(21,128,61,.22), inset 0 1px 0 rgba(255,255,255,.16);}}
    .env-action-btn.green:hover{{border-color:#4ade80;filter:brightness(1.03);}}
    .env-refresh-status{{margin-top:10px;color:#9fb4cc;font-size:13px;line-height:1.55;}}
  </style>
  <h1>Data Domains</h1>
  <p class=\"muted\">Container deployments do not expose Data Domains until Splunk MCP has been validated and the initial environment profile has finished building.</p>
  <p>Current profile path: <code>{html.escape(str(ENV_PROFILE_PATH.relative_to(PROJECT_ROOT)))}</code></p>
  <p>Next step: open <a href=\"/configure\">Configuration</a>, validate the Splunk MCP connection, then wait for the first environment profile build to complete.</p>
  <div class=\"env-work-panel\">
    <strong>Fresh Start Controls</strong>
    <div class=\"env-summary-copy\" style=\"margin-top:6px;\">Need to rebuild Data Domains from scratch for this new system? Use the green button below after validating the runtime.</div>
    <div class=\"env-actions\">
      <button id=\"env-wipe-refresh-btn\" class=\"env-action-btn green\" type=\"button\">Wipe And Refresh</button>
      <span id=\"env-refresh-inline-status\" class=\"badge\">state={html.escape(str(refresh_meta.get('state', 'pending')))}</span>
    </div>
    <div id=\"env-refresh-inline-detail\" class=\"env-refresh-status\"><strong>Status:</strong> {html.escape(str(refresh_meta.get('detail', 'Ready to refresh Data Domains.')))}</div>
  </div>
  <script>
    (() => {{
      const statusBadge = document.getElementById('env-refresh-inline-status');
      const statusDetail = document.getElementById('env-refresh-inline-detail');
      const wipeBtn = document.getElementById('env-wipe-refresh-btn');
      const setStatus = (meta, fallback) => {{
        const state = String(meta?.state || 'pending');
        statusBadge.textContent = `state=${{state}}`;
        statusDetail.innerHTML = `<strong>Status:</strong> ${{String(meta?.detail || fallback || 'Ready to refresh Data Domains.')}}`;
        wipeBtn.disabled = state === 'in_progress';
      }};
      wipeBtn?.addEventListener('click', async () => {{
        const confirmed = window.confirm('Wipe the current Data Domains profile and rebuild it from scratch for this system? This clears the existing profile artifacts before refreshing.');
        if(!confirmed) return;
        setStatus({{ state:'in_progress', detail:'Wiping current Data Domains artifacts and starting a fresh rebuild...' }}, 'Wiping current Data Domains artifacts and starting a fresh rebuild...');
        try {{
          const resp = await fetch('/api/environment/wipe-refresh', {{ method:'POST', credentials:'same-origin' }});
          const data = await resp.json();
          setStatus(data.refresh || {{ state:'pending', detail:data.detail || data.error || 'Wipe and refresh request submitted.' }}, data.detail || data.error || 'Wipe and refresh request submitted.');
        }} catch (_err) {{
          setStatus({{ state:'error', detail:'Could not start wipe and refresh.' }}, 'Could not start wipe and refresh.');
        }}
      }});
    }})();
  </script>
</div>
"""
        return f"""
<div class=\"card\">
  <h1>Data Domains</h1>
  <p class=\"muted\">Environment profile is missing or unreadable.</p>
  <p>Expected file: <code>{html.escape(str(ENV_PROFILE_PATH.relative_to(PROJECT_ROOT)))}</code></p>
  <p>Build it with:</p>
  <pre>make env-profile-refresh</pre>
</div>
"""

    timestamp = str(profile.get("timestamp_utc", "unknown"))
    refresh_meta = _environment_profile_refresh_status()
    counts = profile.get("counts", {}) if isinstance(profile.get("counts"), dict) else {}
    index_count = counts.get("index_count", 0)
    sourcetype_count = counts.get("sourcetype_count", 0)
    time_window = profile.get("time_window", {}) if isinstance(profile.get("time_window"), dict) else {}
    earliest = str(time_window.get("earliest_time", ""))
    latest = str(time_window.get("latest_time", ""))
    indexes = profile.get("indexes", []) if isinstance(profile.get("indexes"), list) else []
    semantics = profile.get("sourcetype_semantics", {}) if isinstance(profile.get("sourcetype_semantics"), dict) else {}
    field_inventory = (
        profile.get("sourcetype_field_inventory", {})
        if isinstance(profile.get("sourcetype_field_inventory"), dict)
        else {}
    )
    field_meta = profile.get("field_inventory_meta", {}) if isinstance(profile.get("field_inventory_meta"), dict) else {}

    def _friendly_sourcetype_label(value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return "not recorded"
        if "too_small" in text:
            base = text.replace("_too_small", "").replace("-too_small", "")
            return f"{base} (small sample placeholder)"
        return text

    def _render_index_cards(rows_payload: list[dict[str, Any]]) -> str:
        cards: list[str] = []
        for row in rows_payload:
            if not isinstance(row, dict):
                continue
            idx = str(row.get("index", "")).strip()
            if not idx:
                continue
            sourcetypes = row.get("sourcetypes", [])
            st_counts = row.get("sourcetype_event_counts", {}) if isinstance(row.get("sourcetype_event_counts"), dict) else {}
            error = str(row.get("error", "")).strip()
            if not isinstance(sourcetypes, list):
                sourcetypes = []

            sourcetype_cards: list[str] = []
            for st in sourcetypes:
                st_name = str(st).strip()
                if not st_name:
                    continue
                sem = semantics.get(st_name, {}) if isinstance(semantics.get(st_name), dict) else {}
                desc = str(sem.get("description", "")).strip()
                count = st_counts.get(st_name, "")
                st_field_meta = field_inventory.get(st_name, {}) if isinstance(field_inventory, dict) else {}
                field_preview = ""
                field_rows_html = ""
                if isinstance(st_field_meta, dict):
                    field_examples = st_field_meta.get("interesting_field_examples", [])
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
                            field_preview = "; ".join(preview_parts)
                    field_rows = st_field_meta.get("display_fields", [])
                    if not isinstance(field_rows, list) or not field_rows:
                        field_rows = st_field_meta.get("fields", [])
                    if isinstance(field_rows, list) and field_rows:
                        field_table_rows: list[str] = []
                        for item in field_rows[:20]:
                            if not isinstance(item, dict):
                                continue
                            field_name = str(item.get("field", "")).strip()
                            if not field_name:
                                continue
                            samples = item.get("sample_values", [])
                            if isinstance(samples, list):
                                sample_text = ", ".join(str(x).strip() for x in samples[:3] if str(x).strip())
                            else:
                                sample_text = ""
                            if not sample_text:
                                sample_text = "No high-signal preview"
                            field_table_rows.append(
                                "<tr>"
                                f"<td class=\"mono\">{html.escape(field_name)}</td>"
                                f"<td class=\"mono\">{html.escape(sample_text)}</td>"
                                f"<td class=\"mono\">{html.escape(str(item.get('count', '')))}</td>"
                                f"<td class=\"mono\">{html.escape(str(item.get('distinct_count', '')))}</td>"
                                "</tr>"
                            )
                        if field_table_rows:
                            field_rows_html = (
                                "<table class=\"env-table\"><thead><tr><th>Field</th><th>Sample Values</th><th>Count</th><th>Distinct</th></tr></thead>"
                                f"<tbody>{''.join(field_table_rows)}</tbody></table>"
                            )
                    field_names = st_field_meta.get("interesting_fields", [])
                    if not field_preview and (not isinstance(field_names, list) or not field_names):
                        field_rows = st_field_meta.get("fields", [])
                        if isinstance(field_rows, list) and field_rows:
                            field_names = [
                                str(item.get("field", "")).strip()
                                for item in field_rows[:8]
                                if isinstance(item, dict) and str(item.get("field", "")).strip()
                            ]
                    if not field_preview and field_names:
                        field_preview = ", ".join(str(name).strip() for name in field_names[:8] if str(name).strip())
                preview_html = html.escape(field_preview) if field_preview else "Field inventory pending refresh"
                field_rows_html = field_rows_html or "<p class=\"muted\">No field inventory captured yet for this sourcetype.</p>"
                sourcetype_cards.append(
                    "<details class=\"env-subcard\">"
                    "<summary>"
                    "<div>"
                    f"<div class=\"env-title\">sourcetype={html.escape(st_name)}</div>"
                    f"<div class=\"env-preview\">{html.escape(desc) if desc else 'No semantic description yet.'}</div>"
                    f"<div class=\"env-preview\">{preview_html}</div>"
                    "</div>"
                    "<div class=\"env-submeta\">"
                    f"<span class=\"badge\">events={html.escape(str(count))}</span>"
                    f"<span class=\"badge\">fields={html.escape(str(st_field_meta.get('field_count', 0) if isinstance(st_field_meta, dict) else 0))}</span>"
                    "</div>"
                    "</summary>"
                    "<div class=\"env-subbody\">"
                    f"{field_rows_html}"
                    "</div>"
                    "</details>"
                )

            details = "".join(sourcetype_cards) if sourcetype_cards else "<p class=\"muted\">No sourcetypes discovered.</p>"
            if error:
                details += f"<p class=\"kv\"><span class=\"badge\">metadata_error</span> {html.escape(error)}</p>"
            cards.append(
                "<details class=\"env-card\">"
                "<summary>"
                f"<span class=\"env-title\">index={html.escape(idx)}</span>"
                f"<span class=\"badge\">sourcetypes={len(sourcetypes)}</span>"
                "</summary>"
                "<div class=\"env-body\">"
                f"<div class=\"env-sublist\">{details}</div>"
                "</div>"
                "</details>"
            )
        return "".join(cards) if cards else "<div class=\"env-card\"><div class=\"env-body\"><p class=\"muted\">No index rows available.</p></div></div>"

    cards_html = _render_index_cards(indexes)

    profile_json = html.escape(json.dumps(profile, indent=2))
    return f"""
<div class=\"card\">
  <style>
    .env-summary-grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:14px 0;}}
    .env-summary-card{{border:1px solid #27415a;border-radius:14px;background:#071523;padding:14px;}}
    .env-summary-title{{font-size:12px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:#7dd3fc;margin-bottom:6px;}}
    .env-summary-value{{font-size:18px;font-weight:900;color:#f8fafc;}}
    .env-summary-copy{{margin-top:4px;color:#9fb4cc;font-size:12px;line-height:1.45;}}
    .env-work-panel{{border:1px solid #27415a;border-radius:14px;background:#071523;padding:14px;margin:12px 0;}}
    .env-actions{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px;}}
    .env-action-btn{{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:11px 16px;border-radius:14px;border:1px solid #33506a;background:linear-gradient(180deg,#16324a,#102435);color:#e0f2fe;font-size:13px;font-weight:800;cursor:pointer;box-shadow:0 12px 24px rgba(8,23,37,.22), inset 0 1px 0 rgba(255,255,255,.05);transition:transform .16s ease, filter .16s ease, border-color .16s ease;}}
    .env-action-btn:hover{{transform:translateY(-1px);filter:brightness(1.04);border-color:#60a5fa;}}
    .env-action-btn:disabled{{cursor:not-allowed;opacity:.6;transform:none;filter:none;}}
    .env-action-btn.green{{border-color:#1f7a44;background:linear-gradient(180deg,#22c55e,#15803d);color:#04140c;box-shadow:0 12px 24px rgba(21,128,61,.22), inset 0 1px 0 rgba(255,255,255,.16);}}
    .env-action-btn.green:hover{{border-color:#4ade80;filter:brightness(1.03);}}
    .env-refresh-status{{margin-top:10px;color:#9fb4cc;font-size:13px;line-height:1.55;}}
    .env-refresh-status strong{{color:#f8fafc;}}
    @media (max-width:900px){{.env-summary-grid{{grid-template-columns:1fr 1fr;}}}}
    @media (max-width:620px){{.env-summary-grid{{grid-template-columns:1fr;}}}}
  </style>
  <h1>Data Domains</h1>
  <p class=\"muted\">Use this page to understand what telemetry is available for hunting in this environment: which indexes exist, which sourcetypes are present, and which fields have enough signal to support grounded SPL.</p>
  <div class=\"env-summary-grid\">
    <div class=\"env-summary-card\"><div class=\"env-summary-title\">Current Coverage</div><div class=\"env-summary-value\">{html.escape(str(index_count))}</div><div class=\"env-summary-copy\">Indexes currently represented in the environment profile.</div></div>
    <div class=\"env-summary-card\"><div class=\"env-summary-title\">Source Variety</div><div class=\"env-summary-value\">{html.escape(str(sourcetype_count))}</div><div class=\"env-summary-copy\">Sourcetypes available for planning and grounding.</div></div>
    <div class=\"env-summary-card\"><div class=\"env-summary-title\">Field Fit</div><div class=\"env-summary-value\">{html.escape(str(counts.get('field_inventory_sourcetypes', 0)))}</div><div class=\"env-summary-copy\">Sourcetypes with field inventory captured for higher-confidence SPL.</div></div>
    <div class=\"env-summary-card\"><div class=\"env-summary-title\">Time Window</div><div class=\"env-summary-value\">{html.escape(earliest)}</div><div class=\"env-summary-copy\">Profile window ending at {html.escape(latest)}.</div></div>
  </div>
  <div class=\"env-work-panel\"><strong>How to use this page:</strong> Start here when you want to know whether the environment actually has the telemetry needed for a hunt. The detailed index and sourcetype cards below are the proof surface. Most users can ignore maintenance internals unless a refresh is still catching up.</div>
  <div class=\"env-work-panel\">
    <strong>Fresh Start Controls</strong>
    <div class=\"env-summary-copy\" style=\"margin-top:6px;\">When you connect A.G.E.N.T. Smith to a new system, use <strong>Wipe And Refresh</strong> to clear the current Data Domains profile and rebuild it from scratch against the new environment.</div>
    <div class=\"env-actions\">
      <button id=\"env-refresh-btn\" class=\"env-action-btn\" type=\"button\">Refresh Data Domains</button>
      <button id=\"env-wipe-refresh-btn\" class=\"env-action-btn green\" type=\"button\">Wipe And Refresh</button>
      <span id=\"env-refresh-inline-status\" class=\"badge\">state={html.escape(str(refresh_meta.get('state', 'pending')))}</span>
    </div>
    <div id=\"env-refresh-inline-detail\" class=\"env-refresh-status\"><strong>Status:</strong> {html.escape(str(refresh_meta.get('detail', 'Ready to refresh Data Domains.')))}</div>
  </div>
  <div class=\"statline\">
    <span class=\"badge\">indexes={html.escape(str(index_count))}</span>
    <span class=\"badge\">sourcetypes={html.escape(str(sourcetype_count))}</span>
    <span class=\"badge\">field_inventory={html.escape(str(counts.get('field_inventory_sourcetypes', 0)))}</span>
    <span class=\"badge\">window={html.escape(earliest)} -> {html.escape(latest)}</span>
    <span class=\"badge\">timestamp={html.escape(timestamp)}</span>
  </div>
  <p class=\"muted\">The cards below show the hunt coverage the platform currently knows about. Maintenance refreshes happen in the background to keep the profile current; most operators only need the two status lines below if they are checking whether a refresh is still catching up.</p>
  <div class=\"env-card\" style=\"margin-bottom:12px;\">
    <div class=\"env-body\">
      <p class=\"muted\" style=\"margin:0 0 6px;\"><strong>Most recently refreshed:</strong> <code>{html.escape(_friendly_sourcetype_label(field_meta.get('last_refreshed_sourcetype', '')))}</code></p>
      <p class=\"muted\" style=\"margin:0;\"><strong>Queued next:</strong> <code>{html.escape(_friendly_sourcetype_label(field_meta.get('next_sourcetype', '')))}</code></p>
    </div>
  </div>
  <p>Maintenance commands:</p>
  <pre>make env-profile-refresh
make env-profile-check</pre>
  <h2>All Domains (Global)</h2>
  <div class=\"env-list\">{cards_html}</div>
  <details class=\"guided\" style=\"margin-top:12px;\">
    <summary>Show Raw Environment Profile JSON</summary>
    <pre>{profile_json}</pre>
  </details>
  <script>
    (() => {{
      const statusBadge = document.getElementById('env-refresh-inline-status');
      const statusDetail = document.getElementById('env-refresh-inline-detail');
      const refreshBtn = document.getElementById('env-refresh-btn');
      const wipeBtn = document.getElementById('env-wipe-refresh-btn');
      const setStatus = (meta, fallback) => {{
        const state = String(meta?.state || 'pending');
        statusBadge.textContent = `state=${{state}}`;
        statusDetail.innerHTML = `<strong>Status:</strong> ${{String(meta?.detail || fallback || 'Ready to refresh Data Domains.')}}`;
        const busy = state === 'in_progress';
        refreshBtn.disabled = busy;
        wipeBtn.disabled = busy;
      }};
      const loadStatus = async () => {{
        try {{
          const resp = await fetch('/api/config/env-refresh', {{ credentials:'same-origin' }});
          const data = await resp.json();
          setStatus(data.refresh || {{}}, 'Ready to refresh Data Domains.');
        }} catch (_err) {{
          setStatus({{ state:'unknown', detail:'Unable to load refresh status right now.' }}, 'Unable to load refresh status right now.');
        }}
      }};
      refreshBtn?.addEventListener('click', async () => {{
        setStatus({{ state:'in_progress', detail:'Starting Data Domains refresh...' }}, 'Starting Data Domains refresh...');
        try {{
          const resp = await fetch('/api/config/env-refresh', {{ method:'POST', credentials:'same-origin' }});
          const data = await resp.json();
          setStatus(data.refresh || {{ state:'pending', detail:data.detail || data.error || 'Refresh request submitted.' }}, data.detail || data.error || 'Refresh request submitted.');
        }} catch (_err) {{
          setStatus({{ state:'error', detail:'Could not start Data Domains refresh.' }}, 'Could not start Data Domains refresh.');
        }}
      }});
      wipeBtn?.addEventListener('click', async () => {{
        const confirmed = window.confirm('Wipe the current Data Domains profile and rebuild it from scratch for this system? This clears the existing profile artifacts before refreshing.');
        if(!confirmed) return;
        setStatus({{ state:'in_progress', detail:'Wiping current Data Domains artifacts and starting a fresh rebuild...' }}, 'Wiping current Data Domains artifacts and starting a fresh rebuild...');
        try {{
          const resp = await fetch('/api/environment/wipe-refresh', {{ method:'POST', credentials:'same-origin' }});
          const data = await resp.json();
          setStatus(data.refresh || {{ state:'pending', detail:data.detail || data.error || 'Wipe and refresh request submitted.' }}, data.detail || data.error || 'Wipe and refresh request submitted.');
        }} catch (_err) {{
          setStatus({{ state:'error', detail:'Could not start wipe and refresh.' }}, 'Could not start wipe and refresh.');
        }}
      }});
      loadStatus();
    }})();
  </script>
</div>
"""


def _configure_page_body() -> str:
    return """
<div class="card">
  <style>
    .cfg-shell{display:grid;gap:16px;}
    .cfg-hero{display:grid;grid-template-columns:minmax(320px,.95fr) minmax(420px,1.05fr);gap:14px;align-items:stretch;margin-bottom:2px;}
    .cfg-hero-card{border:1px solid #244660;border-radius:18px;background:linear-gradient(160deg,#08182a,#091726 52%,#0a1d17);padding:18px 18px 16px;box-shadow:inset 0 0 0 1px rgba(255,255,255,.02);}
    .cfg-hero-title{margin:0 0 8px;font-size:28px;line-height:1.05;}
    .cfg-hero-copy{color:#a8c0d8;font-size:14px;line-height:1.65;margin:0;}
    .cfg-status-board{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;}
    .cfg-health-card{border:1px solid #234059;border-radius:14px;background:#081220;padding:12px;}
    .cfg-health-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:6px;}
    .cfg-health-name{color:#f8fafc;font-size:13px;font-weight:800;}
    .cfg-health-dot{width:12px;height:12px;border-radius:999px;background:#64748b;box-shadow:0 0 0 3px rgba(100,116,139,.15);}
    .cfg-health-dot.ok{background:#22c55e;box-shadow:0 0 0 3px rgba(34,197,94,.16);}
    .cfg-health-dot.warn{background:#f59e0b;box-shadow:0 0 0 3px rgba(245,158,11,.16);}
    .cfg-health-dot.error{background:#ef4444;box-shadow:0 0 0 3px rgba(239,68,68,.16);}
    .cfg-health-detail{color:#9fb4cc;font-size:12px;line-height:1.45;min-height:34px;}
    .cfg-step{border:1px solid #23445f;border-radius:18px;background:linear-gradient(180deg,#081525,#06111d);padding:18px;box-shadow:inset 0 0 0 1px rgba(255,255,255,.015);}
    .cfg-step summary{cursor:pointer;list-style:none;display:flex;align-items:center;justify-content:space-between;gap:12px;}
    .cfg-step summary::-webkit-details-marker{display:none;}
    .cfg-step-label{display:flex;align-items:center;gap:12px;}
    .cfg-step-num{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border-radius:999px;background:#0b2130;border:1px solid #294560;color:#dbeafe;font-size:13px;font-weight:900;}
    .cfg-step-title{font-size:19px;font-weight:800;color:#f8fafc;}
    .cfg-step-toggle{color:#9fb4cc;font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;}
    .cfg-step[open] .cfg-step-toggle::after{content:"Hide";}
    .cfg-step:not([open]) .cfg-step-toggle::after{content:"Show";}
    .cfg-step-body{margin-top:16px;min-width:0;}
    .cfg-stack{display:grid;gap:16px;}
    .cfg-grid{display:grid;grid-template-columns:minmax(320px,.95fr) minmax(420px,1.05fr);gap:16px;align-items:start;}
    .cfg-panel{border:1px solid #23445f;border-radius:18px;background:linear-gradient(180deg,#081525,#06111d);padding:18px;box-shadow:inset 0 0 0 1px rgba(255,255,255,.015);min-width:0;max-width:100%;}
    .cfg-panel h2{margin:0 0 10px;font-size:19px;letter-spacing:.2px;}
    .cfg-panel h3{margin:18px 0 8px;font-size:13px;color:#b9d9f6;text-transform:uppercase;letter-spacing:.09em;}
    .cfg-help{color:#9fb4cc;font-size:13px;line-height:1.6;margin:0 0 12px;}
    .cfg-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;}
    .cfg-row{display:grid;grid-template-columns:1fr;gap:6px;align-items:start;margin:0;}
    .cfg-row.wide{grid-column:1 / -1;}
    .cfg-row label{margin:0;color:#d7e6f5;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.08em;}
    .cfg-example{color:#89a7c4;font-size:11px;line-height:1.45;margin-top:2px;}
    .cfg-field, .cfg-row input,.cfg-row select,.cfg-row textarea, .cfg-model-row input, .cfg-model-row select{
      width:100%;box-sizing:border-box;background:linear-gradient(180deg,#06101b,#040c18);color:#f8fafc;border:1px solid #33506a;border-radius:14px;
      padding:12px 14px;font-size:13px;outline:none;transition:border-color .16s ease, box-shadow .16s ease, transform .16s ease;
      appearance:none;
    }
    .cfg-row input:focus,.cfg-row select:focus,.cfg-row textarea:focus,.cfg-model-row input:focus,.cfg-model-row select:focus{
      border-color:#60a5fa;box-shadow:0 0 0 3px rgba(96,165,250,.14);
    }
    .cfg-row select option,.cfg-model-row select option{
      background:#06101b;
      color:#f8fafc;
    }
    .cfg-row textarea{min-height:100px;resize:vertical;font-family:"Consolas","SFMono-Regular",Menlo,monospace;}
    .cfg-secret-view{
      display:none;
      border:1px solid #2a4056;
      border-radius:12px;
      background:#07111f;
      color:#dbeafe;
      font-family:"Consolas","SFMono-Regular",Menlo,monospace;
      font-size:12px;
      line-height:1.45;
      padding:12px;
      white-space:pre-wrap;
      word-break:break-all;
      overflow-wrap:anywhere;
      max-height:160px;
      overflow:auto;
      box-sizing:border-box;
    }
    .cfg-secret-view.visible{display:block;}
    .cfg-secret-note{
      color:#9fb4cc;
      font-size:12px;
      line-height:1.45;
      margin-top:6px;
    }
    .cfg-select-wrap{position:relative;}
    .cfg-select-wrap::after{content:"";position:absolute;right:16px;top:50%;width:10px;height:10px;border-right:2px solid #8fb6d9;border-bottom:2px solid #8fb6d9;transform:translateY(-65%) rotate(45deg);pointer-events:none;}
    .cfg-actions{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:16px;}
    .cfg-status{font-size:13px;color:#9fb4cc;overflow-wrap:anywhere;word-break:break-word;min-width:0;}
    .cfg-note{margin-top:14px;padding:12px 14px;border:1px solid #36516b;border-radius:14px;background:#091423;color:#dbeafe;font-size:13px;line-height:1.55;}
    .cfg-pre{white-space:pre-wrap;background:#020617;border:1px solid #1f2937;border-radius:14px;padding:14px;overflow:auto;line-height:1.5;font-family:"Consolas","SFMono-Regular",Menlo,monospace;font-size:12px;max-width:100%;min-width:0;}
    .cfg-badges{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 0;}
    .cfg-badge{display:inline-flex;align-items:center;padding:4px 10px;border-radius:999px;border:1px solid #294560;background:#0b2130;color:#bde6ff;font-size:12px;font-weight:700;}
    .cfg-linkline{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:10px 0 16px;}
    .cfg-linkbtn{
      display:inline-flex;align-items:center;gap:8px;padding:11px 15px;border-radius:16px;
      border:1px solid #315a79;background:linear-gradient(180deg,#16324a,#102435);color:#e0f2fe;
      text-decoration:none;font-size:13px;font-weight:800;letter-spacing:.01em;
      box-shadow:0 12px 24px rgba(8,23,37,.26), inset 0 1px 0 rgba(255,255,255,.05);
      transition:transform .18s ease, box-shadow .18s ease, border-color .18s ease, filter .18s ease;
    }
    .cfg-linkbtn:hover{
      transform:translateY(-1px);filter:brightness(1.04);border-color:#60a5fa;
      box-shadow:0 16px 30px rgba(8,23,37,.34), inset 0 1px 0 rgba(255,255,255,.06);
    }
    .cfg-validate-grid{display:grid;gap:8px;}
    .cfg-check{border:1px solid #25384d;border-radius:14px;padding:12px 14px;background:#091423;}
    .cfg-check.ok{border-color:#166534;background:#062313;}
    .cfg-check.warn{border-color:#a16207;background:#2a1a06;}
    .cfg-check.error{border-color:#991b1b;background:#2a0d0d;}
    .cfg-check-head{display:flex;justify-content:space-between;gap:10px;align-items:center;margin-bottom:4px;}
    .cfg-check-name{font-weight:800;color:#f8fafc;font-size:13px;}
    .cfg-check-detail{color:#d7e6f5;font-size:13px;line-height:1.45;white-space:pre-wrap;}
    .cfg-check-meta{margin-top:6px;color:#bfd3e7;font-size:12px;line-height:1.4;white-space:pre-wrap;}
    .cfg-model-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin-top:14px;min-width:0;}
    .cfg-model-card{
      --cfg-accent:#38bdf8;
      border:1px solid color-mix(in srgb, var(--cfg-accent) 34%, #183246);border-radius:20px;
      background:
        radial-gradient(circle at top right, color-mix(in srgb, var(--cfg-accent) 18%, transparent), transparent 38%),
        linear-gradient(180deg,#0a1627,#07111f 78%);
      padding:16px 16px 14px;
      box-shadow:0 16px 30px rgba(2,6,23,.18), inset 0 1px 0 rgba(255,255,255,.03);
      position:relative;overflow:hidden;
    }
    .cfg-model-card::before{
      content:"";position:absolute;left:0;right:0;top:0;height:3px;
      background:linear-gradient(90deg,var(--cfg-accent), rgba(255,255,255,.06));
      opacity:.95;
    }
    .cfg-model-card.role-query-writer{--cfg-accent:#38bdf8;}
    .cfg-model-card.role-repair{--cfg-accent:#0ea5e9;}
    .cfg-model-card.role-evidence{--cfg-accent:#14b8a6;}
    .cfg-model-card.role-security{--cfg-accent:#22c55e;}
    .cfg-model-card.role-peer1{--cfg-accent:#a78bfa;}
    .cfg-model-card.role-peer2{--cfg-accent:#f472b6;}
    .cfg-model-card.role-continuation{--cfg-accent:#f59e0b;}
    .cfg-model-card.role-summary{--cfg-accent:#fb7185;}
    .cfg-model-card h4{margin:0 0 4px;font-size:15px;color:#f8fafc;}
    .cfg-model-card p{margin:0 0 12px;color:#9fb4cc;font-size:12px;line-height:1.55;}
    .cfg-model-label{display:block;margin:0 0 6px;color:#d7e6f5;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.08em;}
    .cfg-model-picker{display:grid;gap:12px;}
    .cfg-model-input{
      width:100%;box-sizing:border-box;background:linear-gradient(180deg,color-mix(in srgb, var(--cfg-accent) 8%, #06101b),#040c18);color:#f8fafc;border:1px solid color-mix(in srgb, var(--cfg-accent) 44%, #2a4a64);border-radius:14px;
      padding:12px 14px;font-size:13px;outline:none;transition:border-color .16s ease, box-shadow .16s ease;
    }
    .cfg-model-input:focus{border-color:var(--cfg-accent);box-shadow:0 0 0 3px color-mix(in srgb, var(--cfg-accent) 20%, transparent);}
    .cfg-model-picks{display:grid;grid-template-columns:1fr;gap:8px;max-height:188px;overflow:auto;padding-right:4px;}
    .cfg-model-pick{
      border:1px solid color-mix(in srgb, var(--cfg-accent) 38%, #29465e);
      background:linear-gradient(180deg,color-mix(in srgb, var(--cfg-accent) 13%, #13283d),#0c1d2e);
      color:#dbeafe;
      border-radius:12px;
      padding:10px 12px;
      font-size:12px;
      line-height:1.25;
      cursor:pointer;
      box-shadow:inset 0 1px 0 rgba(255,255,255,.04);
      transition:transform .16s ease, border-color .16s ease, background .16s ease, box-shadow .16s ease;
      text-align:left;
      width:100%;
      overflow-wrap:anywhere;
      word-break:break-word;
    }
    .cfg-model-pick:hover{
      transform:translateY(-1px);
      border-color:var(--cfg-accent);
      background:linear-gradient(180deg,color-mix(in srgb, var(--cfg-accent) 20%, #17324b),#10263a);
      box-shadow:0 10px 20px rgba(2,6,23,.18), inset 0 1px 0 rgba(255,255,255,.05);
    }
    .cfg-model-pick.active{
      border-color:color-mix(in srgb, var(--cfg-accent) 70%, #ffffff10);
      background:linear-gradient(180deg,color-mix(in srgb, var(--cfg-accent) 30%, #10263a),color-mix(in srgb, var(--cfg-accent) 18%, #0c1d2e));
      color:#f8fbff;
      box-shadow:0 10px 20px rgba(3,18,13,.18), inset 0 1px 0 rgba(255,255,255,.05);
    }
    .cfg-model-pick-empty{
      color:#94a3b8;
      font-size:12px;
      padding:2px 0 0;
    }
    .cfg-tip{font-size:12px;color:#a9bfd6;line-height:1.55;margin-top:8px;}
    .cfg-subgrid{display:grid;grid-template-columns:1fr 1fr;gap:14px;min-width:0;}
    .cfg-subgrid > *{min-width:0;}
    .cfg-compare{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin:14px 0 16px;min-width:0;}
    .cfg-compare > *{min-width:0;}
    .cfg-compare-card{
      border:1px solid #2a4a64;border-radius:18px;
      background:linear-gradient(180deg,#0a1627,#07111f 78%);
      padding:14px;
      box-shadow:0 14px 26px rgba(2,6,23,.16), inset 0 1px 0 rgba(255,255,255,.03);
      min-width:0;
    }
    .cfg-compare-card h4{margin:0 0 10px;font-size:13px;color:#f8fafc;letter-spacing:.02em;}
    .cfg-compare-list{display:grid;gap:6px;min-width:0;}
    .cfg-compare-item{border:1px solid #254059;border-radius:12px;background:#07111f;padding:9px 11px;color:#dbeafe;font-size:12px;line-height:1.5;overflow-wrap:anywhere;word-break:break-word;min-width:0;}
    .cfg-compare-item.ok{border-color:#166534;background:#062313;color:#dcfce7;}
    .cfg-compare-item.warn{border-color:#a16207;background:#2a1a06;color:#fde68a;}
    .cfg-personalize-card{border:1px solid #27415a;border-radius:16px;background:linear-gradient(180deg,#091423,#07111f);padding:16px;}
    .cfg-personalize-status{display:flex;gap:10px;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;}
    .cfg-personalize-copy{color:#dbeafe;font-size:13px;line-height:1.6;}
    .cfg-personalize-meta{margin-top:10px;display:grid;gap:8px;}
    .cfg-advanced{margin-top:14px;border:1px solid #27415a;border-radius:16px;background:linear-gradient(180deg,#091423,#07111f);}
    .cfg-advanced > summary{cursor:pointer;list-style:none;padding:14px 16px;display:flex;justify-content:space-between;align-items:center;gap:12px;}
    .cfg-advanced > summary::-webkit-details-marker{display:none;}
    .cfg-advanced-title{font-size:15px;font-weight:800;color:#f8fafc;}
    .cfg-advanced-copy{color:#9fb4cc;font-size:12px;line-height:1.5;margin-top:4px;}
    .cfg-advanced-toggle{color:#9fb4cc;font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;}
    .cfg-advanced[open] .cfg-advanced-toggle::after{content:"Hide";}
    .cfg-advanced:not([open]) .cfg-advanced-toggle::after{content:"Show";}
    .cfg-advanced-body{padding:0 16px 16px;border-top:1px solid #213246;}
    .cfg-deps-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:14px;align-items:stretch;}
    .cfg-deps-grid > *{min-width:0;}
    .cfg-dep-card{
      border:1px solid #2a4a64;border-radius:16px;background:linear-gradient(180deg,#0a1627,#07111f 80%);
      padding:12px 13px;box-shadow:0 14px 26px rgba(2,6,23,.16), inset 0 1px 0 rgba(255,255,255,.03);
      display:grid;gap:6px;align-content:start;
    }
    .cfg-dep-card.ok{border-color:#166534;background:linear-gradient(180deg,#0a2514,#07160d 82%);}
    .cfg-dep-card.host_only{border-color:#7c5b12;background:linear-gradient(180deg,#241808,#151008 82%);}
    .cfg-dep-card.error{border-color:#7f1d1d;background:linear-gradient(180deg,#240d0d,#13090b 82%);}
    .cfg-dep-head{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:2px;}
    .cfg-dep-name{font-size:13px;font-weight:800;color:#f8fafc;letter-spacing:.02em;text-transform:uppercase;}
    .cfg-dep-dot{width:10px;height:10px;border-radius:999px;background:#ef4444;box-shadow:0 0 0 4px rgba(239,68,68,.14);}
    .cfg-dep-card.ok .cfg-dep-dot{background:#22c55e;box-shadow:0 0 0 4px rgba(34,197,94,.14);}
    .cfg-dep-card.host_only .cfg-dep-dot{background:#f59e0b;box-shadow:0 0 0 4px rgba(245,158,11,.14);}
    .cfg-dep-cmd{font-size:11px;color:#93c5fd;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;line-height:1.35;overflow-wrap:anywhere;word-break:break-word;}
    .cfg-dep-detail{font-size:12px;color:#dbeafe;line-height:1.45;overflow-wrap:anywhere;word-break:break-word;}
    .cfg-progress-wrap{display:grid;gap:8px;margin-top:12px;}
    .cfg-progress-head{display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap;}
    .cfg-progress-track{width:100%;height:12px;border-radius:999px;border:1px solid #26435c;background:#07111f;overflow:hidden;}
    .cfg-progress-bar{height:100%;width:0%;background:linear-gradient(90deg,#22c55e,#10b981);transition:width .25s ease;}
    .cfg-progress-log{max-height:220px;}
    .cfg-shell button{
      margin-top:0;
      background:linear-gradient(135deg,#22c55e,#14b86a);
      color:#03210d;
      border:1px solid rgba(134,239,172,.22);
      border-radius:16px;
      font-weight:800;
      padding:12px 16px;
      cursor:pointer;
      letter-spacing:.01em;
      box-shadow:0 12px 24px rgba(20,184,106,.24), inset 0 1px 0 rgba(255,255,255,.18);
      transition:transform .18s ease, box-shadow .18s ease, filter .18s ease, border-color .18s ease;
    }
    .cfg-shell button:hover{
      transform:translateY(-1px);
      filter:brightness(1.03);
      box-shadow:0 16px 30px rgba(20,184,106,.30), inset 0 1px 0 rgba(255,255,255,.2);
    }
    .cfg-shell .btn-secondary{
      background:linear-gradient(180deg,#16324a,#102435);
      color:#dbeafe;
      border-color:#315a79;
      box-shadow:0 12px 24px rgba(8,23,37,.26), inset 0 1px 0 rgba(255,255,255,.05);
    }
    .cfg-shell .btn-secondary:hover{
      box-shadow:0 16px 30px rgba(8,23,37,.34), inset 0 1px 0 rgba(255,255,255,.06);
    }
    @media (max-width: 1120px){.cfg-grid{grid-template-columns:1fr;}.cfg-hero{grid-template-columns:1fr;}.cfg-deps-grid{grid-template-columns:repeat(2,minmax(0,1fr));}}
    @media (max-width: 980px){.cfg-form-grid,.cfg-subgrid,.cfg-status-board,.cfg-model-grid,.cfg-compare,.cfg-deps-grid{grid-template-columns:1fr;}}
  </style>
  <h1>Configuration</h1>
  <p class="muted">Central runtime setup for A.G.E.N.T. Smith, including Splunk MCP, the primary Ollama host, optional edge-helper routing, UI auth, tasker-role assignments, and repeatable deployment guidance for both host and Docker runtimes.</p>
  <div class="cfg-shell">
  <div class="cfg-hero">
    <div class="cfg-hero-card">
      <div class="statline" style="margin:0 0 10px;">
        <span class="badge">Release {html.escape(APP_VERSION_LABEL)}</span>
        <span class="badge">Stable branch</span>
      </div>
      <h2 class="cfg-hero-title">AGENT Smith runtime control center</h2>
      <p class="cfg-hero-copy">Use this page to point A.G.E.N.T. Smith at the right primary Ollama and Splunk services, optionally include a small edge helper for routing, assign model roles, validate live dependencies, and bring the platform online in the right order for either host or Docker deployment.</p>
      <div id="cfg-runtime" class="cfg-badges"></div>
      <div class="cfg-linkline">
        <a id="cfg-setup-link" class="cfg-linkbtn" href="/docs/view?path=runbooks/initial_setup.md">Open Initial Setup Guide</a>
        <span class="cfg-tip">Use this first on a new machine. It assumes Splunk is already installed and walks the rest of the setup step by step.</span>
      </div>
    </div>
    <div class="cfg-hero-card">
      <h3 style="margin:0 0 12px;font-size:13px;color:#b9d9f6;text-transform:uppercase;letter-spacing:.09em;">Live Dependency Status</h3>
      <div id="cfg-health-board" class="cfg-status-board">
        <div class="cfg-health-card"><div class="cfg-health-head"><span class="cfg-health-name">Ollama</span><span class="cfg-health-dot"></span></div><div class="cfg-health-detail">Waiting for validation.</div></div>
        <div class="cfg-health-card"><div class="cfg-health-head"><span class="cfg-health-name">Edge Helper</span><span class="cfg-health-dot"></span></div><div class="cfg-health-detail">Waiting for validation.</div></div>
        <div class="cfg-health-card"><div class="cfg-health-head"><span class="cfg-health-name">Splunk Base</span><span class="cfg-health-dot"></span></div><div class="cfg-health-detail">Waiting for validation.</div></div>
        <div class="cfg-health-card"><div class="cfg-health-head"><span class="cfg-health-name">Splunk MCP</span><span class="cfg-health-dot"></span></div><div class="cfg-health-detail">Waiting for validation.</div></div>
        <div class="cfg-health-card"><div class="cfg-health-head"><span class="cfg-health-name">Data Domains Init</span><span class="cfg-health-dot"></span></div><div class="cfg-health-detail">Waiting for validation.</div></div>
      </div>
    </div>
  </div>
  <div class="cfg-stack">
    <div class="cfg-step" open>
      <div class="cfg-step-body" style="margin-top:0;">
        <div class="cfg-panel">
          <h2>Current State</h2>
          <p class="cfg-help">Use this section first. It answers four operator questions: is the runtime reachable, are the model roles assigned, has Data Domains started, and what should I do next?</p>
          <div class="cfg-compare">
            <div class="cfg-compare-card">
              <h4>Live Endpoint Health</h4>
              <div class="cfg-compare-list">
                <div class="cfg-compare-item">Ollama, Splunk Base, Splunk MCP, and Data Domains health appear in the status board above.</div>
                <div class="cfg-compare-item warn">If any card above is amber or red, validate the runtime before editing deeper settings.</div>
              </div>
            </div>
            <div class="cfg-compare-card">
              <h4>Current Role Map</h4>
              <div class="cfg-compare-list">
                <div class="cfg-compare-item">Planner, SPL Writer, reviewers, and summary roles are assigned in Step 3.</div>
                <div class="cfg-compare-item">Use this page to confirm that each live role points at the model you actually intend to use.</div>
              </div>
            </div>
            <div class="cfg-compare-card">
              <h4>Next Action</h4>
              <div class="cfg-compare-list">
                <div class="cfg-compare-item ok">New host: open Step 1, then validate runtime endpoints in Step 2.</div>
                <div class="cfg-compare-item">Healthy host: refresh Data Domains in Step 5, then open SPL Optimization after you have real investigations.</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <div class="cfg-step" open>
      <div class="cfg-step-label">
        <span class="cfg-step-num">1</span>
        <div class="cfg-step-title">First-Time Setup</div>
      </div>
      <div class="cfg-step-body">
        <p class="cfg-help">Use the setup guide first on a new machine. It is now Docker-first and is meant to get a fresh deployment online with the fewest possible steps.</p>
        <div class="cfg-linkline" style="margin:0;">
          <a id="cfg-setup-link-inline" class="cfg-linkbtn" href="/docs/view?path=runbooks/initial_setup.md">Open Initial Setup Guide</a>
        </div>
        <h3 style="margin:16px 0 6px;">Dependency Checker</h3>
        <p class="cfg-help">This checks whether the current runtime can see the basic setup tools used in the install guide. Green means the command is available here. Red means it is missing here. Amber means it is a host-only prerequisite and is not expected inside the app container.</p>
        <div id="cfg-deps-note" class="cfg-note">Checking runtime dependencies...</div>
        <div id="cfg-deps-results" class="cfg-deps-grid">
          <div class="cfg-note">Dependency status will appear here.</div>
        </div>
      </div>
    </div>
    <details class="cfg-step">
      <summary>
        <div class="cfg-step-label">
          <span class="cfg-step-num">2</span>
          <div class="cfg-step-title">Live Runtime Controls</div>
        </div>
        <span class="cfg-step-toggle"></span>
      </summary>
      <div class="cfg-step-body">
      <div class="cfg-panel" style="padding:0;border:0;background:transparent;box-shadow:none;">
      <p class="cfg-help">These values drive the current host runtime and both Docker modes. Saving writes <code>config/ui.env</code>. In Docker, the initial Data Domains build starts only after Splunk MCP validates successfully.</p>
      <div class="cfg-form-grid">
      <div class="cfg-row"><label for="cfg-ollama-host">OLLAMA_HOST</label><div class="cfg-example">Example URL: <code>http://192.168.1.50:11434</code></div><input id="cfg-ollama-host" placeholder="http://192.168.1.50:11434" /></div>
      <div class="cfg-row"><label for="cfg-splunk-base">SPLUNK_BASE_URL</label><div class="cfg-example">Example URL: <code>https://192.168.1.60:8089</code></div><input id="cfg-splunk-base" placeholder="https://192.168.1.60:8089" /></div>
      <div class="cfg-row wide"><label for="cfg-splunk-mcp">SPLUNK_MCP_URL</label><div class="cfg-example">Example URL: <code>https://192.168.1.60:8089/services/mcp</code></div><input id="cfg-splunk-mcp" placeholder="https://192.168.1.60:8089/services/mcp" /></div>
      <div class="cfg-row wide">
        <label for="cfg-splunk-token">SPLUNK_LAB_BEARER_TOKEN</label>
        <div class="cfg-example">Stored server-side for the runtime. The field stays masked unless you explicitly reveal or replace it.</div>
        <input id="cfg-splunk-token" type="password" placeholder="Bearer token value" autocomplete="off" />
        <div id="cfg-splunk-token-view" class="cfg-secret-view" aria-live="polite"></div>
        <div id="cfg-token-note" class="cfg-secret-note" style="display:none;">Token is revealed in a wrapped read-only view. Hide it to return to the compact masked editor or replace it.</div>
        <div class="cfg-actions" style="margin-top:6px;">
          <button id="cfg-token-toggle" class="btn-secondary" type="button" style="margin-top:0;">Reveal Token</button>
          <button id="cfg-token-copy" class="btn-secondary" type="button" style="margin-top:0;">Copy Token</button>
          <button id="cfg-token-clear" class="btn-secondary" type="button" style="margin-top:0;">Clear Token</button>
          <span id="cfg-token-state" class="cfg-status">No saved token detected.</span>
        </div>
      </div>
      <h3>UI Access</h3>
      <div class="cfg-row"><label for="cfg-auth-enabled">SOC_UI_AUTH_ENABLED</label><div class="cfg-example">Keep this enabled for a guarded multi-user UI. First-run setup creates the initial user automatically.</div><div class="cfg-select-wrap"><select id="cfg-auth-enabled"><option value="1">1</option><option value="0">0</option></select></div></div>
      </div>
      <div class="cfg-actions">
        <button id="cfg-save">Save Configuration</button>
        <button id="cfg-validate" class="btn-secondary">Validate Current Config</button>
        <button id="cfg-mcp-probe" class="btn-secondary">Test MCP Query</button>
        <span id="cfg-status" class="cfg-status">Loading current values...</span>
      </div>
      <div class="cfg-note">
        Save updates <code>config/ui.env</code>. Restart guidance is shown on the right for host runtime, Docker wrapper, and deployment image.
      </div>
      <h3>Validation Checker</h3>
      <p class="cfg-help">This runs bounded live checks against the current values and confirms whether the Ollama endpoint, expected models, Splunk base URL, and Splunk MCP endpoint are reachable. In Docker, a successful MCP check also kicks off the first Data Domains build if it has not been created yet.</p>
      <div id="cfg-validation-summary" class="cfg-badges"></div>
      <div id="cfg-validation-results" class="cfg-validate-grid">
        <div class="cfg-note">No validation has been run yet.</div>
      </div>
      <div style="margin-top:12px;">
        <h3 style="margin:0 0 6px;">MCP Query Probe</h3>
        <p class="cfg-help">This runs a real bounded MCP tool call using the current draft values, without requiring a save first. It is meant to answer a simple question: will the configured MCP endpoint actually execute a live request right now?</p>
        <div id="cfg-mcp-probe-results" class="cfg-validate-grid">
          <div class="cfg-note">No MCP probe has been run yet.</div>
        </div>
      </div>
     </div>
     </div>
    </details>
    <details class="cfg-step">
      <summary>
        <div class="cfg-step-label">
          <span class="cfg-step-num">3</span>
          <div class="cfg-step-title">Model Role Map</div>
        </div>
        <span class="cfg-step-toggle"></span>
      </summary>
      <div class="cfg-step-body">
      <div class="cfg-panel" style="padding:0;border:0;background:transparent;box-shadow:none;">
    <p class="cfg-help">These model slots are used by the primary inference pipeline. If the primary Ollama endpoint is reachable, the selectors below are populated from the currently installed model list. Saving a model name here only assigns that role; it does not install the model. The optional edge-helper model is configured separately in Step 4.</p>
    <div id="cfg-model-compare" class="cfg-compare">
      <div class="cfg-compare-card"><h4>Expected</h4><div id="cfg-expected-list" class="cfg-compare-list"></div></div>
      <div class="cfg-compare-card"><h4>Installed</h4><div id="cfg-installed-list" class="cfg-compare-list"></div></div>
      <div class="cfg-compare-card"><h4>Missing</h4><div id="cfg-missing-list" class="cfg-compare-list"></div></div>
    </div>
    <div class="cfg-model-grid">
      <div class="cfg-model-card role-security"><h4>Planner</h4><p>Interprets analyst intent, likely data sources, and search strategy before SPL generation.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-planner">Assigned model</label><input id="cfg-model-planner" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-planner-picks" class="cfg-model-picks"></div></div></div></div>
      <div class="cfg-model-card role-query-writer"><h4>SPL Writer</h4><p>Turns the structured plan into bounded read-only SPL or a bounded MCP retrieval call.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-query-writer">Assigned model</label><input id="cfg-model-query-writer" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-query-writer-picks" class="cfg-model-picks"></div></div></div></div>
      <div class="cfg-model-card role-repair"><h4>Query Repair</h4><p>Used when the reviewer or validation path requests a bounded rewrite of the SPL before final approval.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-repair">Assigned model</label><input id="cfg-model-repair" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-repair-picks" class="cfg-model-picks"></div></div></div></div>
      <div class="cfg-model-card role-evidence"><h4>Evidence Reviewer</h4><p>Checks whether conclusions are supported by the returned rows.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-evidence">Assigned model</label><input id="cfg-model-evidence" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-evidence-picks" class="cfg-model-picks"></div></div></div></div>
      <div class="cfg-model-card role-security"><h4>Security Reviewer</h4><p>Critiques the planned query for quality, alignment, and safety.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-security">Assigned model</label><input id="cfg-model-security" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-security-picks" class="cfg-model-picks"></div></div></div></div>
      <div class="cfg-model-card role-peer1"><h4>Peer Reviewer 1</h4><p>Conditional adjudication pass used only when the security reviewer does not cleanly approve the writer output.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-peer1">Assigned model</label><input id="cfg-model-peer1" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-peer1-picks" class="cfg-model-picks"></div></div></div></div>
      <div class="cfg-model-card role-peer2"><h4>Peer Reviewer 2</h4><p>Conditional second adjudication pass that validates or overrides the first peer-review decision.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-peer2">Assigned model</label><input id="cfg-model-peer2" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-peer2-picks" class="cfg-model-picks"></div></div></div></div>
      <div class="cfg-model-card role-continuation"><h4>Continuation Reviewer</h4><p>Decides whether deeper investigation is worth another bounded pivot.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-continuation">Assigned model</label><input id="cfg-model-continuation" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-continuation-picks" class="cfg-model-picks"></div></div></div></div>
      <div class="cfg-model-card role-summary"><h4>Final Summary</h4><p>Produces the analyst-facing narrative after evidence and gates are complete.</p><div class="cfg-model-picker"><div><label class="cfg-model-label" for="cfg-model-summary">Assigned model</label><input id="cfg-model-summary" class="cfg-model-input" list="cfg-models-list" /></div><div><label class="cfg-model-label">Installed models</label><div id="cfg-model-summary-picks" class="cfg-model-picks"></div></div></div></div>
    </div>
    <datalist id="cfg-models-list"></datalist>
    <div class="cfg-tip">Recommended flow: pick a model already visible from Ollama, save the assignment, then use the generated pull commands below to install anything that is missing.</div>
    <div class="cfg-subgrid">
      <div>
        <h3>Generated Ollama Pull Commands</h3>
        <pre id="cfg-ollama-pulls" class="cfg-pre"></pre>
        <h3>Connectivity Checks</h3>
        <pre id="cfg-checks" class="cfg-pre"></pre>
      </div>
      <div>
        <h3>Generated Splunk MCP Config</h3>
        <pre id="cfg-mcp-json" class="cfg-pre"></pre>
        <h3>Restart Commands</h3>
        <pre id="cfg-restart" class="cfg-pre"></pre>
      </div>
    </div>
    </div>
    </details>
    <details class="cfg-step">
      <summary>
        <div class="cfg-step-label">
          <span class="cfg-step-num">4</span>
          <div class="cfg-step-title">Optional Edge Routing</div>
        </div>
        <span class="cfg-step-toggle"></span>
      </summary>
      <div class="cfg-step-body">
      <div class="cfg-panel" style="padding:0;border:0;background:transparent;box-shadow:none;">
      <p class="cfg-help">This is optional. Leave it disabled if you want the primary inference host to handle all planning, writing, and review stages. Enable it only when you want a small edge-hosted model to assist with question routing, split-query hints, or cheap confidence pre-checks.</p>
      <div class="cfg-form-grid">
      <div class="cfg-row"><label for="cfg-edge-enabled">EDGE_LLM_ENABLED</label><div class="cfg-example">Use <code>0</code> to leave the edge helper out of the runtime entirely.</div><div class="cfg-select-wrap"><select id="cfg-edge-enabled"><option value="0">0</option><option value="1">1</option></select></div></div>
      <div class="cfg-row"><label for="cfg-edge-role">EDGE_LLM_ROLE</label><div class="cfg-example">Recommended: <code>edge_router_splitter</code></div><input id="cfg-edge-role" placeholder="edge_router_splitter" /></div>
      <div class="cfg-row"><label for="cfg-edge-host">EDGE_LLM_HOST</label><div class="cfg-example">Example URL: <code>http://192.168.1.70:11434</code></div><input id="cfg-edge-host" placeholder="http://192.168.1.70:11434" /></div>
      <div class="cfg-row"><label for="cfg-edge-timeout">EDGE_LLM_TIMEOUT_SEC</label><div class="cfg-example">Short timeout for a cheap routing helper. Example: <code>60</code></div><input id="cfg-edge-timeout" placeholder="60" /></div>
      <div class="cfg-row wide"><label for="cfg-edge-model">EDGE_LLM_MODEL</label><div class="cfg-example">Small routing model name visible from the edge Ollama host. Example: <code>qwen2.5:1.5b</code></div><input id="cfg-edge-model" list="cfg-edge-models-list" placeholder="qwen2.5:1.5b" /></div>
      </div>
      <div class="cfg-note">
        If enabled, validation checks the edge endpoint, confirms the assigned model is installed, and lists the models currently visible from the edge Ollama host. If disabled, the checker records that the helper is intentionally excluded.
      </div>
      <div class="cfg-actions">
        <button id="cfg-edge-save">Save Edge Helper</button>
        <button id="cfg-edge-validate" class="btn-secondary">Validate Edge Helper</button>
        <span id="cfg-edge-status" class="cfg-status">No edge validation has been run yet.</span>
      </div>
      <h3>Edge Validation Checker</h3>
      <div id="cfg-edge-validation-results" class="cfg-validate-grid">
        <div class="cfg-note">No edge validation has been run yet.</div>
      </div>
      <div class="cfg-subgrid">
        <div>
          <h3>Edge Helper Checks</h3>
          <pre id="cfg-edge-checks" class="cfg-pre"></pre>
        </div>
        <div>
          <h3>Installed Edge Models</h3>
          <div id="cfg-edge-model-picks" class="cfg-model-picks"></div>
        </div>
      </div>
      <h3>Edge Pull Command</h3>
      <pre id="cfg-edge-pull" class="cfg-pre"></pre>
      <datalist id="cfg-edge-models-list"></datalist>
      </div>
      </div>
    </details>
    <details class="cfg-step">
      <summary>
        <div class="cfg-step-label">
          <span class="cfg-step-num">5</span>
          <div class="cfg-step-title">Environment Grounding</div>
        </div>
        <span class="cfg-step-toggle"></span>
      </summary>
      <div class="cfg-step-body">
      <div class="cfg-panel" style="padding:0;border:0;background:transparent;box-shadow:none;">
        <div class="cfg-personalize-card">
          <div class="cfg-personalize-status">
            <div>
              <h3 style="margin-top:0;">Refresh Data Domains</h3>
              <p class="cfg-help">This scans Splunk through MCP and rebuilds the local environment profile: accessible indexes, sourcetypes, tag inventory, and a bounded field inventory for the sources the system has seen. On first setup, this is the main button you should run after runtime validation succeeds.</p>
            </div>
            <span id="cfg-env-refresh-state" class="cfg-badge">state=unknown</span>
          </div>
          <div id="cfg-env-refresh-detail" class="cfg-personalize-copy">Waiting for configuration load.</div>
          <div class="cfg-actions">
            <button id="cfg-env-refresh">Refresh Data Domains</button>
            <button id="cfg-env-wipe-refresh" class="btn-green" type="button">Wipe And Refresh</button>
            <span id="cfg-env-refresh-status" class="cfg-status">Not started.</span>
          </div>
          <div class="cfg-progress-wrap">
            <div class="cfg-progress-head">
              <span id="cfg-env-refresh-phase" class="cfg-note" style="margin-top:0;">phase=idle</span>
              <span id="cfg-env-refresh-pct" class="cfg-badge">0%</span>
            </div>
            <div class="cfg-progress-track"><div id="cfg-env-refresh-bar" class="cfg-progress-bar"></div></div>
            <pre id="cfg-env-refresh-log" class="cfg-pre cfg-progress-log">No refresh output yet.</pre>
          </div>
          <div class="cfg-personalize-meta">
            <div id="cfg-env-refresh-path" class="cfg-note">Refresh log path will appear here.</div>
            <div class="cfg-note">Use this again later only when your Splunk data changes materially: new indexes, new sourcetypes, new tags, or after reconnecting MCP to a different environment.</div>
          </div>
        </div>
        <details class="cfg-advanced">
          <summary>
            <div>
              <div class="cfg-advanced-title">Advanced: Rebuild Personalization Only</div>
              <div class="cfg-advanced-copy">Most users do not need this. A successful Data Domains refresh already rebuilds the environment-aware skillpack automatically.</div>
            </div>
            <span class="cfg-advanced-toggle"></span>
          </summary>
          <div class="cfg-advanced-body">
            <div class="cfg-personalize-status">
              <div>
                <h3 style="margin-top:16px;">Environment-Aware SPL Personalization</h3>
                <p class="cfg-help">This rebuilds the environment-aware SPL guidance layer from the current profile only. Use it when Data Domains already exist and you want to regenerate the local skillpack again without re-scanning Splunk.</p>
              </div>
              <span id="cfg-personalize-state" class="cfg-badge">state=unknown</span>
            </div>
            <div id="cfg-personalize-detail" class="cfg-personalize-copy">Waiting for configuration load.</div>
            <div class="cfg-actions">
              <button id="cfg-personalize" class="btn-secondary">Rebuild Personalization Only</button>
              <span id="cfg-personalize-status" class="cfg-status">Not started.</span>
            </div>
            <div class="cfg-progress-wrap">
              <div class="cfg-progress-head">
                <span id="cfg-personalize-phase" class="cfg-note" style="margin-top:0;">phase=idle</span>
                <span id="cfg-personalize-pct" class="cfg-badge">0%</span>
              </div>
              <div class="cfg-progress-track"><div id="cfg-personalize-bar" class="cfg-progress-bar"></div></div>
              <pre id="cfg-personalize-log" class="cfg-pre cfg-progress-log">No personalization output yet.</pre>
            </div>
            <div class="cfg-personalize-meta">
              <div id="cfg-personalize-path" class="cfg-note">Skillpack path will appear after personalization exists.</div>
              <div class="cfg-note">If you are setting up the platform for the first time, do not use this button. Run <strong>Refresh Data Domains</strong> and let that complete.</div>
            </div>
          </div>
        </details>
      </div>
      </div>
    </details>
    <details class="cfg-step">
      <summary>
        <div class="cfg-step-label">
          <span class="cfg-step-num">6</span>
          <div class="cfg-step-title">Optimization And Review</div>
        </div>
        <span class="cfg-step-toggle"></span>
      </summary>
      <div class="cfg-step-body">
      <div class="cfg-panel" style="padding:0;border:0;background:transparent;box-shadow:none;">
        <p class="cfg-help">The SPL Optimization AI Engine now has its own Control Center page so you can review proposed SPL assets, approve or reject them, and keep optimization history separate from endpoint setup.</p>
        <div class="cfg-note">Design rule: shipped logic stays deterministic; SPL optimization stays local, reviewable, benchmarked, and reversible.</div>
        <div class="cfg-actions" style="margin-top:12px;">
          <a class="btn-secondary" href="/learning" style="text-decoration:none;display:inline-flex;align-items:center;justify-content:center;">Open SPL Optimization</a>
          <span class="cfg-status">Use this after Data Domains exist and you have some real investigations to learn from.</span>
        </div>
      </div>
      </div>
    </details>
  </div>
</div>
</div>
<script>
  const cfg$ = (id) => document.getElementById(id);
  function cfgEscape(v){return String(v ?? '');}
  function cfgRenderDependencies(payload){
    const data = payload || {};
    cfg$('cfg-deps-note').textContent = data.scope_note || 'No dependency scope note available.';
    const checks = Array.isArray(data.checks) ? data.checks : [];
    if(!checks.length){
      cfg$('cfg-deps-results').innerHTML = '<div class="cfg-note">No dependency results available.</div>';
      return;
    }
    cfg$('cfg-deps-results').innerHTML = checks.map((item) => {
      const state = String(item.state || 'error');
      const stateLabel = state === 'ok' ? 'green' : (state === 'host_only' ? 'host only' : 'red');
      return `
        <div class="cfg-dep-card ${state}">
          <div class="cfg-dep-head">
            <div class="cfg-dep-name">${cfgEscape(item.key)}</div>
            <span class="cfg-dep-dot" title="${cfgEscape(stateLabel)}"></span>
          </div>
          <div class="cfg-dep-cmd">${cfgEscape(item.command || '')}</div>
          <div class="cfg-dep-detail">${cfgEscape(item.detail || '')}</div>
        </div>
      `;
    }).join('');
  }
  const cfgModelPairs = [
    ['cfg-model-planner','cfg-model-planner-picks'],
    ['cfg-model-query-writer','cfg-model-query-writer-picks'],
    ['cfg-model-repair','cfg-model-repair-picks'],
    ['cfg-model-evidence','cfg-model-evidence-picks'],
    ['cfg-model-security','cfg-model-security-picks'],
    ['cfg-model-peer1','cfg-model-peer1-picks'],
    ['cfg-model-peer2','cfg-model-peer2-picks'],
    ['cfg-model-continuation','cfg-model-continuation-picks'],
    ['cfg-model-summary','cfg-model-summary-picks']
  ];
  let cfgTokenMasked = false;
  let cfgTokenReveal = false;
  let cfgTokenActual = '';
  let cfgTokenFetched = false;
  function cfgShowMaskedTokenEditor(){
    cfg$('cfg-splunk-token').style.display = 'block';
    cfg$('cfg-splunk-token').type = 'password';
    cfg$('cfg-splunk-token-view').classList.remove('visible');
    cfg$('cfg-token-note').style.display = 'none';
    cfg$('cfg-token-toggle').textContent = 'Reveal Token';
    cfgTokenReveal = false;
  }
  function cfgShowRevealedToken(value){
    cfg$('cfg-splunk-token-view').textContent = String(value || '');
    cfg$('cfg-splunk-token-view').classList.add('visible');
    cfg$('cfg-splunk-token').style.display = 'none';
    cfg$('cfg-token-note').style.display = 'block';
    cfg$('cfg-token-toggle').textContent = 'Hide Token';
    cfgTokenReveal = true;
  }
  async function cfgFetchRuntimeSecret(){
    const resp = await fetch('/api/config/runtime-secret?name=SPLUNK_LAB_BEARER_TOKEN');
    const data = await resp.json();
    if(!resp.ok){ throw new Error(data.error || `secret fetch failed (${resp.status})`); }
    cfgTokenActual = String(data.value || '');
    cfgTokenFetched = true;
    return cfgTokenActual;
  }
  function cfgApplyPayload(values){
    const payload = values || {};
    cfg$('cfg-ollama-host').value = payload.OLLAMA_HOST || '';
    cfg$('cfg-splunk-base').value = payload.SPLUNK_BASE_URL || '';
    cfg$('cfg-splunk-mcp').value = payload.SPLUNK_MCP_URL || '';
    cfg$('cfg-splunk-token').value = payload.SPLUNK_LAB_BEARER_TOKEN || '';
    cfgTokenMasked = String(payload.SPLUNK_LAB_BEARER_TOKEN || '') === '__KEEP_EXISTING_SPLUNK_TOKEN__';
    cfgTokenActual = '';
    cfgTokenFetched = false;
    cfgShowMaskedTokenEditor();
    cfg$('cfg-auth-enabled').value = payload.SOC_UI_AUTH_ENABLED || '1';
    cfg$('cfg-edge-enabled').value = payload.EDGE_LLM_ENABLED || '0';
    cfg$('cfg-edge-host').value = payload.EDGE_LLM_HOST || '';
    cfg$('cfg-edge-model').value = payload.EDGE_LLM_MODEL || '';
    cfg$('cfg-edge-role').value = payload.EDGE_LLM_ROLE || 'edge_router_splitter';
    cfg$('cfg-edge-timeout').value = payload.EDGE_LLM_TIMEOUT_SEC || '60';
    cfg$('cfg-model-planner').value = payload.OLLAMA_MODEL_QUERY_PLANNER || '';
    cfg$('cfg-model-query-writer').value = payload.OLLAMA_MODEL_QUERY_WRITER || '';
    cfg$('cfg-model-repair').value = payload.OLLAMA_MODEL_QUERY_REPAIR || '';
    cfg$('cfg-model-evidence').value = payload.OLLAMA_MODEL_EVIDENCE_REVIEWER || '';
    cfg$('cfg-model-security').value = payload.OLLAMA_MODEL_SECURITY_REVIEWER || '';
    cfg$('cfg-model-peer1').value = payload.OLLAMA_MODEL_PEER_REVIEWER || '';
    cfg$('cfg-model-peer2').value = payload.OLLAMA_MODEL_PEER_REVIEWER_2 || '';
    cfg$('cfg-model-continuation').value = payload.OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER || '';
    cfg$('cfg-model-summary').value = payload.OLLAMA_MODEL_FINAL_SUMMARY || '';
  }
  function cfgApplySecretState(secretState){
    const meta = secretState || {};
    const present = Boolean(meta.splunk_token_present);
    const masked = String(meta.splunk_token_masked || '').trim();
    cfg$('cfg-token-state').textContent = present
      ? `Saved token detected (${masked || 'masked'}). Leave the field as-is to keep it, replace it to rotate it, or clear it to remove it.`
      : 'No saved token detected.';
  }
  const cfgDefaultAssignments = {
    OLLAMA_MODEL_QUERY_PLANNER: 'hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M',
    OLLAMA_MODEL_QUERY_WRITER: 'deepseek-coder-v2:lite',
    OLLAMA_MODEL_QUERY_REPAIR: 'deepseek-coder-v2:lite',
    OLLAMA_MODEL_EVIDENCE_REVIEWER: 'hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest',
    OLLAMA_MODEL_SECURITY_REVIEWER: 'hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest',
    OLLAMA_MODEL_PEER_REVIEWER: 'hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M',
    OLLAMA_MODEL_PEER_REVIEWER_2: 'hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M',
    OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER: 'hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest',
    OLLAMA_MODEL_FINAL_SUMMARY: 'hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest'
  };
  function cfgExpectedModelsFromValues(values, explicitExpected){
    const explicit = Array.isArray(explicitExpected) ? explicitExpected.filter(Boolean) : [];
    if(explicit.length){ return explicit; }
    const raw = Object.values(cfgDefaultAssignments).map((model) => String(model || '').trim()).filter(Boolean);
    return raw.filter((model, index) => raw.indexOf(model) === index);
  }
  function cfgRenderModelCompare(values, installedModels, explicitExpected){
    const expected = cfgExpectedModelsFromValues(values || {}, explicitExpected);
    const installed = Array.isArray(installedModels) ? installedModels : [];
    const missing = expected.filter(model => !installed.includes(model));
    const renderList = (id, items, cls='') => {
      cfg$(id).innerHTML = items.length
        ? items.map(item => `<div class="cfg-compare-item ${cls}">${cfgEscape(item)}</div>`).join('')
        : '<div class="cfg-compare-item">None</div>';
    };
    renderList('cfg-expected-list', expected);
    renderList('cfg-installed-list', installed, 'ok');
    renderList('cfg-missing-list', missing, missing.length ? 'warn' : 'ok');
  }
  function cfgAutoAssignDefaults(values, installedModels){
    const assigned = {...values};
    const installed = new Set(Array.isArray(installedModels) ? installedModels : []);
    Object.entries(cfgDefaultAssignments).forEach(([key, model]) => {
      if(String(assigned[key] || '').trim()){ return; }
      if(installed.has(model)){ assigned[key] = model; }
    });
    return assigned;
  }
  function cfgRenderPersonalization(meta){
    const state = String(meta?.state || 'unknown');
    const pct = Math.max(0, Math.min(100, Number(meta?.progress_pct || 0)));
    cfg$('cfg-personalize-state').textContent = `state=${state}`;
    cfg$('cfg-personalize-detail').textContent = meta?.detail || 'No personalization state available.';
    const path = meta?.path ? `Skillpack path: ${meta.path}` : 'Skillpack path will appear after personalization exists.';
    cfg$('cfg-personalize-path').textContent = path;
    cfg$('cfg-personalize-phase').textContent = `phase=${meta?.phase || 'idle'}`;
    cfg$('cfg-personalize-pct').textContent = `${Math.round(pct)}%`;
    cfg$('cfg-personalize-bar').style.width = `${pct}%`;
    cfg$('cfg-personalize-log').textContent = meta?.output || 'No personalization output yet.';
    const btn = cfg$('cfg-personalize');
    const blocked = state === 'blocked' || state === 'in_progress';
    btn.disabled = blocked;
    if(state === 'in_progress'){
      btn.textContent = 'Rebuilding Personalization...';
    } else if (state === 'ready'){
      btn.textContent = 'Rebuild Personalization';
    } else {
      btn.textContent = 'Rebuild Personalization Only';
    }
  }
  let cfgPersonalizePoll = null;
  async function cfgPollPersonalization(){
    const resp = await fetch('/api/config/personalize');
    const data = await resp.json();
    if(!resp.ok){
      cfg$('cfg-personalize-status').textContent = data.error || `personalization status failed (${resp.status})`;
      return;
    }
    cfgRenderPersonalization(data.personalization || {});
    const state = String(data.personalization?.state || 'unknown');
    if(state === 'in_progress'){
      cfg$('cfg-personalize-status').textContent = data.personalization?.detail || 'Rebuilding personalization...';
      if(!cfgPersonalizePoll){
        cfgPersonalizePoll = window.setInterval(cfgPollPersonalization, 1200);
      }
      return;
    }
    if(cfgPersonalizePoll){
      window.clearInterval(cfgPersonalizePoll);
      cfgPersonalizePoll = null;
    }
    if(state === 'ready'){
      cfg$('cfg-personalize-status').textContent = data.personalization?.detail || 'Personalization complete.';
      return;
    }
    if(state === 'error'){
      cfg$('cfg-personalize-status').textContent = data.personalization?.detail || 'Personalization failed.';
      return;
    }
    cfg$('cfg-personalize-status').textContent = data.personalization?.detail || 'Ready.';
  }
  function cfgRenderEnvRefresh(meta){
    const state = String(meta?.state || 'unknown');
    const pct = Math.max(0, Math.min(100, Number(meta?.progress_pct || 0)));
    cfg$('cfg-env-refresh-state').textContent = `state=${state}`;
    cfg$('cfg-env-refresh-detail').textContent = meta?.detail || 'No environment refresh state available.';
    cfg$('cfg-env-refresh-phase').textContent = `phase=${meta?.phase || 'idle'}`;
    cfg$('cfg-env-refresh-pct').textContent = `${Math.round(pct)}%`;
    cfg$('cfg-env-refresh-bar').style.width = `${pct}%`;
    cfg$('cfg-env-refresh-log').textContent = meta?.output || 'No refresh output yet.';
    cfg$('cfg-env-refresh-path').textContent = meta?.log_path ? `Refresh log: ${meta.log_path}` : 'Refresh log path will appear here.';
    cfg$('cfg-env-refresh').disabled = state === 'in_progress';
    if(cfg$('cfg-env-wipe-refresh')){
      cfg$('cfg-env-wipe-refresh').disabled = state === 'in_progress';
    }
  }
  let cfgEnvRefreshPoll = null;
  async function cfgPollEnvRefresh(){
    const resp = await fetch('/api/config/env-refresh');
    const data = await resp.json();
    if(!resp.ok){
      cfg$('cfg-env-refresh-status').textContent = data.error || `refresh status failed (${resp.status})`;
      return;
    }
    cfgRenderEnvRefresh(data.refresh || {});
    const state = String(data.refresh?.state || 'unknown');
    if(state === 'in_progress'){
      cfg$('cfg-env-refresh-status').textContent = data.refresh?.detail || 'Refreshing Data Domains...';
      if(!cfgEnvRefreshPoll){
        cfgEnvRefreshPoll = window.setInterval(cfgPollEnvRefresh, 1200);
      }
      return;
    }
    if(cfgEnvRefreshPoll){
      window.clearInterval(cfgEnvRefreshPoll);
      cfgEnvRefreshPoll = null;
    }
    if(state === 'ready'){
      cfg$('cfg-env-refresh-status').textContent = data.refresh?.detail || 'Data Domains refresh complete.';
      await cfgPollPersonalization();
    } else if(state === 'error'){
      cfg$('cfg-env-refresh-status').textContent = data.refresh?.detail || 'Data Domains refresh failed.';
    }
  }
  function cfgCollectPayload(){
    const tokenValue = cfg$('cfg-splunk-token').value.trim();
    return {
      OLLAMA_HOST: cfg$('cfg-ollama-host').value.trim(),
      SPLUNK_BASE_URL: cfg$('cfg-splunk-base').value.trim(),
      SPLUNK_MCP_URL: cfg$('cfg-splunk-mcp').value.trim(),
      SPLUNK_LAB_BEARER_TOKEN: cfgTokenMasked && !tokenValue ? '' : (tokenValue || (cfgTokenMasked ? '__KEEP_EXISTING_SPLUNK_TOKEN__' : '')),
      SOC_UI_AUTH_ENABLED: cfg$('cfg-auth-enabled').value.trim(),
      EDGE_LLM_ENABLED: cfg$('cfg-edge-enabled').value.trim(),
      EDGE_LLM_HOST: cfg$('cfg-edge-host').value.trim(),
      EDGE_LLM_MODEL: cfg$('cfg-edge-model').value.trim(),
      EDGE_LLM_ROLE: cfg$('cfg-edge-role').value.trim(),
      EDGE_LLM_TIMEOUT_SEC: cfg$('cfg-edge-timeout').value.trim(),
      OLLAMA_MODEL_QUERY_PLANNER: cfg$('cfg-model-planner').value.trim(),
      OLLAMA_MODEL_QUERY_WRITER: cfg$('cfg-model-query-writer').value.trim(),
      OLLAMA_MODEL_QUERY_REPAIR: cfg$('cfg-model-repair').value.trim(),
      OLLAMA_MODEL_EVIDENCE_REVIEWER: cfg$('cfg-model-evidence').value.trim(),
      OLLAMA_MODEL_SECURITY_REVIEWER: cfg$('cfg-model-security').value.trim(),
      OLLAMA_MODEL_PEER_REVIEWER: cfg$('cfg-model-peer1').value.trim(),
      OLLAMA_MODEL_PEER_REVIEWER_2: cfg$('cfg-model-peer2').value.trim(),
      OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER: cfg$('cfg-model-continuation').value.trim(),
      OLLAMA_MODEL_FINAL_SUMMARY: cfg$('cfg-model-summary').value.trim()
    };
  }
  function cfgRenderQuickPicks(inputId, pickerId, models){
    const picker = cfg$(pickerId);
    const input = cfg$(inputId);
    const current = String(input.value || '').trim();
    if(!Array.isArray(models) || !models.length){
      picker.innerHTML = '<div class="cfg-model-pick-empty">No installed models discovered yet.</div>';
      return;
    }
    picker.innerHTML = models.map((model) => {
      const active = current === model ? ' active' : '';
      return `<button type="button" class="cfg-model-pick${active}" data-model="${cfgEscape(model)}">${cfgEscape(model)}</button>`;
    }).join('');
    picker.querySelectorAll('.cfg-model-pick').forEach((btn) => {
      btn.onclick = () => {
        input.value = btn.getAttribute('data-model') || '';
        cfgRenderQuickPicks(inputId, pickerId, models);
      };
    });
  }
  function cfgRenderEdgeModelOptions(models){
    const list = cfg$('cfg-edge-models-list');
    const picker = cfg$('cfg-edge-model-picks');
    const input = cfg$('cfg-edge-model');
    list.innerHTML = '';
    const normalized = Array.isArray(models) ? models : [];
    normalized.forEach((model) => {
      const option = document.createElement('option');
      option.value = model;
      list.appendChild(option);
    });
    const current = String(input.value || '').trim();
    if(!normalized.length){
      picker.innerHTML = '<div class="cfg-model-pick-empty">No edge models discovered yet.</div>';
      return;
    }
    picker.innerHTML = normalized.map((model) => {
      const active = current === model ? ' active' : '';
      return `<button type="button" class="cfg-model-pick${active}" data-model="${cfgEscape(model)}">${cfgEscape(model)}</button>`;
    }).join('');
    picker.querySelectorAll('.cfg-model-pick').forEach((btn) => {
      btn.onclick = () => {
        input.value = btn.getAttribute('data-model') || '';
        cfgRenderEdgeModelOptions(normalized);
      };
    });
    input.oninput = () => cfgRenderEdgeModelOptions(normalized);
  }
  function cfgPopulateModelOptions(models){
    const list = cfg$('cfg-models-list');
    list.innerHTML = '';
    const normalized = Array.isArray(models) ? models : [];
    normalized.forEach((model) => {
      const option = document.createElement('option');
      option.value = model;
      list.appendChild(option);
    });
    cfgModelPairs.forEach(([inputId, pickerId]) => {
      const input = cfg$(inputId);
      input.oninput = () => cfgRenderQuickPicks(inputId, pickerId, normalized);
      cfgRenderQuickPicks(inputId, pickerId, normalized);
    });
  }
  function cfgRenderEdgeValidation(data){
    const checks = Array.isArray(data?.checks) ? data.checks : [];
    const edgeCheck = checks.find((item) => String(item?.name || '') === 'edge_helper');
    if(!edgeCheck){
      cfg$('cfg-edge-validation-results').innerHTML = '<div class="cfg-note">No edge validation results available.</div>';
      return;
    }
    const extraBits = [];
    if(Array.isArray(edgeCheck.models) && edgeCheck.models.length){ extraBits.push(`models: ${edgeCheck.models.join(', ')}`); }
    if(Array.isArray(edgeCheck.missing_models) && edgeCheck.missing_models.length){ extraBits.push(`missing: ${edgeCheck.missing_models.join(', ')}`); }
    cfg$('cfg-edge-validation-results').innerHTML = `
      <div class="cfg-check ${cfgEscape(edgeCheck.status || 'warn')}">
        <div class="cfg-check-head">
          <div class="cfg-check-name">edge_helper</div>
          <span class="cfg-badge">${cfgEscape(edgeCheck.status || 'unknown')}</span>
        </div>
        <div class="cfg-check-detail">${cfgEscape(edgeCheck.detail || '')}</div>
        ${extraBits.length ? `<div class="cfg-check-meta">${cfgEscape(extraBits.join('\\n'))}</div>` : ''}
      </div>
    `;
  }
  function cfgRenderValidation(data){
    const summary = data.summary || {};
    cfg$('cfg-validation-summary').innerHTML = [
      `<span class="cfg-badge">ok=${cfgEscape(summary.ok || 0)}</span>`,
      `<span class="cfg-badge">warn=${cfgEscape(summary.warn || 0)}</span>`,
      `<span class="cfg-badge">error=${cfgEscape(summary.error || 0)}</span>`
    ].join('');
    const checks = Array.isArray(data.checks) ? data.checks : [];
    if(!checks.length){
      cfg$('cfg-validation-results').innerHTML = '<div class="cfg-note">No validation results available.</div>';
      return;
    }
    cfg$('cfg-validation-results').innerHTML = checks.map((check) => {
      const extraBits = [];
      if(Array.isArray(check.models) && check.models.length){ extraBits.push(`models: ${check.models.join(', ')}`); }
      if(Array.isArray(check.missing_models) && check.missing_models.length){ extraBits.push(`missing: ${check.missing_models.join(', ')}`); }
      return `
        <div class="cfg-check ${cfgEscape(check.status || 'warn')}">
          <div class="cfg-check-head">
            <div class="cfg-check-name">${cfgEscape(check.name || 'check')}</div>
            <span class="cfg-badge">${cfgEscape(check.status || 'unknown')}</span>
          </div>
          <div class="cfg-check-detail">${cfgEscape(check.detail || '')}</div>
          ${extraBits.length ? `<div class="cfg-check-meta">${cfgEscape(extraBits.join('\\n'))}</div>` : ''}
        </div>
      `;
    }).join('');
    const statusMap = {};
    checks.forEach((check) => { statusMap[check.name] = check; });
    const healthCards = [
      ['ollama_api', 'Ollama'],
      ['edge_helper', 'Edge Helper'],
      ['splunk_base', 'Splunk Base'],
      ['splunk_mcp', 'Splunk MCP'],
      ['environment_profile', 'Data Domains Init']
    ];
    cfg$('cfg-health-board').innerHTML = healthCards.map(([key, label]) => {
      const check = statusMap[key] || {};
      const state = cfgEscape(check.status || 'warn');
      const detail = cfgEscape(check.detail || 'Validation has not completed yet.');
      return `
        <div class="cfg-health-card">
          <div class="cfg-health-head">
            <span class="cfg-health-name">${cfgEscape(label)}</span>
            <span class="cfg-health-dot ${state}"></span>
          </div>
          <div class="cfg-health-detail">${detail}</div>
        </div>
      `;
    }).join('');
  }
  function cfgRenderMcpProbe(data){
    const payload = data || {};
    const status = String(payload.status || 'error');
    const extras = [];
    if(payload.tool){ extras.push(`tool: ${payload.tool}`); }
    if(typeof payload.rows_returned !== 'undefined'){ extras.push(`rows_returned: ${payload.rows_returned}`); }
    if(payload.http_status){ extras.push(`http_status: ${payload.http_status}`); }
    if(payload.raw_excerpt){ extras.push(`excerpt: ${payload.raw_excerpt}`); }
    cfg$('cfg-mcp-probe-results').innerHTML = `
      <div class="cfg-check ${cfgEscape(status)}">
        <div class="cfg-check-head">
          <div class="cfg-check-name">mcp_query_probe</div>
          <span class="cfg-badge">${cfgEscape(status)}</span>
        </div>
        <div class="cfg-check-detail">${cfgEscape(payload.detail || 'No MCP probe result available.')}</div>
        ${extras.length ? `<div class="cfg-check-meta">${cfgEscape(extras.join('\\n'))}</div>` : ''}
      </div>
    `;
  }
  function cfgRender(data){
    const values = data.values || {};
    cfgApplyPayload(values);
    cfgApplySecretState(data.secret_state || {});
    cfgPopulateModelOptions(data.ollama_available_models || []);
    cfgRenderModelCompare(values, data.ollama_available_models || [], data.expected_models || []);
    cfg$('cfg-ollama-pulls').textContent = (data.ollama_pull_commands || []).join('\\n') || 'No model pull commands generated.';
    cfg$('cfg-mcp-json').textContent = data.splunk_mcp_config_json || '{}';
    cfg$('cfg-checks').textContent = [
      data.connectivity_checks?.ollama_tags || '',
      data.connectivity_checks?.edge_ollama_tags || '',
      data.connectivity_checks?.splunk_mcp || ''
    ].filter(Boolean).join('\\n\\n');
    cfg$('cfg-edge-checks').textContent = data.connectivity_checks?.edge_ollama_tags || 'Edge helper disabled or not configured.';
    cfgRenderEdgeModelOptions(data.edge_ollama_available_models || []);
    cfg$('cfg-edge-pull').textContent = data.edge_helper?.pull_command || 'No edge model pull command generated.';
    cfgRenderEdgeValidation({checks: []});
    cfg$('cfg-restart').textContent = [
      `Host runtime:\\n${data.host_restart_command || ''}`,
      `Docker wrapper:\\n${data.docker_wrapper_restart_command || ''}`,
      `Deployment image:\\n${data.docker_deploy_restart_command || ''}`
    ].join('\\n\\n');
    cfg$('cfg-runtime').innerHTML = [
      `<span class="cfg-badge">mode=${cfgEscape(data.runtime_mode || 'unknown')}</span>`,
      `<span class="cfg-badge">config=${cfgEscape(data.config_path || '')}</span>`
    ].join('');
    const setupPath = data.setup_guide_path || 'runbooks/initial_setup.md';
    cfg$('cfg-setup-link').href = `/docs/view?path=${encodeURIComponent(setupPath)}`;
    cfg$('cfg-setup-link-inline').href = `/docs/view?path=${encodeURIComponent(setupPath)}`;
    cfgRenderEnvRefresh(data.environment_profile_refresh || {});
    cfgRenderPersonalization(data.personalization || {});
  }
  async function cfgLoad(){
    try{
      const depResp = await fetch('/api/config/dependencies');
      const depData = await depResp.json();
      if(depResp.ok){
      cfgRenderDependencies(depData);
      } else {
        cfg$('cfg-deps-note').textContent = depData.error || `dependency check failed (${depResp.status})`;
      }
    } catch(err){
      cfg$('cfg-deps-note').textContent = `dependency check failed: ${err}`;
    }
    const resp = await fetch('/api/config/runtime');
    const data = await resp.json();
    if(!resp.ok){ cfg$('cfg-status').textContent = data.error || `load failed (${resp.status})`; return; }
    cfgRender(data);
    cfg$('cfg-status').textContent = 'Loaded current configuration.';
    if(String(data.environment_profile_refresh?.state || '') === 'in_progress'){
      await cfgPollEnvRefresh();
    }
    if(String(data.personalization?.state || '') === 'in_progress'){
      await cfgPollPersonalization();
    }
    await cfgValidate();
  }
  async function cfgValidate(){
    const draft = cfgCollectPayload();
    cfg$('cfg-status').textContent = 'Validating live connections...';
    const resp = await fetch('/api/config/validate', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({values: draft})
    });
    const data = await resp.json();
    if(!resp.ok){
      cfgApplyPayload(draft);
      cfg$('cfg-status').textContent = data.error || `validation failed (${resp.status})`;
      cfg$('cfg-edge-status').textContent = data.error || `edge validation failed (${resp.status})`;
      return;
    }
    if(Array.isArray(data.ollama_available_models)){ cfgPopulateModelOptions(data.ollama_available_models); }
    cfgApplyPayload(draft);
    cfgRenderModelCompare(draft, data.ollama_available_models || [], data.expected_models || []);
    cfgRenderValidation(data);
    cfgRenderEdgeModelOptions(data.edge_ollama_available_models || []);
    cfgRenderEdgeValidation(data);
    cfg$('cfg-checks').textContent = [
      data.connectivity_checks?.ollama_tags || '',
      data.connectivity_checks?.edge_ollama_tags || '',
      data.connectivity_checks?.splunk_mcp || ''
    ].filter(Boolean).join('\\n\\n');
    cfg$('cfg-edge-checks').textContent = data.connectivity_checks?.edge_ollama_tags || 'Edge helper disabled or not configured.';
    if(data.environment_profile_status === 'in_progress'){
      cfg$('cfg-status').textContent = 'Validation complete. Data Domains initialization started.';
    } else {
      cfg$('cfg-status').textContent = 'Validation complete.';
    }
    cfg$('cfg-edge-status').textContent = 'Edge helper validation complete.';
  }
  async function cfgValidateEdge(){
    const draft = cfgCollectPayload();
    cfg$('cfg-edge-status').textContent = 'Validating edge helper...';
    const resp = await fetch('/api/config/validate', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({values: draft, scope: 'edge'})
    });
    const data = await resp.json();
    if(!resp.ok){
      cfgApplyPayload(draft);
      cfg$('cfg-edge-status').textContent = data.error || `edge validation failed (${resp.status})`;
      return;
    }
    cfgApplyPayload(draft);
    cfgRenderEdgeModelOptions(data.edge_ollama_available_models || []);
    cfgRenderEdgeValidation(data);
    cfg$('cfg-edge-checks').textContent = data.connectivity_checks?.edge_ollama_tags || 'Edge helper disabled or not configured.';
    cfg$('cfg-edge-status').textContent = 'Edge helper validation complete.';
  }
  async function cfgProbeMcp(){
    const draft = cfgCollectPayload();
    cfg$('cfg-status').textContent = 'Running live MCP probe...';
    const resp = await fetch('/api/config/mcp-probe', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({values: draft})
    });
    const data = await resp.json();
    if(!resp.ok){
      cfgApplyPayload(draft);
      cfgRenderMcpProbe({
        status: 'error',
        detail: data.error || `MCP probe failed (${resp.status})`
      });
      cfg$('cfg-status').textContent = data.error || `MCP probe failed (${resp.status})`;
      return;
    }
    cfgApplyPayload(draft);
    cfgRenderMcpProbe(data);
    cfg$('cfg-status').textContent = data.detail || 'MCP probe complete.';
  }
  async function cfgSave(mode='full'){
    const edgeOnly = mode === 'edge';
    const saveBtn = cfg$('cfg-save');
    const priorSaveLabel = saveBtn ? saveBtn.textContent : '';
    if(saveBtn){
      saveBtn.disabled = true;
      saveBtn.textContent = edgeOnly ? 'Saving Edge...' : 'Saving...';
    }
    cfg$('cfg-status').textContent = edgeOnly ? 'Saving edge helper...' : 'Saving...';
    if(edgeOnly){
      cfg$('cfg-edge-status').textContent = 'Saving edge helper...';
    }
    try {
      let payload = cfgCollectPayload();
      const validationResp = await fetch('/api/config/validate', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(edgeOnly ? {values: payload, scope: 'edge'} : {values: payload})
      });
      const validationData = await validationResp.json();
      if(!validationResp.ok){
        const detail = validationData.error || `pre-save validation failed (${validationResp.status})`;
        cfg$('cfg-status').textContent = detail;
        if(edgeOnly){
          cfg$('cfg-edge-status').textContent = detail;
        }
        return;
      }
      if(edgeOnly){
        cfgRenderEdgeModelOptions(validationData.edge_ollama_available_models || []);
        cfgRenderEdgeValidation(validationData);
        cfg$('cfg-edge-checks').textContent = validationData.connectivity_checks?.edge_ollama_tags || 'Edge helper disabled or not configured.';
      }
      payload = cfgAutoAssignDefaults(payload, validationData.ollama_available_models || []);
      const resp = await fetch('/api/config/runtime', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({values: payload})
      });
      const data = await resp.json();
      if(!resp.ok){
        const detail = data.error || `save failed (${resp.status})`;
        cfg$('cfg-status').textContent = detail;
        if(edgeOnly){
          cfg$('cfg-edge-status').textContent = detail;
        }
        return;
      }
      const savedStatus = edgeOnly ? 'Saved edge helper settings to config/ui.env.' : 'Saved to config/ui.env.';
      cfg$('cfg-status').textContent = savedStatus;
      if(edgeOnly){
        cfg$('cfg-edge-status').textContent = 'Edge helper saved to config/ui.env.';
      }
      try {
        cfgRender(data);
      } catch (renderErr) {
        console.error('cfgRender failed after save', renderErr);
        cfg$('cfg-status').textContent = `${savedStatus} UI refresh was partial; reload if fields look stale.`;
      }
      try {
        await cfgValidate();
      } catch (validateErr) {
        console.error('cfgValidate failed after save', validateErr);
        if(cfg$('cfg-status').textContent === 'Validating live connections...'){
          cfg$('cfg-status').textContent = `${savedStatus} Validation refresh failed; use Validate Current Config to retry.`;
        }
      }
    } catch (err) {
      console.error('cfgSave failed', err);
      const detail = err?.message ? `save failed: ${err.message}` : 'save failed';
      cfg$('cfg-status').textContent = detail;
      if(edgeOnly){
        cfg$('cfg-edge-status').textContent = detail;
      }
    } finally {
      if(saveBtn){
        saveBtn.disabled = false;
        saveBtn.textContent = priorSaveLabel || 'Save Configuration';
      }
    }
  }
  cfg$('cfg-save').onclick = async () => { await cfgSave('full'); };
  cfg$('cfg-personalize').onclick = async () => {
    cfg$('cfg-personalize-status').textContent = 'Starting personalization rebuild...';
    const resp = await fetch('/api/config/personalize', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({})
    });
    const data = await resp.json();
    if(!resp.ok && resp.status !== 202){
      cfg$('cfg-personalize-status').textContent = data.detail || data.error || `personalization failed (${resp.status})`;
      return;
    }
    cfgRenderPersonalization(data.personalization || {});
    cfg$('cfg-personalize-status').textContent = data.detail || 'Personalization started.';
    await cfgPollPersonalization();
  };
  cfg$('cfg-env-refresh').onclick = async () => {
    cfg$('cfg-env-refresh-status').textContent = 'Starting Data Domains refresh...';
    const resp = await fetch('/api/config/env-refresh', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({})
    });
    const data = await resp.json();
    if(!resp.ok && resp.status !== 202){
      cfg$('cfg-env-refresh-status').textContent = data.detail || data.error || `refresh failed (${resp.status})`;
      return;
    }
    cfgRenderEnvRefresh(data.refresh || {});
    cfg$('cfg-env-refresh-status').textContent = data.detail || 'Data Domains refresh started.';
    await cfgPollEnvRefresh();
  };
  if(cfg$('cfg-env-wipe-refresh')){
    cfg$('cfg-env-wipe-refresh').onclick = async () => {
      const confirmed = window.confirm('Wipe the current Data Domains profile and rebuild it from scratch for this system? This clears the existing profile artifacts before refreshing.');
      if(!confirmed) return;
      cfg$('cfg-env-refresh-status').textContent = 'Wiping current Data Domains artifacts and starting a fresh rebuild...';
      const resp = await fetch('/api/environment/wipe-refresh', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: '{}'
      });
      const data = await resp.json();
      if(!resp.ok){
        cfgRenderEnvRefresh(data.refresh || {});
        cfg$('cfg-env-refresh-status').textContent = data.detail || data.error || `wipe and refresh failed (${resp.status})`;
        return;
      }
      cfgRenderEnvRefresh(data.refresh || {});
      cfg$('cfg-env-refresh-status').textContent = data.detail || 'Wipe and refresh started.';
      await cfgPollEnvRefresh();
    };
  }
  cfg$('cfg-edge-save').onclick = async () => { await cfgSave('edge'); };
  cfg$('cfg-edge-validate').onclick = cfgValidateEdge;
  cfg$('cfg-validate').onclick = cfgValidate;
  cfg$('cfg-mcp-probe').onclick = cfgProbeMcp;
  cfg$('cfg-token-toggle').onclick = () => {
    const tokenInput = cfg$('cfg-splunk-token');
    if(cfgTokenReveal){
      cfgShowMaskedTokenEditor();
      return;
    }
    const currentValue = String(tokenInput.value || '').trim();
    if(cfgTokenMasked && currentValue === '__KEEP_EXISTING_SPLUNK_TOKEN__'){
      cfg$('cfg-token-state').textContent = 'Loading saved token into the secure read-only viewer...';
      cfgFetchRuntimeSecret()
        .then((value) => {
          cfgShowRevealedToken(value);
          cfg$('cfg-token-state').textContent = value
            ? 'Saved token revealed in a wrapped read-only view. Hide it to return to the masked editor.'
            : 'No saved token detected.';
        })
        .catch((err) => {
          cfg$('cfg-token-state').textContent = String(err && err.message ? err.message : err);
        });
      return;
    }
    cfgTokenActual = currentValue;
    cfgShowRevealedToken(currentValue);
  };
  cfg$('cfg-token-copy').onclick = async () => {
    try {
      let tokenValue = '';
      const currentValue = String(cfg$('cfg-splunk-token').value || '').trim();
      if(cfgTokenMasked && currentValue === '__KEEP_EXISTING_SPLUNK_TOKEN__'){
        tokenValue = cfgTokenFetched ? cfgTokenActual : await cfgFetchRuntimeSecret();
      } else {
        tokenValue = cfgTokenReveal ? cfgTokenActual : currentValue;
      }
      if(!tokenValue){
        cfg$('cfg-token-state').textContent = 'No token value is available to copy.';
        return;
      }
      await navigator.clipboard.writeText(tokenValue);
      cfg$('cfg-token-state').textContent = 'Token copied to clipboard.';
    } catch (err) {
      cfg$('cfg-token-state').textContent = String(err && err.message ? err.message : err);
    }
  };
  cfg$('cfg-token-clear').onclick = () => {
    cfg$('cfg-splunk-token').value = '';
    cfgTokenMasked = false;
    cfgTokenActual = '';
    cfgTokenFetched = false;
    cfgShowMaskedTokenEditor();
    cfg$('cfg-token-state').textContent = 'Token cleared in the draft form. Save Configuration to remove it from runtime.';
  };
  cfg$('cfg-splunk-token').addEventListener('input', () => {
    const tokenInput = cfg$('cfg-splunk-token');
    if(String(tokenInput.value || '').trim() !== '__KEEP_EXISTING_SPLUNK_TOKEN__'){
      cfgTokenMasked = false;
      cfgTokenActual = String(tokenInput.value || '');
      cfgTokenFetched = false;
    }
  });
  cfgLoad();
</script>
""".replace("{html.escape(APP_VERSION_LABEL)}", html.escape(APP_VERSION_LABEL))


def _users_page_body() -> str:
    return """
<div class="card">
  <style>
    .users-shell{display:grid;gap:16px;}
    .users-hero{border:1px solid #244660;border-radius:18px;background:linear-gradient(160deg,#08182a,#091726 52%,#0a1d17);padding:18px;}
    .users-hero h1{margin:0 0 8px;font-size:28px;line-height:1.05;}
    .users-hero p{margin:0;color:#a8c0d8;font-size:14px;line-height:1.65;}
    .users-tabs{display:flex;gap:10px;flex-wrap:wrap;}
    .users-tab{appearance:none;border:1px solid #315a79;border-radius:14px;padding:10px 14px;background:linear-gradient(180deg,#16324a,#102435);color:#dbeafe;font-weight:800;cursor:pointer;font-size:13px;}
    .users-tab.active{background:linear-gradient(135deg,#22c55e,#16a34a);color:#03230f;border-color:#22c55e;}
    .users-grid{display:grid;grid-template-columns:minmax(0,1fr);gap:16px;}
    .users-panel{border:1px solid #23445f;border-radius:18px;background:linear-gradient(180deg,#081525,#06111d);padding:18px;}
    .users-panel h2{margin:0 0 10px;font-size:18px;}
    .users-help{margin:0 0 12px;color:#9fb4cc;font-size:13px;line-height:1.55;}
    .users-form-grid{display:grid;grid-template-columns:1fr 180px;gap:12px;}
    .users-row{display:grid;gap:6px;}
    .users-row.wide{grid-column:1 / -1;}
    .users-row label{font-size:12px;color:#dbeafe;font-weight:800;text-transform:uppercase;letter-spacing:.08em;}
    .users-row input,.users-row select{width:100%;box-sizing:border-box;background:#040c18;color:#f8fafc;border:1px solid #33506a;border-radius:14px;padding:12px 14px;font-size:14px;outline:none;}
    .users-row input:focus,.users-row select:focus{border-color:#60a5fa;box-shadow:0 0 0 3px rgba(96,165,250,.15);}
    .users-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:14px;}
    .users-actions button{appearance:none;border:0;border-radius:14px;padding:12px 16px;background:linear-gradient(135deg,#22c55e,#16a34a);color:#03230f;font-weight:900;cursor:pointer;font-size:14px;}
    .users-actions .btn-secondary{background:linear-gradient(180deg,#16324a,#102435);color:#dbeafe;border:1px solid #315a79;}
    .users-status{color:#9fb4cc;font-size:13px;}
    .users-list{display:grid;gap:10px;}
    .users-item{border:1px solid #27415a;border-radius:12px;background:#081729;padding:12px;}
    .users-item-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:6px;}
    .users-item-name{font-weight:800;color:#f8fafc;}
    .users-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;border:1px solid #294560;background:#0b2130;color:#dbeafe;font-size:12px;font-weight:800;}
    .users-item-meta{color:#9fb4cc;font-size:12px;line-height:1.5;white-space:pre-wrap;}
    .users-item-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;}
    .users-item-btn{appearance:none;border:1px solid #315a79;border-radius:10px;padding:8px 10px;background:linear-gradient(180deg,#16324a,#102435);color:#dbeafe;font-weight:800;cursor:pointer;font-size:12px;letter-spacing:.02em;}
    .users-item-btn:hover{border-color:#60a5fa;transform:translateY(-1px);}
    .users-item-btn.danger{border-color:#6b2a2a;background:linear-gradient(180deg,#3f1518,#271013);color:#fecaca;}
    .users-section{display:none;}
    .users-section.active{display:block;}
    @media (max-width: 980px){.users-form-grid{grid-template-columns:1fr;}}
  </style>
  <div class="users-shell">
    <div class="users-hero">
      <h1>Users and Audit</h1>
      <p>These are two separate operator tasks. Use <strong>Local Users</strong> to manage access to this console. Use <strong>Operator Audit</strong> to review who launched which investigation and inspect the exact question and query trail.</p>
    </div>
    <div class="users-tabs">
      <button id="users-tab-manage" class="users-tab active" type="button">Local Users</button>
      <button id="users-tab-audit" class="users-tab" type="button">Operator Audit</button>
    </div>
    <div class="users-grid">
      <section id="users-section-manage" class="users-panel users-section active">
        <h2>Local Users</h2>
        <p class="users-help">This is local runtime user management for the web UI. It is intentionally simple and does not replace enterprise IAM.</p>
        <div id="users-list" class="users-list"><div class="users-item"><div class="users-item-meta">Loading users...</div></div></div>
        <div class="users-panel" style="margin-top:14px;padding:14px;background:#07121f;">
          <h2 style="font-size:16px;">Create or Update User</h2>
          <div class="users-form-grid">
            <div class="users-row"><label for="users-username">Username</label><input id="users-username" placeholder="analyst2" /></div>
            <div class="users-row"><label for="users-role">Role</label><select id="users-role"><option value="analyst">analyst</option><option value="ops">ops</option><option value="admin">admin</option></select></div>
            <div class="users-row wide"><label for="users-password">Password</label><input id="users-password" type="password" placeholder="Set a strong password" /></div>
          </div>
          <div class="users-actions">
            <button id="users-create">Create User</button>
            <button id="users-update" class="btn-secondary">Update User</button>
            <button id="users-delete" class="btn-secondary">Delete User</button>
            <span id="users-status" class="users-status">No changes submitted yet.</span>
          </div>
        </div>
      </section>
      <section id="users-section-audit" class="users-panel users-section">
        <h2>Operator Audit</h2>
        <p class="users-help">Review which operator launched which investigation, what question they asked, and the exact query path when you need provenance. Expand an entry to inspect the full query detail.</p>
        <div id="users-audit-path" class="users-help" style="margin-bottom:12px;">Loading audit log path...</div>
        <div id="users-audit-list" class="users-list"><div class="users-item"><div class="users-item-meta">No audit entries yet.</div></div></div>
      </section>
    </div>
  </div>
  <script>
    const users$ = (id) => document.getElementById(id);
    function usersEscape(v){ return String(v ?? ''); }
    function usersShowSection(name){
      const showManage = name !== 'audit';
      users$('users-section-manage').classList.toggle('active', showManage);
      users$('users-section-audit').classList.toggle('active', !showManage);
      users$('users-tab-manage').classList.toggle('active', showManage);
      users$('users-tab-audit').classList.toggle('active', !showManage);
    }
    function renderUsers(rows){
      const items = Array.isArray(rows) ? rows : [];
      users$('users-list').innerHTML = items.length ? items.map((user) => `
        <div class="users-item">
          <div class="users-item-head">
            <div class="users-item-name">${usersEscape(user.username || 'unknown')}</div>
            <span class="users-badge">role=${usersEscape(user.role || 'analyst')}</span>
          </div>
          <div class="users-item-meta">password=${usersEscape(user.password_kind || 'unknown')}</div>
          <div class="users-item-actions">
            <button class="users-item-btn" data-action="reset-password" data-username="${usersEscape(user.username || '')}">Reset Password</button>
            <button class="users-item-btn danger" data-action="delete-user" data-username="${usersEscape(user.username || '')}">Delete</button>
          </div>
        </div>
      `).join('') : '<div class="users-item"><div class="users-item-meta">No managed users found.</div></div>';
    }
    function renderAudit(audit){
      const recent = Array.isArray(audit?.recent) ? audit.recent : [];
      const now = Date.now();
      const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
      const recentWindow = recent.filter((item) => {
        const ts = Number(item?.ts_epoch || 0) * 1000;
        return ts > 0 && (now - ts) <= sevenDaysMs;
      });
      const grouped = new Map();
      for (const item of recentWindow) {
        const ts = Number(item?.ts_epoch || 0) * 1000;
        const dt = new Date(ts);
        const dayKey = Number.isNaN(dt.getTime()) ? 'Unknown day' : dt.toISOString().slice(0, 10);
        if (!grouped.has(dayKey)) grouped.set(dayKey, []);
        grouped.get(dayKey).push(item);
      }
      const orderedDays = Array.from(grouped.keys()).sort((a, b) => a < b ? 1 : -1);
      const currentDay = orderedDays[0] || '';
      const fmtStamp = (epoch) => {
        const dt = new Date(Number(epoch || 0) * 1000);
        if (Number.isNaN(dt.getTime())) return 'Unknown time';
        return dt.toLocaleString([], { month:'short', day:'numeric', hour:'numeric', minute:'2-digit' });
      };
      users$('users-audit-path').textContent = `Audit log: ${String(audit?.path || 'artifacts/audit/query_runs.jsonl')}`;
      users$('users-audit-list').innerHTML = orderedDays.length ? orderedDays.map((day) => {
        const entries = grouped.get(day) || [];
        const isOpen = day === currentDay ? ' open' : '';
        const dayLabel = day === currentDay ? `Today · ${day}` : day;
        return `
          <details class="users-item"${isOpen}>
            <summary class="users-item-head" style="cursor:pointer;list-style:none;">
              <div class="users-item-name">${usersEscape(dayLabel)}</div>
              <span class="users-badge">entries=${usersEscape(entries.length)}</span>
            </summary>
            ${entries.map((item) => `
              <details class="users-item" style="margin-top:10px;background:#07121f;">
                <summary class="users-item-head" style="cursor:pointer;list-style:none;">
                  <div class="users-item-name">${usersEscape(item.username || 'unknown')} -> ${usersEscape(item.selected_tool || 'n/a')}</div>
                  <span class="users-badge">${usersEscape(fmtStamp(item.ts_epoch))}</span>
                </summary>
                <div class="users-item-meta"><strong>Question:</strong> ${usersEscape(item.question || '')}</div>
                <div class="users-item-meta">${usersEscape(`pipeline=${item.pipeline || 'n/a'} | intent=${item.intent || 'n/a'} | rows=${item.rows_returned ?? 'n/a'}`)}</div>
                ${item.query ? `<div class="users-item-meta"><strong>Exact query:</strong>\n${usersEscape(item.query)}</div>` : ''}
              </details>
            `).join('')}
          </details>
        `;
      }).join('') : '<div class="users-item"><div class="users-item-meta">No audit entries captured in the last 7 days.</div></div>';
    }
    async function loadUsersPage(){
      const resp = await fetch('/api/config/users');
      const data = await resp.json();
      if(!resp.ok){
        users$('users-status').textContent = data.error || `load failed (${resp.status})`;
        return;
      }
      renderUsers(data.auth_users || []);
      try {
        const auditResp = await fetch('/api/config/audit');
        if(auditResp.ok){
          renderAudit(await auditResp.json());
        } else if (auditResp.status === 403) {
          users$('users-audit-path').textContent = 'Audit log: admin role required';
          users$('users-audit-list').innerHTML = '<div class="users-item"><div class="users-item-meta">Only admin can view the query audit trail.</div></div>';
        }
      } catch (_err) {
        users$('users-audit-list').innerHTML = '<div class="users-item"><div class="users-item-meta">Unable to load audit trail.</div></div>';
      }
    }
    async function submitUserAction(action){
      users$('users-status').textContent = 'Saving user change...';
      const resp = await fetch('/api/config/users', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({
          action,
          username: users$('users-username').value.trim(),
          role: users$('users-role').value.trim(),
          password: users$('users-password').value
        })
      });
      const data = await resp.json();
      if(!resp.ok){
        users$('users-status').textContent = data.error || `user action failed (${resp.status})`;
        return;
      }
      renderUsers(data.auth_users || []);
      users$('users-password').value = '';
      users$('users-status').textContent = `User action complete: ${action}.`;
      const auditResp = await fetch('/api/config/audit');
      if(auditResp.ok){
        renderAudit(await auditResp.json());
      } else if (auditResp.status === 403) {
        users$('users-audit-path').textContent = 'Audit log: admin role required';
      }
    }
    async function directUserAction(action, username){
      if(!username){ return; }
      if(action === 'delete-user'){
        if(!window.confirm(`Delete user "${username}"?`)){ return; }
        users$('users-status').textContent = `Deleting ${username}...`;
        const resp = await fetch('/api/config/users', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ action:'delete', username })
        });
        const data = await resp.json();
        if(!resp.ok){
          users$('users-status').textContent = data.error || `delete failed (${resp.status})`;
          return;
        }
        renderUsers(data.auth_users || []);
        users$('users-status').textContent = `Deleted user: ${username}.`;
        return;
      }
      if(action === 'reset-password'){
        const nextPassword = window.prompt(`Set a new password for "${username}" (minimum 12 characters):`, '');
        if(nextPassword === null){ return; }
        if(String(nextPassword).length < 12){
          users$('users-status').textContent = 'password must be at least 12 characters';
          return;
        }
        users$('users-status').textContent = `Resetting password for ${username}...`;
        const resp = await fetch('/api/config/users', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ action:'update', username, password: nextPassword })
        });
        const data = await resp.json();
        if(!resp.ok){
          users$('users-status').textContent = data.error || `password reset failed (${resp.status})`;
          return;
        }
        renderUsers(data.auth_users || []);
        users$('users-status').textContent = `Password reset for ${username}.`;
      }
    }
    users$('users-list').addEventListener('click', (event) => {
      const button = event.target.closest('[data-action][data-username]');
      if(!button){ return; }
      directUserAction(String(button.dataset.action || ''), String(button.dataset.username || ''));
    });
    users$('users-tab-manage').onclick = () => usersShowSection('manage');
    users$('users-tab-audit').onclick = () => usersShowSection('audit');
    users$('users-create').onclick = () => submitUserAction('create');
    users$('users-update').onclick = () => submitUserAction('update');
    users$('users-delete').onclick = () => submitUserAction('delete');
    loadUsersPage();
  </script>
</div>
"""


def _learning_page_body() -> str:
    return """
<div class="card">
  <style>
    .learning-shell{display:grid;gap:16px;padding-bottom:92px;}
    .learning-hero{border:1px solid #244660;border-radius:18px;background:linear-gradient(160deg,#08182a,#091726 52%,#0a1d17);padding:16px;}
    .learning-hero h1{margin:0 0 6px;font-size:28px;line-height:1.05;}
    .learning-hero p{margin:0;color:#a8c0d8;font-size:13px;line-height:1.6;}
    .learning-grid{display:grid;grid-template-columns:minmax(0,1fr);gap:16px;align-items:start;}
    .learning-panel{border:1px solid #23445f;border-radius:18px;background:linear-gradient(180deg,#081525,#06111d);padding:18px;}
    .learning-panel h2{margin:0 0 10px;font-size:18px;}
    .learning-help{margin:0 0 10px;color:#9fb4cc;font-size:13px;line-height:1.55;}
    .learning-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:14px;}
    .learning-actions button,.learning-actions a{appearance:none;border:0;border-radius:14px;padding:12px 16px;background:linear-gradient(135deg,#22c55e,#16a34a);color:#03230f;font-weight:900;cursor:pointer;font-size:14px;text-decoration:none;}
    .learning-actions .btn-secondary{background:linear-gradient(180deg,#16324a,#102435);color:#dbeafe;border:1px solid #315a79;}
    .learning-status{color:#9fb4cc;font-size:13px;}
    .learning-badges{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;}
    .learning-badge{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;border:1px solid #294560;background:#0b2130;color:#dbeafe;font-size:12px;font-weight:800;}
    .learning-notes{display:grid;gap:6px;color:#9fb4cc;font-size:12px;}
    .learning-why{margin-top:14px;border:1px solid #26435c;border-radius:14px;background:#071523;padding:12px 14px;}
    .learning-why-title{font-size:12px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:#7dd3fc;margin-bottom:8px;}
    .learning-why-list{display:grid;gap:8px;color:#dbeafe;font-size:13px;line-height:1.5;}
    .learning-why-list strong{color:#f8fafc;}
    .learning-topline{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:12px;}
    .learning-topline-copy{color:#9fb4cc;font-size:12px;line-height:1.45;}
    .learning-simple{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-top:14px;}
    .learning-simple-card{border:1px solid #26435c;border-radius:14px;background:#071523;padding:12px 14px;}
    .learning-simple-label{font-size:12px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:#7dd3fc;margin-bottom:6px;}
    .learning-simple-value{color:#f8fafc;font-size:16px;font-weight:900;}
    .learning-simple-copy{margin-top:4px;color:#9fb4cc;font-size:12px;line-height:1.45;}
    .learning-main-grid{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(280px,.8fr);gap:14px;align-items:start;}
    .learning-main-stack{display:grid;gap:14px;}
    .learning-side-stack{display:grid;gap:14px;}
    .learning-mini{border:1px solid #26435c;border-radius:14px;background:#071523;padding:12px 14px;}
    .learning-mini-title{font-size:12px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:#7dd3fc;margin-bottom:6px;}
    .learning-mini-copy{color:#dbeafe;font-size:13px;line-height:1.5;}
    .learning-mini-copy strong{color:#f8fafc;}
    .learning-impact{margin-top:14px;border:1px solid #26435c;border-radius:14px;background:#071523;padding:12px 14px;}
    .learning-impact-title{font-size:12px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:#7dd3fc;margin-bottom:8px;}
    .learning-impact-summary{border:1px solid #27415a;border-radius:12px;background:#081729;padding:12px 14px;color:#d6e5f3;font-size:13px;line-height:1.6;}
    .learning-impact-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:10px;}
    .learning-impact-card{border:1px solid #27415a;border-radius:12px;background:#081729;padding:10px;}
    .learning-impact-label{font-size:11px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:#8fb4cf;margin-bottom:6px;}
    .learning-impact-value{font-size:18px;font-weight:900;color:#f8fafc;}
    .learning-impact-copy{margin-top:8px;color:#9fb4cc;font-size:12px;line-height:1.5;}
    .learning-impact-history{margin-top:8px;color:#9fb4cc;font-size:12px;line-height:1.5;}
    .learning-impact-warning{margin-top:8px;color:#fecaca;font-size:12px;line-height:1.5;}
    .learning-impact-meta{margin-top:8px;color:#9fb4cc;font-size:12px;line-height:1.5;}
    .learning-impact-details{margin-top:10px;}
    .learning-change{margin-top:12px;border:1px solid #26435c;border-radius:14px;background:#071523;padding:12px 14px;}
    .learning-change-title{font-size:12px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:#7dd3fc;margin-bottom:8px;}
    .learning-change-copy{color:#d6e5f3;font-size:13px;line-height:1.55;}
    .learning-repo{margin-top:14px;border:1px solid #26435c;border-radius:14px;background:#071523;padding:12px 14px;}
    .learning-repo-title{font-size:12px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:#7dd3fc;margin-bottom:8px;}
    .learning-repo-copy{color:#9fb4cc;font-size:12px;line-height:1.5;margin-bottom:8px;}
    .learning-repo-list{display:grid;gap:8px;}
    .learning-repo-item{border:1px solid #27415a;border-radius:12px;background:#081729;padding:10px;}
    .learning-repo-item strong{color:#f8fafc;}
    .learning-list{display:grid;gap:10px;}
    .learning-item{border:1px solid #27415a;border-radius:12px;background:#081729;padding:12px;}
    .learning-item-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:6px;}
    .learning-item-name{font-weight:800;color:#f8fafc;}
    .learning-item-meta{color:#9fb4cc;font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word;}
    .learning-item-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;}
    .learning-item-btn{appearance:none;border:1px solid #315a79;border-radius:10px;padding:8px 10px;background:linear-gradient(180deg,#16324a,#102435);color:#dbeafe;font-weight:800;cursor:pointer;font-size:12px;letter-spacing:.02em;}
    .learning-item-btn:hover{border-color:#60a5fa;transform:translateY(-1px);}
    .learning-history{border:1px solid #27415a;border-radius:14px;background:#081729;padding:0;overflow:hidden;}
    .learning-history summary{list-style:none;cursor:pointer;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 16px;}
    .learning-history summary::-webkit-details-marker{display:none;}
    .learning-history-title{font-weight:800;color:#f8fafc;}
    .learning-history-copy{color:#9fb4cc;font-size:12px;line-height:1.45;}
    .learning-history-body{padding:0 16px 16px;}
    .learning-progress-wrap{margin-top:14px;border:1px solid #26435c;border-radius:12px;background:#07111f;padding:10px;}
    .learning-progress-head{display:flex;justify-content:space-between;gap:8px;align-items:center;font-size:12px;color:#c7d8eb;margin-bottom:6px;}
    .learning-progress-track{width:100%;height:10px;border-radius:999px;border:1px solid #1f2937;background:#0b2130;overflow:hidden;}
    .learning-progress-bar{width:0%;height:100%;border-radius:999px;background:linear-gradient(90deg,#22c55e,#10b981);transition:width .2s ease;}
    .learning-progress-log{margin-top:8px;max-height:200px;overflow:auto;white-space:pre-wrap;font-family:"Consolas","SFMono-Regular",Menlo,monospace;font-size:12px;line-height:1.45;color:#dbeafe;background:#030b17;border:1px solid #26435c;border-radius:10px;padding:10px;}
    .learning-progress-wrap.is-idle .learning-progress-log{display:none;}
    .learning-drawer{position:fixed;left:24px;right:24px;bottom:0;z-index:8;border:1px solid #27415a;border-bottom:0;border-radius:18px 18px 0 0;background:linear-gradient(180deg,rgba(8,21,37,.98),rgba(6,17,29,.98));box-shadow:0 -18px 36px rgba(2,6,23,.38);overflow:hidden;}
    .learning-drawer summary{list-style:none;cursor:pointer;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:12px;align-items:center;padding:10px 14px;}
    .learning-drawer summary::-webkit-details-marker{display:none;}
    .learning-drawer-head{display:flex;align-items:center;gap:8px;min-width:0;}
    .learning-drawer-title{font-weight:800;color:#f8fafc;}
    .learning-drawer-copy{color:#9fb4cc;font-size:12px;line-height:1.35;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
    .learning-drawer-controls{display:flex;align-items:center;gap:8px;min-width:0;overflow-x:auto;scrollbar-width:none;}
    .learning-drawer-controls::-webkit-scrollbar{display:none;}
    .learning-drawer-chip{display:inline-flex;align-items:center;padding:4px 10px;border-radius:999px;border:1px solid #315a79;background:#0b2030;color:#dbeafe;font-size:11px;font-weight:800;white-space:nowrap;}
    .learning-drawer-toggle{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:999px;border:1px solid #315a79;background:#0a2034;color:#dbeafe;font-size:12px;font-weight:900;transition:transform .18s ease;}
    .learning-drawer[open] .learning-drawer-toggle{transform:rotate(180deg);}
    .learning-drawer-body{display:grid;gap:14px;padding:0 14px 14px;}
    .learning-drawer-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:14px;align-items:start;}
    @media (max-width: 980px){.learning-impact-grid{grid-template-columns:repeat(2,minmax(0,1fr));}.learning-simple,.learning-main-grid,.learning-drawer-grid{grid-template-columns:1fr;}.learning-drawer{left:12px;right:12px;}}
  </style>
  <div class="learning-shell">
<div class="learning-hero">
      <h1>SPL Optimization AI Engine</h1>
      <p>Use this to find better reusable SPL for this environment. The engine drafts candidate patterns, tests them, stores what it found, and only lets approved assets influence future SPL writing.</p>
      <div class="learning-topline">
        <div class="learning-topline-copy">Start with <strong>What Changed This Run</strong>. Open the bottom drawer for repository detail, review queue, run trace, and score proof.</div>
        <div id="learning-summary" class="learning-badges"></div>
      </div>
    </div>
    <div class="learning-grid">
      <section class="learning-panel">
        <div class="learning-main-grid">
          <div class="learning-main-stack">
            <div>
              <h2>Run The Engine</h2>
              <p class="learning-help"><strong>Run Optimization Cycle</strong> uses multiple AI roles to draft candidate SPL assets, test them, and keep only what improves future SPL writing for this environment.</p>
              <div class="learning-actions">
                <button id="learning-run">Run Optimization Cycle</button>
                <a class="btn-secondary" href="/configure">Back to Configuration</a>
                <span id="learning-status" class="learning-status">Not started.</span>
              </div>
            </div>
            <div class="learning-change">
              <div class="learning-change-title">What Changed This Run</div>
              <div id="learning-change-copy" class="learning-change-copy">Run the engine to see whether it found a better reusable SPL asset, kept anything for review, or confirmed that the current baseline is already strong enough.</div>
            </div>
          </div>
          <div class="learning-side-stack">
            <div class="learning-mini">
              <div class="learning-mini-title">What This Is For</div>
              <div class="learning-mini-copy">Improve future SPL writing for <strong>this environment</strong> by creating reusable SPL assets and only activating the ones an operator approves.</div>
            </div>
            <div class="learning-mini">
              <div class="learning-mini-title">What A Run Does</div>
              <div class="learning-mini-copy">Drafts SPL assets, tests them, records what it found, and separates <strong>recorded drafts</strong> from <strong>approved active assets</strong>.</div>
            </div>
          </div>
        </div>
        <div class="learning-simple">
          <div class="learning-simple-card">
            <div class="learning-simple-label">Approved Active</div>
            <div id="learning-state-simple" class="learning-simple-value">0</div>
            <div class="learning-simple-copy">Assets influencing future SPL writing.</div>
          </div>
          <div class="learning-simple-card">
            <div class="learning-simple-label">Recorded Assets</div>
            <div id="learning-recorded-simple" class="learning-simple-value">0</div>
            <div class="learning-simple-copy">Draft SPL assets captured by the engine.</div>
          </div>
          <div class="learning-simple-card">
            <div class="learning-simple-label">Pending Review</div>
            <div id="learning-pending-simple" class="learning-simple-value">0</div>
            <div class="learning-simple-copy">Waiting for operator approval.</div>
          </div>
          <div class="learning-simple-card">
            <div class="learning-simple-label">Repository</div>
            <div id="learning-drawer-repo-state" class="learning-simple-value">Empty</div>
            <div class="learning-simple-copy">Open the drawer for assets, proof, and run trace.</div>
          </div>
        </div>
        <div class="learning-notes" style="margin-top:12px;">
          <div id="learning-repo-summary">Approved SPL assets will appear here after the first run.</div>
          <div><a class="btn-secondary" href="/spl-assets" style="margin-top:8px;display:inline-flex;">Open SPL Asset Repository</a></div>
          <details class="learning-history" style="margin-top:8px;">
            <summary>
              <div>
                <div class="learning-history-title">Show Technical Notes</div>
                <div class="learning-history-copy">Registry path, internal run detail, and additional implementation notes.</div>
              </div>
            </summary>
            <div class="learning-history-body">
              <div class="learning-notes" style="margin-top:0;">
                <div id="learning-detail">Loading SPL optimization registry...</div>
                <div id="learning-path">Registry path will appear here.</div>
              </div>
            </div>
          </details>
        </div>
      </section>
    </div>
    <details id="learning-drawer" class="learning-drawer">
      <summary>
        <div class="learning-drawer-head">
          <span class="learning-drawer-title">Optimization Drawer</span>
          <span class="learning-drawer-copy">Repository, measured proof, review queue, and run trace.</span>
        </div>
        <div class="learning-drawer-controls">
          <span class="learning-drawer-chip">Active <span id="learning-drawer-active" style="margin-left:6px;">0</span></span>
          <span class="learning-drawer-chip">Recorded <span id="learning-drawer-recorded" style="margin-left:6px;">0</span></span>
          <span class="learning-drawer-chip">Pending <span id="learning-drawer-pending" style="margin-left:6px;">0</span></span>
          <span class="learning-drawer-toggle">&#9650;</span>
        </div>
      </summary>
      <div class="learning-drawer-body">
        <div class="learning-drawer-grid">
          <section class="learning-panel" style="padding:14px;">
            <h2>Active SPL Asset Repository</h2>
            <div class="learning-repo-copy">Approved reusable SPL assets live here. These are the environment-specific patterns already influencing future SPL writing.</div>
            <div id="learning-repo-list" class="learning-repo-list"><div class="learning-repo-item">No approved SPL assets yet.</div></div>
          </section>
          <section class="learning-panel" style="padding:14px;">
            <h2>Measured Improvement</h2>
            <div id="learning-impact-summary" class="learning-impact-summary">Run the engine to see whether it found a better reusable SPL asset for this environment.</div>
            <div id="learning-impact-copy" class="learning-impact-copy">No optimization benchmark has been recorded yet. Run the engine to see whether it can produce a better reusable SPL asset for this environment.</div>
            <div id="learning-impact-meta" class="learning-impact-meta">Whether the latest improvement is active or still waiting for approval will appear here after the first run.</div>
            <div id="learning-impact-history" class="learning-impact-history">A short summary of recent optimization runs will appear here after the first run.</div>
            <div id="learning-impact-warning" class="learning-impact-warning" style="display:none;"></div>
            <details class="learning-history learning-impact-details">
              <summary>
                <div>
                  <div class="learning-history-title">Show Score Detail</div>
                  <div class="learning-history-copy">Benchmark numbers and deeper optimization metrics.</div>
                </div>
              </summary>
              <div class="learning-history-body">
                <div id="learning-impact-grid" class="learning-impact-grid">
                  <div class="learning-impact-card"><div class="learning-impact-label">Starting Point</div><div id="learning-impact-baseline" class="learning-impact-value">--</div></div>
                  <div class="learning-impact-card"><div class="learning-impact-label">Current Result</div><div id="learning-impact-latest" class="learning-impact-value">--</div></div>
                  <div class="learning-impact-card"><div class="learning-impact-label">Change</div><div id="learning-impact-delta" class="learning-impact-value">--</div></div>
                  <div class="learning-impact-card"><div class="learning-impact-label">New Assets Kept</div><div id="learning-impact-kept" class="learning-impact-value">0</div></div>
                </div>
                <div id="learning-impact-tech" class="learning-item-meta" style="margin-top:10px;">Technical detail will appear here after the first run.</div>
              </div>
            </details>
          </section>
        </div>
        <div class="learning-drawer-grid">
          <section class="learning-panel" style="padding:14px;">
            <h2>Pending Review Queue</h2>
            <p class="learning-help">These items are waiting for operator review. Approve only what makes sense for this environment.</p>
            <div id="learning-pending" class="learning-list"><div class="learning-item"><div class="learning-item-meta">No pending learning records.</div></div></div>
          </section>
          <section class="learning-panel" style="padding:14px;">
            <details class="learning-history" open>
              <summary>
                <div>
                  <div class="learning-history-title">Current Run Progress</div>
                  <div class="learning-history-copy">Expand this while the engine is running if you want to watch the live steps.</div>
                </div>
              </summary>
              <div class="learning-history-body">
                <div class="learning-progress-wrap" style="margin-top:0;">
                  <div class="learning-progress-head">
                    <span id="learning-phase">Idle</span>
                    <span id="learning-pct" class="learning-badge">0%</span>
                  </div>
                  <div class="learning-progress-track"><div id="learning-bar" class="learning-progress-bar"></div></div>
                  <pre id="learning-log" class="learning-progress-log">No optimization output yet.</pre>
                </div>
              </div>
            </details>
            <details class="learning-history" style="margin-top:14px;">
              <summary>
                <div>
                  <div class="learning-history-title">Show Approved, Rejected, and Not Applied Items</div>
                  <div class="learning-history-copy">Older items stay here for audit and review without cluttering the active queue.</div>
                </div>
                <span class="learning-badge" id="learning-history-count">history=0</span>
              </summary>
              <div class="learning-history-body">
                <div id="learning-history-list" class="learning-list"><div class="learning-item"><div class="learning-item-meta">No historical learning records yet.</div></div></div>
              </div>
            </details>
          </section>
        </div>
      </div>
    </details>
  </div>
  <script>
    const learning$ = (id) => document.getElementById(id);
    let learningRunRequestedAt = 0;
    function learningEscape(v){ return String(v ?? ''); }
    function learningFormatClock(iso){
      const text = String(iso || '').trim();
      if(!text){ return ''; }
      const dt = new Date(text);
      if(Number.isNaN(dt.getTime())){ return text; }
      return dt.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', second: '2-digit' });
    }
    function learningApiUrl(){
      return `/api/config/local-learning?_=${Date.now()}`;
    }
    function normalizeLearningDetail(text){
      return String(text || '')
        .replace(/Guarded local learning/gi, 'SPL Optimization AI Engine')
        .replace(/local learning/gi, 'optimization')
        .replace(/optimization asset generation started for ([^\\n]+)/gi, 'Starting reusable SPL asset generation for $1')
        .replace(/optimization asset writer step using writer_alt/gi, 'Alternate writer is drafting a reusable SPL pattern')
        .replace(/optimization asset writer step using writer/gi, 'Primary writer is drafting a reusable SPL pattern')
        .replace(/optimization asset judge comparing writer candidates/gi, 'Judge is comparing reusable SPL drafts')
        .replace(/optimization asset distiller tightening chosen pattern/gi, 'Distiller is refining the chosen SPL asset')
        .replace(/optimization asset generation found no usable writer output for ([^\\n]+)/gi, 'No usable SPL draft was produced for $1')
        .replace(/optimization asset generation produced no reusable asset for ([^\\n]+)/gi, 'No reusable SPL asset was produced for $1')
        .replace(/optimization asset ready for ([^\\n]+)/gi, 'Reusable SPL asset ready for $1')
        .replace(/Accepted deterministic candidate for ([^\\n]+)/gi, 'Captured an environment-backed improvement for $1')
        .replace(/Accepted candidate for ([^\\n]+)/gi, 'Accepted a proposed improvement for $1');
    }
    function learningCompletedStatus(runClock, runDurationSec, detail){
      const prefix = 'Optimization cycle finished at ' + String(runClock || '');
      const duration = runDurationSec > 0 ? (' in ' + runDurationSec.toFixed(2) + 's') : '';
      const suffix = detail ? (' ' + normalizeLearningDetail(detail).trim()) : '';
      return (prefix + duration + '.' + suffix).trim();
    }
    function ensureLearningPoll(){
      if(learningPoll){ return; }
      learningPoll = window.setInterval(pollLearningPage, 1500);
    }
    function stopLearningPoll(){
      if(!learningPoll){ return; }
      window.clearInterval(learningPoll);
      learningPoll = null;
    }
    function learningPhaseLabel(state, phase){
      const st = String(state || '').trim();
      const ph = String(phase || '').trim();
      if(st === 'in_progress'){
        if(ph === 'starting'){ return 'Preparing optimization cycle'; }
        if(ph === 'collecting_evidence'){ return 'Collecting environment evidence'; }
        if(ph === 'reviewing_bundle'){ return 'Generating and reviewing assets'; }
        if(ph === 'candidate_accepted'){ return 'Accepted candidate'; }
        if(ph === 'benchmarking_factory'){ return 'Benchmarking factory baseline'; }
        if(ph === 'benchmarking_baseline'){ return 'Benchmarking approved optimization state'; }
        if(ph === 'benchmarking_candidates'){ return 'Benchmarking candidate assets'; }
        if(ph === 'writing_registry'){ return 'Writing optimization registry'; }
      }
      if(st === 'ready'){ return 'Ready to run'; }
      if(st === 'error' && ph === 'interrupted'){ return 'Previous run interrupted'; }
      if(st === 'error'){ return 'Run needs attention'; }
      return 'Idle';
    }
    function renderLearningPage(payload){
      const data = payload || {};
      const counts = data.counts || {};
      const latest = Array.isArray(data.latest) ? data.latest : [];
      const pending = latest.filter((item) => String(item?.status || '') === 'pending');
      const recordHistory = latest.filter((item) => String(item?.status || '') !== 'pending');
      const state = String(data.state || 'ready');
      const pct = Math.max(0, Math.min(100, Number(data.progress_pct || 0)));
      const runBtn = learning$('learning-run');
      const improvement = (data.improvement && typeof data.improvement === 'object') ? data.improvement : {};
      const comparison = (improvement.comparison && typeof improvement.comparison === 'object') ? improvement.comparison : {};
      const overallLevel = (improvement.overall_learning_level && typeof improvement.overall_learning_level === 'object') ? improvement.overall_learning_level : {};
      const selectedCandidates = Array.isArray(improvement.selected_candidates) ? improvement.selected_candidates : [];
      const runHistory = Array.isArray(improvement.history) ? improvement.history : [];
      const bestRun = (improvement.best_run && typeof improvement.best_run === 'object') ? improvement.best_run : {};
      const approvedState = (improvement.approved_learning_state && typeof improvement.approved_learning_state === 'object') ? improvement.approved_learning_state : {};
      const cacheMetrics = (improvement.cache_metrics && typeof improvement.cache_metrics === 'object') ? improvement.cache_metrics : {};
      const candidateFiltering = (improvement.candidate_filtering && typeof improvement.candidate_filtering === 'object') ? improvement.candidate_filtering : {};
      const timeoutWarnings = Number(data.timeout_warnings ?? improvement.timeout_warnings ?? 0);
      const runDurationSec = Number(improvement.run_duration_sec ?? 0);
      const runTimestamp = String(improvement.timestamp_utc || '').trim();
      learning$('learning-summary').innerHTML = [
        `Pending ${Number(counts.pending || 0)}`,
        `Approved ${Number(counts.approved || 0)}`,
        `Rejected ${Number(counts.rejected || 0)}`,
        `Not Applied ${Number(counts.stale || 0)}`
      ].map((v) => `<span class="learning-badge">${learningEscape(v)}</span>`).join('');
      learning$('learning-detail').textContent =
        (data.detail && String(data.detail).trim())
          ? normalizeLearningDetail(String(data.detail).trim())
          : 'No optimization cycle is active. Start one when you want A.G.E.N.T. Smith to search for better reusable SPL for this environment.';
      const repositoryPath = String(data.repository_path || '').trim();
      learning$('learning-path').textContent = data.path
        ? `Registry path: ${data.path}${repositoryPath ? ` | SPL asset repository: ${repositoryPath}` : ''}`
        : 'Registry path will appear here.';
      learning$('learning-phase').textContent = learningPhaseLabel(state, data.phase || 'idle');
      learning$('learning-pct').textContent = state === 'ready' ? 'Ready' : `${Math.round(pct)}%`;
      learning$('learning-bar').style.width = `${pct}%`;
      learning$('learning-log').textContent = normalizeLearningDetail(data.output || 'No optimization output yet.');
      learning$('learning-log').parentElement.classList.toggle('is-idle', state === 'ready' && !String(data.output || '').trim());
      const baselineScore = Number(comparison.baseline_avg_score ?? improvement.baseline?.avg_score ?? 0);
      const latestScore = Number(comparison.current_avg_score ?? improvement.latest?.avg_score ?? 0);
      const avgDelta = Number(comparison.avg_score_delta ?? 0);
      const overallDelta = Number(overallLevel.avg_score_delta ?? 0);
      const factoryBaselineScore = Number(overallLevel.baseline_avg_score ?? improvement.factory_baseline?.avg_score ?? 0);
      const selectedCountRaw = data.selected ?? improvement.selected_candidate_count ?? selectedCandidates.length ?? 0;
      const selectedCount = Number(selectedCountRaw || 0);
      const bestScore = Number(bestRun.current_avg_score ?? 0);
      learning$('learning-impact-baseline').textContent = improvement.baseline ? baselineScore.toFixed(2) : '--';
      learning$('learning-impact-latest').textContent = improvement.latest ? latestScore.toFixed(2) : '--';
      learning$('learning-impact-delta').textContent = improvement.comparison ? `${avgDelta >= 0 ? '+' : ''}${avgDelta.toFixed(2)}` : '--';
      learning$('learning-impact-kept').textContent = String(selectedCount);
      const changedCases = Array.isArray(comparison.changed_cases) ? comparison.changed_cases : [];
      const impactSummaryEl = learning$('learning-impact-summary');
      if(improvement.baseline && improvement.latest){
        let summary = '';
        let copy = '';
        if(selectedCount > 0 && avgDelta > 0){
          summary = `Improvement found. ${selectedCount} reusable SPL asset(s) beat the current baseline and were kept for review.`;
          copy = `The benchmark moved from ${baselineScore.toFixed(2)} to ${latestScore.toFixed(2)}. These assets will only influence future SPL writing after approval.`;
        } else if(selectedCount > 0){
          summary = `${selectedCount} reusable SPL asset(s) were kept for review, but the measured benchmark score stayed the same.`;
          copy = `The engine found reusable drafts worth reviewing, but they did not improve the benchmark beyond the current approved baseline.`;
        } else {
          summary = 'No improvement found this run.';
          copy = `The generated drafts did not beat the current approved baseline, so nothing new was kept.`;
        }
        if(impactSummaryEl){ impactSummaryEl.textContent = summary; }
        learning$('learning-impact-copy').textContent = copy;
      } else {
        if(impactSummaryEl){ impactSummaryEl.textContent = 'No benchmarked optimization result has been recorded yet.'; }
        learning$('learning-impact-copy').textContent = 'Run the engine to see whether it can produce a better reusable SPL asset for this environment.';
      }
      const changeCopyEl = learning$('learning-change-copy');
      const approvedCount = Number(approvedState.approved_count ?? counts.approved ?? 0);
      const historyRows = Array.isArray(((data.repository && data.repository.history_rows) || (improvement.repository && improvement.repository.history_rows))) ? (((data.repository && data.repository.history_rows) || (improvement.repository && improvement.repository.history_rows))) : [];
      const pendingDraftCount = historyRows.filter((row) => { const st = String(row?.status || "").toLowerCase(); return st && st !== "approved" && st !== "rejected" && st !== "stale"; }).length;
      const pendingCount = Math.max(Number(counts.pending || 0), pendingDraftCount);
      const cacheHits = Number(cacheMetrics.hits ?? 0);
      const cacheMisses = Number(cacheMetrics.misses ?? 0);
      const skippedDuplicates = Number(candidateFiltering.skipped_duplicate_count ?? 0);
      const skippedApproved = Number(candidateFiltering.skipped_already_approved_count ?? 0);
      const skippedNonWriter = Number(candidateFiltering.skipped_non_writer_count ?? 0);
      const skippedNoGain = Number(candidateFiltering.skipped_no_gain_count ?? 0);
      const repository = (data.repository && typeof data.repository === 'object') ? data.repository : ((improvement.repository && typeof improvement.repository === 'object') ? improvement.repository : {});
      const activeAssets = Number(repository.active_assets ?? 0);
      const historyAssets = Number(repository.history_assets ?? 0);
      const repoAssets = Array.isArray(repository.records) ? repository.records : [];
      let meta = `Approved active: ${activeAssets}. Recorded assets: ${historyAssets}. Pending review: ${pendingCount}.`; 
      const runMode = String(improvement.run_mode || '');
      const deterministicOnlyMode = runMode ? (runMode === 'fast_optimization_check') : (!timeoutWarnings && skippedNoGain >= 1 && cacheMisses <= 4);
      meta += deterministicOnlyMode
        ? ' This run used the fast optimization check path.'
        : ' This run used the full AI optimization cycle.';
      if(approvedState.active){
        const activeIntents = Array.isArray(approvedState.intents) ? approvedState.intents.slice(0, 4) : [];
        if(activeIntents.length){
          meta += ` Active areas: ${activeIntents.join(', ')}.`;
        }
      } else if(activeAssets <= 0) {
        meta += ' No approved optimization assets are active yet.';
      }
      if(selectedCount > 0){
        meta += ` ${selectedCount} kept asset(s) are waiting for approval before they become active.`;
      }
      meta += ` Repository size: ${activeAssets} active, ${historyAssets} total asset records.`;
      learning$('learning-impact-meta').textContent = meta;
      let tech = `Run mode: ${deterministicOnlyMode ? 'Fast optimization check' : 'Full AI optimization cycle'}. Repository size: ${activeAssets} active / ${historyAssets} total.`;
      if(cacheHits || cacheMisses){ tech += ` Cache reuse: ${cacheHits} hit(s), ${cacheMisses} miss(es).`; }
      if(skippedDuplicates || skippedApproved || skippedNonWriter || skippedNoGain){ tech += ` Skipped candidates - duplicate: ${skippedDuplicates}, already approved: ${skippedApproved}, non-writer: ${skippedNonWriter}, no gain: ${skippedNoGain}.`; }
      learning$('learning-impact-tech').textContent = tech;
      const repoSummaryEl = learning$('learning-repo-summary');
      if(repoSummaryEl){
        repoSummaryEl.textContent = activeAssets > 0
          ? `Approved SPL asset repository: ${activeAssets} active asset(s) ready to influence future SPL writing.`
          : 'Approved SPL asset repository: no active SPL assets yet.';
      }
      const stateSimpleEl = learning$('learning-state-simple');
      if(stateSimpleEl){
        stateSimpleEl.textContent = String(activeAssets);
      }
      const recordedSimpleEl = learning$('learning-recorded-simple');
      if(recordedSimpleEl){
        recordedSimpleEl.textContent = String(historyAssets);
      }
      const pendingSimpleEl = learning$('learning-pending-simple');
      if(pendingSimpleEl){
        pendingSimpleEl.textContent = String(pendingCount);
      }
      const drawerActiveEl = learning$('learning-drawer-active');
      if(drawerActiveEl){
        drawerActiveEl.textContent = String(activeAssets);
      }
      const drawerRecordedEl = learning$('learning-drawer-recorded');
      if(drawerRecordedEl){
        drawerRecordedEl.textContent = String(historyAssets);
      }
      const drawerPendingEl = learning$('learning-drawer-pending');
      if(drawerPendingEl){
        drawerPendingEl.textContent = String(pendingCount);
      }
      const drawerRepoStateEl = learning$('learning-drawer-repo-state');
      if(drawerRepoStateEl){
        drawerRepoStateEl.textContent = activeAssets > 0 ? 'Active' : (historyAssets > 0 ? 'Recorded' : 'Empty');
      }
      if(changeCopyEl){
        if(selectedCount > 0 && avgDelta > 0){
          changeCopyEl.textContent = `This run found ${selectedCount} better reusable SPL asset(s). They are kept for review and will only become active after approval.`;
        } else if(selectedCount > 0){
          changeCopyEl.textContent = `This run kept ${selectedCount} reusable SPL asset(s) for review, but the measured benchmark score did not move.`;
        } else if(improvement.baseline && improvement.latest){
          changeCopyEl.textContent = `This run did not find a better reusable SPL asset than the current approved baseline, so nothing new was kept.`;
        } else {
          changeCopyEl.textContent = 'Run the engine to see whether it found a better reusable SPL asset, kept anything for review, or confirmed that the current baseline is already strong enough.';
        }
      }
      const repoListEl = learning$('learning-repo-list');
      if(repoListEl){
        const splAssets = Array.isArray(repoAssets) ? repoAssets : [];
        repoListEl.innerHTML = splAssets.length ? splAssets.slice(0, 6).map((row) => {
          const proposal = (row.proposal && typeof row.proposal === 'object') ? row.proposal : {};
          const useWhen = String(proposal.use_when || '').trim();
          const template = String(proposal.query_template || '').trim();
          return `
            <div class="learning-repo-item">
              <div><strong>${learningEscape(row.intent || 'unknown_intent')}</strong> <span class="learning-badge">ACTIVE</span></div>
              ${useWhen ? `<div class="learning-item-meta"><strong>Use when:</strong> ${learningEscape(useWhen)}</div>` : ''}
              ${template ? `<div class="learning-item-meta"><strong>Pattern:</strong> ${learningEscape(template)}</div>` : ''}
            </div>
          `;
        }).join('') : '<div class="learning-repo-item">No approved SPL assets yet.</div>';
      }
      if(runHistory.length){
        const recent = runHistory.slice(-3).map((row) => {
          const score = Number(row.current_avg_score ?? 0).toFixed(2);
          const delta = Number(row.avg_score_delta ?? 0);
          const dur = Number(row.run_duration_sec ?? 0);
          return `${score} (${delta >= 0 ? '+' : ''}${delta.toFixed(2)}, ${dur.toFixed(2)}s)`;
        });
        let historyText = `Recent score history: ${recent.join(' -> ')}. Best verified result: ${bestScore.toFixed(2)}.`;
        if(runHistory.length){
          const latestRun = runHistory[runHistory.length - 1] || {};
          const learnedDelta = Number(latestRun.factory_to_current_avg_delta ?? overallDelta ?? 0);
          historyText += ` Overall improvement versus the original baseline: ${learnedDelta >= 0 ? '+' : ''}${learnedDelta.toFixed(2)}.`;
        }
        if(runDurationSec > 0){
          historyText += ` Last run duration: ${runDurationSec.toFixed(2)}s.`;
        }
        learning$('learning-impact-history').textContent = historyText;
      } else {
        learning$('learning-impact-history').textContent = 'Run history will appear here after the first completed benchmarked optimization cycle.';
      }
      const warningEl = learning$('learning-impact-warning');
      if(timeoutWarnings > 0){
        warningEl.style.display = '';
        warningEl.textContent = `Optimization slowed because one or more remote model calls timed out. ${timeoutWarnings} fallback or skip event(s) were recorded.`;
      } else {
        warningEl.style.display = 'none';
        warningEl.textContent = '';
      }
      if(runBtn){
        runBtn.disabled = state === 'in_progress';
        runBtn.textContent = state === 'in_progress' ? 'Optimization Running...' : 'Run Optimization Cycle';
      }
      learning$('learning-history-count').textContent = `history=${recordHistory.length}`;
      const renderProposalSummary = (item) => {
        const kind = String(item.kind || '').trim();
        const proposal = (item.proposal && typeof item.proposal === 'object') ? item.proposal : {};
        if(kind === 'spl_pattern_asset'){
          const fields = Array.isArray(proposal.required_fields) ? proposal.required_fields.join(', ') : '';
          const template = String(proposal.query_template || '').trim();
          const useWhen = String(proposal.use_when || '').trim();
          return `
            <div class="learning-item-meta"><strong>Asset summary:</strong> Reusable SPL pattern for <code>${learningEscape(item.intent || 'unknown_intent')}</code>.</div>
            ${useWhen ? `<div class="learning-item-meta"><strong>Use when:</strong> ${learningEscape(useWhen)}</div>` : ''}
            ${fields ? `<div class="learning-item-meta"><strong>Required fields:</strong> ${learningEscape(fields)}</div>` : ''}
            ${template ? `<div class="learning-item-meta"><strong>Pattern:</strong> ${learningEscape(template)}</div>` : ''}
          `;
        }
        if(kind === 'preferred_sources'){
          const sources = Array.isArray(proposal.preferred_sources) ? proposal.preferred_sources.join(', ') : '';
          const sourcetypes = Array.isArray(proposal.preferred_sourcetypes) ? proposal.preferred_sourcetypes.join(', ') : '';
          return `
            ${sources ? `<div class=\"learning-item-meta\"><strong>Prefer sources:</strong> ${learningEscape(sources)}</div>` : ''}
            ${sourcetypes ? `<div class=\"learning-item-meta\"><strong>Prefer sourcetypes:</strong> ${learningEscape(sourcetypes)}</div>` : ''}
          `;
        }
        if(kind === 'preferred_fields'){
          const fields = Array.isArray(proposal.preferred_fields) ? proposal.preferred_fields.join(', ') : '';
          return `<div class=\"learning-item-meta\"><strong>Prefer fields:</strong> ${learningEscape(fields)}</div>`;
        }
        if(kind === 'post_result_pivot_hint'){
          return `<div class=\"learning-item-meta\"><strong>Follow-up idea:</strong> ${learningEscape(proposal.cross_platform_pivot_hint || '')}</div>`;
        }
        return `<div class="learning-item-meta"><strong>Proposed local hint:</strong> ${learningEscape(JSON.stringify(proposal || {}))}</div>`;
      };
      const renderItem = (item) => `
        <div class="learning-item">
          <div class="learning-item-head">
            <div class="learning-item-name">${learningEscape(item.intent || 'unknown_intent')}</div>
            <span class="learning-badge">${learningEscape(String(item.status || 'pending').toLowerCase() === 'stale' ? 'NOT APPLIED' : String(item.status || 'pending').toUpperCase())}</span>
          </div>
          <div class="learning-item-meta"><strong>Suggestion type:</strong> ${learningEscape(item.kind || 'unknown')}</div>
          ${renderProposalSummary(item)}
          <div class="learning-item-meta"><strong>Why it was suggested:</strong> ${learningEscape(item.reason || '')}</div>
          ${item.supporting_question ? `<div class="learning-item-meta"><strong>Supporting question:</strong> ${learningEscape(item.supporting_question)}</div>` : ''}
          <div class="learning-item-meta"><strong>Created:</strong> ${learningEscape(item.created_at || '')}</div>
          ${String(item.status || '') === 'pending' ? `<div class="learning-item-actions"><button class="learning-item-btn" data-action="approve" data-id="${learningEscape(item.id || '')}">Approve</button><button class="learning-item-btn" data-action="reject" data-id="${learningEscape(item.id || '')}">Reject</button></div>` : ''}
        </div>
      `;
      learning$('learning-pending').innerHTML = pending.length ? pending.map(renderItem).join('') : '<div class="learning-item"><div class="learning-item-meta">No pending learning records.</div></div>';
      learning$('learning-history-list').innerHTML = recordHistory.length ? recordHistory.map(renderItem).join('') : '<div class="learning-item"><div class="learning-item-meta">No historical learning records yet.</div></div>';
      document.querySelectorAll('[data-action][data-id]').forEach((btn) => {
        btn.onclick = async () => {
          const action = String(btn.getAttribute('data-action') || '').trim();
          const id = String(btn.getAttribute('data-id') || '').trim();
          learning$('learning-status').textContent = `${action} ${id}...`;
          const resp = await fetch('/api/config/local-learning', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body: JSON.stringify({action, id})
          });
          const data = await resp.json();
          if(!resp.ok){
            learning$('learning-status').textContent = data.error || `local learning update failed (${resp.status})`;
            return;
          }
          renderLearningPage(data.local_learning || {});
          learning$('learning-status').textContent = data.detail || `record ${action}d`;
        };
      });
    }
    async function loadLearningPage(){
      const resp = await fetch(learningApiUrl(), { cache:'no-store' });
      const data = await resp.json();
      if(!resp.ok){
        learning$('learning-status').textContent = data.error || `load failed (${resp.status})`;
        return;
      }
      renderLearningPage(data.local_learning || {});
      const state = String(data.local_learning?.state || 'ready');
      const improvement = (data.local_learning?.improvement && typeof data.local_learning.improvement === 'object') ? data.local_learning.improvement : {};
      const runDurationSec = Number(improvement.run_duration_sec ?? 0);
      const runClock = learningFormatClock(improvement.timestamp_utc || '');
      if(state === 'in_progress'){
        learning$('learning-status').textContent = normalizeLearningDetail(data.local_learning?.detail || 'SPL Optimization AI Engine is running...');
        ensureLearningPoll();
      } else if(state === 'ready'){
        if(learningRunRequestedAt && runClock){
          learning$('learning-status').textContent = learningCompletedStatus(runClock, runDurationSec, data.local_learning?.detail || '');
          learningRunRequestedAt = 0;
        } else {
          learning$('learning-status').textContent = normalizeLearningDetail(data.local_learning?.detail || 'SPL Optimization AI Engine complete.');
        }
        stopLearningPoll();
      } else if(state === 'error'){
        learning$('learning-status').textContent = normalizeLearningDetail(data.local_learning?.detail || 'SPL Optimization AI Engine failed.');
        stopLearningPoll();
      } else {
        learning$('learning-status').textContent = 'Loaded SPL optimization registry.';
      }
    }
    let learningPoll = null;
    async function pollLearningPage(){
      const resp = await fetch(learningApiUrl(), { cache:'no-store' });
      const data = await resp.json();
      if(!resp.ok){
        learning$('learning-status').textContent = data.error || `load failed (${resp.status})`;
        stopLearningPoll();
        return;
      }
      renderLearningPage(data.local_learning || {});
      const state = String(data.local_learning?.state || 'ready');
      const improvement = (data.local_learning?.improvement && typeof data.local_learning.improvement === 'object') ? data.local_learning.improvement : {};
      const runDurationSec = Number(improvement.run_duration_sec ?? 0);
      const runClock = learningFormatClock(improvement.timestamp_utc || '');
      if(state === 'in_progress'){
        learning$('learning-status').textContent = normalizeLearningDetail(data.local_learning?.detail || 'SPL Optimization AI Engine is running...');
        ensureLearningPoll();
        return;
      }
      stopLearningPoll();
      if(state === 'ready'){
        if(learningRunRequestedAt && runClock){
          learning$('learning-status').textContent = learningCompletedStatus(runClock, runDurationSec, data.local_learning?.detail || '');
          learningRunRequestedAt = 0;
        } else {
          learning$('learning-status').textContent = normalizeLearningDetail(data.local_learning?.detail || 'SPL Optimization AI Engine complete.');
        }
      } else if(state === 'error'){
        learning$('learning-status').textContent = normalizeLearningDetail(data.local_learning?.detail || 'SPL Optimization AI Engine failed.');
        learningRunRequestedAt = 0;
      }
    }
    learning$('learning-run').onclick = async () => {
      learningRunRequestedAt = Date.now();
      learning$('learning-run').disabled = true;
      learning$('learning-run').textContent = 'Optimization Running...';
      learning$('learning-status').textContent = 'Starting SPL Optimization AI Engine...';
      learning$('learning-phase').textContent = 'Preparing optimization cycle';
      learning$('learning-pct').textContent = '5%';
      learning$('learning-bar').style.width = '5%';
      const resp = await fetch('/api/config/local-learning', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({action:'self_learn'})
      });
      const data = await resp.json();
      if(!resp.ok){
        learning$('learning-run').disabled = false;
        learning$('learning-run').textContent = 'Run Optimization Cycle';
        learning$('learning-status').textContent = normalizeLearningDetail(data.error || `optimization failed (${resp.status})`);
        return;
      }
      renderLearningPage(data.local_learning || {});
      learning$('learning-status').textContent = normalizeLearningDetail(data.detail || 'SPL Optimization AI Engine started.');
      ensureLearningPoll();
      await pollLearningPage();
    };
    document.addEventListener('visibilitychange', () => {
      if(document.visibilityState === 'visible'){
        loadLearningPage();
      }
    });
    loadLearningPage();
  </script>
</div>
"""


def _spl_asset_repository_page_body() -> str:
    summary = learning_registry_summary()
    repository = summary.get("repository", {}) if isinstance(summary, dict) else {}
    active_rows = repository.get("records", []) if isinstance(repository, dict) else []
    active_rows = active_rows if isinstance(active_rows, list) else []
    history_rows = []
    try:
        raw_repo = _load_json_if_exists(Path(summary.get("repository_path", ""))) if summary.get("repository_path") else None
        if isinstance(raw_repo, dict):
            history_rows = raw_repo.get("history_assets", []) if isinstance(raw_repo.get("history_assets", []), list) else []
    except Exception:
        history_rows = []
    active_rows = [row for row in active_rows if isinstance(row, dict)]
    history_rows = [row for row in history_rows if isinstance(row, dict)]
    draft_rows = [row for row in history_rows if str(row.get("status", "")).strip().lower() != "approved"]

    def _fit_summary(row: dict[str, Any]) -> str:
        fields = [str(item).strip() for item in row.get("required_fields", []) if str(item).strip()]
        sources = [str(item).strip() for item in row.get("required_sources", []) if str(item).strip()]
        sourcetypes = [str(item).strip() for item in row.get("required_sourcetypes", []) if str(item).strip()]
        parts: list[str] = []
        if fields:
            parts.append(f"fields: {', '.join(fields[:3])}{'…' if len(fields) > 3 else ''}")
        if sources:
            parts.append(f"sources: {', '.join(sources[:2])}{'…' if len(sources) > 2 else ''}")
        if sourcetypes:
            parts.append(f"sourcetypes: {', '.join(sourcetypes[:2])}{'…' if len(sourcetypes) > 2 else ''}")
        return html.escape(" | ".join(parts) if parts else "Environment fit not recorded")

    def _question_family(row: dict[str, Any]) -> str:
        tokens = [str(item).strip() for item in row.get("match_tokens", []) if str(item).strip()]
        return html.escape(", ".join(tokens[:5]) if tokens else "General reusable pattern")

    def _benchmark_summary(row: dict[str, Any]) -> str:
        impact = row.get("benchmark_impact", {}) if isinstance(row.get("benchmark_impact"), dict) else {}
        avg_delta = impact.get("avg_score_delta")
        pass_delta = impact.get("pass_rate_delta_pct")
        parts: list[str] = []
        if isinstance(avg_delta, (int, float)):
            parts.append(f"writer score {avg_delta:+.2f}")
        if isinstance(pass_delta, (int, float)):
            parts.append(f"pass rate {pass_delta:+.2f}%")
        return html.escape(" | ".join(parts) if parts else "No benchmark lift recorded yet; kept for local review and provenance")

    def _asset_row(row: dict[str, Any], state_label: str, actions: bool = False) -> str:
        intent = html.escape(str(row.get("intent", "")).strip() or "unknown_intent")
        use_when = html.escape(str(row.get("use_when", "")).strip() or "No use case recorded")
        why = html.escape(str(row.get("why", "")).strip() or str(row.get("reason", "")).strip() or "No rationale recorded")
        query_template = html.escape(str(row.get("query_template", "")).strip() or "No SPL pattern recorded")
        row_id = html.escape(str(row.get("id", "")).strip())
        updated_at = html.escape(str(row.get("updated_at", "")).strip() or str(row.get("created_at", "")).strip() or "Unknown")
        selection_reason = html.escape(str(row.get("selection_reason", "")).strip().replace("_", " ") or "Awaiting review")
        action_html = '<span class="splrepo-row-actions-empty">Active</span>'
        if actions and row_id:
            action_html = (
                f'<div class="splrepo-row-actions">'
                f'<button class="learning-item-btn splrepo-action-approve" data-repo-action="approve" data-id="{row_id}">Approve</button>'
                f'<button class="learning-item-btn splrepo-action-reject" data-repo-action="reject" data-id="{row_id}">Reject</button>'
                f'</div>'
            )
        return f"""
        <tr>
          <td>
            <div class="splrepo-cell-title">{intent}</div>
            <div class="splrepo-cell-sub">{use_when}</div>
          </td>
          <td><span class="learning-badge">{html.escape(state_label)}</span></td>
          <td>{_question_family(row)}</td>
          <td>{why}</td>
          <td>{_fit_summary(row)}</td>
          <td>
            <div class="splrepo-pattern">{query_template}</div>
            {'<div class="splrepo-cell-sub">Why not active yet: ' + selection_reason + '</div>' if actions else ''}
          </td>
          <td>
            <div class="splrepo-cell-sub">{_benchmark_summary(row)}</div>
            <div class="splrepo-cell-sub" style="margin-top:6px;">{updated_at}</div>
          </td>
          <td>{action_html}</td>
        </tr>
        """

    recent_history = sorted(draft_rows, key=lambda row: str(row.get("updated_at", "") or row.get("created_at", "")), reverse=True)[:8]
    active_table_rows = "".join(_asset_row(row, "ACTIVE") for row in active_rows)
    draft_table_rows = "".join(_asset_row(row, str(row.get("status", "")).strip().upper() or "RECORDED", actions=True) for row in recent_history)
    repo_path = html.escape(str(summary.get("repository_path", "")).strip() or "Not created yet")
    active_count = len(active_rows)
    history_count = len(draft_rows)
    spotlight = active_rows[0] if active_rows else None
    spotlight_intent = html.escape(str((spotlight or {}).get("intent", "")).strip() or "No active asset yet")
    spotlight_when = html.escape(str((spotlight or {}).get("use_when", "")).strip())
    spotlight_pattern = html.escape(str((spotlight or {}).get("query_template", "")).strip())
    spotlight_why = html.escape(str((spotlight or {}).get("why", "")).strip() or str((spotlight or {}).get("reason", "")).strip())
    review_message = (
        "Nothing is waiting for approval right now."
        if history_count <= 0
        else f"{history_count} recorded draft(s) are ready for review. Approve only the ones you want influencing future SPL writing."
    )
    return f"""
<div class="card">
  <style>
    .splrepo-shell{{display:grid;gap:16px;}}
    .splrepo-hero{{border:1px solid #27415a;border-radius:18px;background:linear-gradient(165deg,#0a1729,#07131f 56%,#0a1a17);padding:18px;}}
    .splrepo-hero h1{{margin:0 0 8px;font-size:32px;line-height:1.05;}}
    .splrepo-copy{{color:#9fb4cc;font-size:13px;line-height:1.6;}}
    .splrepo-metrics{{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px;}}
    .splrepo-metric{{border:1px solid #315a79;border-radius:999px;padding:6px 10px;background:#0b2030;color:#d6e5f3;font-size:12px;font-weight:800;}}
    .splrepo-guide-title{{font-size:12px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:#7dd3fc;margin-bottom:6px;}}
    .splrepo-guide-copy{{color:#dbeafe;font-size:13px;line-height:1.55;}}
    .splrepo-grid{{display:grid;grid-template-columns:minmax(360px,408px) minmax(0,1fr);gap:24px;align-items:start;}}
    .splrepo-main{{display:grid;gap:16px;order:2;min-width:0;}}
    .splrepo-main > *{{min-width:0;}}
    .splrepo-side{{display:grid;gap:16px;order:1;position:sticky;top:88px;align-self:start;min-width:0;}}
    .splrepo-panel{{border:1px solid #27415a;border-radius:16px;background:#081729;padding:14px;box-sizing:border-box;min-width:0;width:100%;}}
    .splrepo-panel h2{{margin:0 0 8px;font-size:20px;}}
    .splrepo-list{{display:grid;gap:10px;}}
    .splrepo-spotlight{{border:1px solid #26614d;border-radius:16px;background:linear-gradient(160deg,#08182a,#09211c);padding:14px;}}
    .splrepo-spotlight-head{{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:8px;}}
    .splrepo-spotlight-title{{font-size:12px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:#86efac;}}
    .splrepo-spotlight-name{{font-size:20px;font-weight:900;color:#f8fafc;}}
    .splrepo-spotlight-copy{{color:#cfe4da;font-size:13px;line-height:1.55;}}
    .splrepo-queue-stat{{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 14px;border:1px solid #315a79;border-radius:14px;background:#071523;}}
    .splrepo-queue-count{{font-size:24px;font-weight:900;color:#f8fafc;}}
    .splrepo-status-list{{display:grid;gap:8px;margin-top:10px;}}
    .splrepo-status-item{{border:1px solid #27415a;border-radius:12px;background:#071523;padding:10px 12px;color:#dbeafe;font-size:13px;line-height:1.5;}}
    .splrepo-section-head{{display:flex;align-items:flex-end;justify-content:space-between;gap:12px;margin-bottom:10px;flex-wrap:wrap;}}
    .splrepo-section-note{{color:#9fb4cc;font-size:12px;line-height:1.45;}}
    .splrepo-compare{{border:1px solid #27415a;border-radius:16px;background:#081729;padding:14px;}}
    .splrepo-compare-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:10px;}}
    .splrepo-compare-col{{border:1px solid #27415a;border-radius:14px;background:#071523;padding:12px;}}
    .splrepo-compare-col h3{{margin:0 0 6px;font-size:15px;}}
    .splrepo-compare-col p{{margin:0;color:#c9d9ea;font-size:13px;line-height:1.55;}}
    .splrepo-footer-note{{color:#8fb4cf;font-size:12px;line-height:1.5;}}
    .splrepo-table-wrap{{border:1px solid #27415a;border-radius:16px;background:#081729;overflow:hidden;}}
    .splrepo-table-scroll{{overflow:auto;}}
    .splrepo-table{{width:100%;border-collapse:collapse;min-width:980px;table-layout:fixed;}}
    .splrepo-table thead th{{position:sticky;top:0;background:#0b2030;color:#8fd0ff;font-size:11px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;text-align:left;padding:12px;border-bottom:1px solid #27415a;z-index:1;}}
    .splrepo-table tbody tr{{border-top:1px solid #1f3549;}}
    .splrepo-table tbody tr:hover{{background:rgba(11,32,48,.45);}}
    .splrepo-table td{{vertical-align:top;padding:12px;color:#dbeafe;font-size:13px;line-height:1.5;}}
    .splrepo-cell-title{{font-weight:900;color:#f8fafc;}}
    .splrepo-cell-sub{{margin-top:4px;color:#8fb4cf;font-size:12px;line-height:1.45;}}
    .splrepo-pattern{{max-width:100%;font-family:"Consolas","SFMono-Regular",Menlo,monospace;font-size:12px;line-height:1.45;color:#d9e7f5;white-space:normal;word-break:break-word;}}
    .splrepo-row-actions{{display:flex;gap:8px;flex-wrap:wrap;}}
    .splrepo-row-actions-empty{{color:#86efac;font-size:12px;font-weight:800;}}
    .splrepo-empty{{padding:16px;color:#9fb4cc;font-size:13px;line-height:1.6;}}
    .splrepo-action-approve{{background:linear-gradient(135deg,#34d399,#10b981);border-color:#34d399;color:#04230f;box-shadow:0 6px 18px rgba(16,185,129,.18);}}
    .splrepo-action-reject{{background:linear-gradient(180deg,#2a1620,#170b12);border-color:#7f1d1d;color:#fecaca;box-shadow:0 6px 18px rgba(127,29,29,.18);}}
    .splrepo-side .splrepo-panel{{padding:16px;}}
    @media (max-width: 1080px){{.splrepo-grid,.splrepo-compare-grid{{grid-template-columns:1fr;}}.splrepo-side{{position:static;top:auto;}}}}
  </style>
  <div class="splrepo-shell">
    <div class="splrepo-hero">
      <h1>SPL Asset Repository</h1>
      <div class="splrepo-copy">This is where the SPL Optimization AI Engine stores reusable SPL patterns for this environment. <strong>Approved active assets</strong> already influence future SPL writing. <strong>Recorded drafts</strong> are candidate patterns waiting for review.</div>
      <div class="splrepo-metrics">
        <span class="splrepo-metric">Approved Active {active_count}</span>
        <span class="splrepo-metric">Recorded Drafts {history_count}</span>
        <span class="splrepo-metric">Review Queue {"Open" if history_count > 0 else "Clear"}</span>
      </div>
    </div>
    <div class="splrepo-grid">
      <div class="splrepo-main">
        <section class="splrepo-panel splrepo-panel-active">
          <div class="splrepo-section-head">
            <div>
              <h2>Active Reusable SPL Assets</h2>
              <div class="splrepo-section-note">These are already approved and can influence future SPL writing. Scan by row, then open the optimization page if you want to generate more drafts.</div>
            </div>
            <a class="btn-secondary" href="/learning" style="text-decoration:none;">Back to SPL Optimization</a>
          </div>
          <div class="splrepo-table-wrap">
            <div class="splrepo-table-scroll">
              <table class="splrepo-table">
                <thead>
                  <tr>
                    <th>Intent</th>
                    <th>State</th>
                    <th>Question Family</th>
                    <th>Why This Exists</th>
                    <th>Environment Fit</th>
                    <th>Pattern</th>
                    <th>Proof / Updated</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {active_table_rows if active_table_rows else '<tr><td colspan="8" class="splrepo-empty">No approved SPL assets yet. Approve a recorded draft when you want it to influence future SPL writing.</td></tr>'}
                </tbody>
              </table>
            </div>
          </div>
        </section>
        <section class="splrepo-compare">
          <h2 style="margin:0 0 4px;font-size:18px;">Why An Approved Asset Is Better For This Environment</h2>
          <div class="splrepo-copy">Use this as a quick mental model when reviewing drafts.</div>
          <div class="splrepo-compare-grid">
            <div class="splrepo-compare-col">
              <h3>Generic baseline pattern</h3>
              <p>Broader SPL often assumes generic fields, wider search scopes, and weaker environment grounding. It is easier to write once, but it is less reliable for this deployment.</p>
            </div>
            <div class="splrepo-compare-col">
              <h3>Approved environment-specific asset</h3>
              <p>An approved asset names the real indexes, sources, sourcetypes, and fields this environment actually exposes. That makes future SPL writing more reusable, more constrained, and more trustworthy.</p>
            </div>
          </div>
        </section>
        <section class="splrepo-panel splrepo-panel-drafts">
          <div class="splrepo-section-head">
            <div>
              <h2>Recorded SPL Asset Drafts</h2>
              <div class="splrepo-section-note">These drafts were generated by the engine. They do not affect runtime until approved. Review them row by row and act from the last column.</div>
            </div>
          </div>
          <div class="splrepo-table-wrap">
            <div class="splrepo-table-scroll">
              <table class="splrepo-table">
                <thead>
                      <tr>
                        <th>Intent</th>
                        <th>State</th>
                        <th>Question Family</th>
                        <th>Why This Exists</th>
                        <th>Environment Fit</th>
                        <th>Pattern</th>
                        <th>Proof / Updated</th>
                        <th>Actions</th>
                      </tr>
                </thead>
                <tbody>
                  {draft_table_rows if draft_table_rows else '<tr><td colspan="8" class="splrepo-empty">No recorded SPL drafts yet. Run the SPL Optimization AI Engine to generate reusable drafts for review.</td></tr>'}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      </div>
      <div class="splrepo-side">
        <section class="splrepo-spotlight">
          <div class="splrepo-spotlight-head">
            <div class="splrepo-spotlight-title">Active Asset Spotlight</div>
            <span class="splrepo-metric">{'Active and influencing future SPL' if spotlight else 'No active asset yet'}</span>
          </div>
          <div class="splrepo-spotlight-name">{spotlight_intent}</div>
          <div class="splrepo-spotlight-copy">{spotlight_when if spotlight_when else 'Approve a recorded draft from the table to create the first active reusable SPL asset for this environment.'}</div>
          {f'<div class="learning-item-meta" style="margin-top:10px;"><strong>Why it matters:</strong> {spotlight_why}</div>' if spotlight_why else ''}
          {f'<div class="learning-item-meta"><strong>Current reusable pattern:</strong> {spotlight_pattern}</div>' if spotlight_pattern else ''}
        </section>
        <section class="splrepo-panel">
          <h2>What This Page Is For</h2>
          <div class="splrepo-status-list">
            <div class="splrepo-status-item"><strong>Scan</strong> the tables by row to compare reusable SPL assets quickly.</div>
            <div class="splrepo-status-item"><strong>Review</strong> recorded drafts in the queue before they influence runtime.</div>
            <div class="splrepo-status-item"><strong>Approve</strong> only assets that are accurate, reusable, and grounded in this environment.</div>
          </div>
        </section>
        <section class="splrepo-panel">
          <h2>Review Queue</h2>
          <div class="splrepo-queue-stat">
            <div>
              <div class="splrepo-guide-title" style="margin:0 0 4px;">Recorded drafts ready</div>
              <div class="splrepo-copy">{review_message}</div>
            </div>
            <div class="splrepo-queue-count">{history_count}</div>
          </div>
          <div class="splrepo-status-list">
            <div class="splrepo-status-item"><strong>Approve</strong> when a draft is accurate, reusable, and grounded in this environment.</div>
            <div class="splrepo-status-item"><strong>Reject</strong> when a draft is too generic, too weak, or not worth influencing future SPL writing.</div>
            <div class="splrepo-status-item"><strong>Remember:</strong> recorded drafts are visible history only. They do not become active until approved.</div>
          </div>
        </section>
        <section class="splrepo-panel">
          <h2>Repository Status</h2>
          <div class="splrepo-status-list">
            <div class="splrepo-status-item"><strong>Repository path:</strong> <code>{repo_path}</code></div>
            <div class="splrepo-status-item"><strong>Approved active:</strong> {active_count}</div>
            <div class="splrepo-status-item"><strong>Recorded drafts:</strong> {history_count}</div>
          </div>
          <div class="splrepo-footer-note" style="margin-top:10px;">This page is for review and activation. The SPL Optimization AI Engine creates the drafts; this repository decides what becomes active.</div>
        </section>
      </div>
    </div>
  </div>
  <script>
    document.querySelectorAll('[data-repo-action][data-id]').forEach((btn) => {{
      btn.onclick = async () => {{
        const action = String(btn.getAttribute('data-repo-action') || '').trim();
        const id = String(btn.getAttribute('data-id') || '').trim();
        btn.disabled = true;
        const resp = await fetch('/api/config/local-learning', {{
          method:'POST',
          headers:{{'Content-Type':'application/json'}},
          body: JSON.stringify({{action, id}})
        }});
        const data = await resp.json();
        if(!resp.ok){{
          alert(data.error || `asset ${{action}} failed (${{resp.status}})`);
          btn.disabled = false;
          return;
        }}
        location.reload();
      }};
    }});
  </script>
</div>
"""


def _mcp_page_body() -> str:
    return """
<div class=\"card\">
  <style>
    .mcp-shell { display:grid; grid-template-columns: 1.05fr .95fr; gap:12px; }
    .mcp-pane {
      background: linear-gradient(170deg,#081a2c,#071321);
      border:1px solid #294560;
      border-radius: 14px;
      padding: 12px;
      box-shadow: inset 0 0 0 1px rgba(255,255,255,0.02);
    }
    .mcp-pane h2 { margin:0 0 8px; font-size:18px; }
    .mcp-sub { color:#abc1d7; font-size:12px; line-height:1.45; margin-bottom:8px; }
    .mcp-prompt {
      min-height: 170px;
      border:1px solid #3b5f7f;
      background:#051120;
      color:#e5e7eb;
      border-radius:10px;
      padding:12px;
      font-size:14px;
      line-height:1.45;
      resize:vertical;
      box-sizing:border-box;
      width:100%;
      font-family:"Trebuchet MS","Segoe UI","Helvetica Neue",Helvetica,sans-serif;
    }
    .mcp-actions { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-top:10px; }
    .mcp-send {
      margin-top:0;
      background:#22c55e;
      color:#04210e;
      border:0;
      border-radius:10px;
      font-weight:800;
      padding:11px 14px;
      cursor:pointer;
    }
    .mcp-status-pill {
      display:inline-block;
      border:1px solid #2d4f6c;
      border-radius:999px;
      padding:3px 10px;
      font-size:12px;
      color:#dbeafe;
      background:#0a2338;
    }
    .mcp-status-pill.ok { border-color:#166534; background:#052e16; color:#bbf7d0; }
    .mcp-status-pill.bad { border-color:#7f1d1d; background:#2a0d0d; color:#fecaca; }
    .mcp-progress {
      margin-top:10px;
      border:1px solid #2a4056;
      border-radius:10px;
      background:#07111f;
      padding:8px;
      display:none;
    }
    .mcp-progress-meta {
      display:flex; justify-content:space-between; gap:8px; align-items:center;
      font-size:12px; color:#c7d8eb; margin-bottom:6px;
    }
    .mcp-progress-track {
      width:100%; height:10px; border-radius:999px; border:1px solid #1f2937;
      background:#0b2130; overflow:hidden;
    }
    .mcp-progress-bar {
      width:0%; height:100%; border-radius:999px;
      background:linear-gradient(90deg,#22c55e,#10b981);
      transition:width .2s ease;
    }
    .mcp-chat {
      height: 410px;
      overflow:auto;
      white-space: pre-wrap;
      border-radius:10px;
      border:1px solid #26435c;
      background:#030b17;
      padding:10px;
      font-family:"Consolas","SFMono-Regular",Menlo,monospace;
      font-size:12.5px;
      line-height:1.45;
    }
    .mcp-metrics { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:8px; }
    .mcp-metric {
      border:1px solid #28445f;
      background:#071628;
      color:#d5e6f8;
      border-radius:999px;
      padding:4px 10px;
      font-size:12px;
      font-family:"Consolas","SFMono-Regular",Menlo,monospace;
    }
    .mcp-domain-box {
      border:1px solid #27415a;
      background:#061423;
      border-radius:10px;
      padding:8px;
      margin-top:8px;
    }
    .mcp-domain-item {
      border:1px solid #25435f;
      background:#0a1b2d;
      border-radius:8px;
      padding:6px 8px;
      margin-bottom:6px;
      font-size:12px;
    }
    .mcp-domain-item:last-child { margin-bottom:0; }
    .mcp-domain-item .idx {
      color:#93c5fd; font-weight:700;
      font-family:"Consolas","SFMono-Regular",Menlo,monospace;
    }
    @media (max-width: 1080px) { .mcp-shell { grid-template-columns: 1fr; } }
  </style>
  <h1>Splunk MCP Chat</h1>
  <p class=\"muted\">Ask a natural-language security question. The backend uses the same guarded multi-model + RAG + Data Domain context used by Investigation UI.</p>
  <div class=\"mcp-shell\">
    <div class=\"mcp-pane\">
      <h2>Prompt</h2>
      <div class=\"mcp-sub\">Single natural-language prompt input. No artifact controls.</div>
      <textarea id=\"mcp-question\" class=\"mcp-prompt\" placeholder=\"Example: Show failed Linux and Windows login activity in the last 24 hours, then summarize suspicious sources.\">Show failed login activity in the last 24 hours</textarea>
      <div class=\"mcp-actions\">
        <button id=\"mcp-send\" class=\"mcp-send\">Ask Splunk MCP</button>
        <span id=\"mcp-status-pill\" class=\"mcp-status-pill\">idle</span>
      </div>
      <div id=\"mcp-progress\" class=\"mcp-progress\">
        <div class=\"mcp-progress-meta\">
          <span id=\"mcp-progress-label\">Preparing MCP query...</span>
          <span id=\"mcp-progress-pct\">0%</span>
        </div>
        <div class=\"mcp-progress-track\"><div id=\"mcp-progress-bar\" class=\"mcp-progress-bar\"></div></div>
      </div>
      <p id=\"mcp-status\" class=\"muted\"></p>
      <div class=\"mcp-domain-box\">
        <div class=\"mcp-sub\" style=\"margin:0 0 6px;\">Data Domain Hints Used for Query Planning</div>
        <div id=\"mcp-domain-hints\" class=\"muted\">Run a question to view likely index/sourcetype targets.</div>
      </div>
    </div>
    <div class=\"mcp-pane\">
      <h2>Assistant Output</h2>
      <div class=\"mcp-sub\">Natural-language response plus execution telemetry from the guarded MCP flow.</div>
      <pre id=\"mcp-chat\" class=\"mcp-chat\"></pre>
    </div>
  </div>
  <h2>Execution Details</h2>
  <div class=\"mcp-metrics\">
    <span id=\"mcp-intent\" class=\"mcp-metric\">intent=n/a</span>
    <span id=\"mcp-tool\" class=\"mcp-metric\">tool=n/a</span>
    <span id=\"mcp-rows\" class=\"mcp-metric\">rows=0</span>
    <span id=\"mcp-writer\" class=\"mcp-metric\">writer_model=unknown</span>
    <span id=\"mcp-runtime\" class=\"mcp-metric\">spl_run_ms=unknown</span>
    <span id=\"mcp-rag\" class=\"mcp-metric\">rag=unknown</span>
  </div>
  <h3>SPL</h3>
  <pre id=\"mcp-spl\"></pre>
  <div><a id=\"mcp-spl-link\" href=\"#\" target=\"_blank\" rel=\"noopener noreferrer\" style=\"display:none; color:#93c5fd; text-decoration:none; font-size:13px;\">View in Splunk</a></div>
  <h3>Result Rows (sample)</h3>
  <pre id=\"mcp-results\"></pre>
  <details class=\"guided\" style=\"margin-top:12px;\">
    <summary>Show Raw JSON</summary>
    <pre id=\"mcp-json\"></pre>
  </details>
</div>
<script>
  const q = document.getElementById('mcp-question');
  const send = document.getElementById('mcp-send');
  const statusEl = document.getElementById('mcp-status');
  const chat = document.getElementById('mcp-chat');
  const intent = document.getElementById('mcp-intent');
  const tool = document.getElementById('mcp-tool');
  const rows = document.getElementById('mcp-rows');
  const writer = document.getElementById('mcp-writer');
  const runtime = document.getElementById('mcp-runtime');
  const rag = document.getElementById('mcp-rag');
  const statusPill = document.getElementById('mcp-status-pill');
  const spl = document.getElementById('mcp-spl');
  const splLink = document.getElementById('mcp-spl-link');
  const results = document.getElementById('mcp-results');
  const raw = document.getElementById('mcp-json');
  const domainHints = document.getElementById('mcp-domain-hints');
  const progressWrap = document.getElementById('mcp-progress');
  const progressBar = document.getElementById('mcp-progress-bar');
  const progressPct = document.getElementById('mcp-progress-pct');
  const progressLabel = document.getElementById('mcp-progress-label');
  let progressTimer = null;
  let progressValue = 0;

  function setStatus(label, cls='') {
    statusPill.textContent = label;
    statusPill.className = 'mcp-status-pill';
    if (cls) statusPill.classList.add(cls);
  }

  function appendChat(role, text) {
    const ts = new Date().toISOString();
    chat.textContent += `[${ts}] ${role}: ${text}\\n\\n`;
    chat.scrollTop = chat.scrollHeight;
  }

  function setProgress(v, label='') {
    progressValue = Math.max(0, Math.min(100, Number(v || 0)));
    progressWrap.style.display = 'block';
    progressBar.style.width = `${progressValue}%`;
    progressPct.textContent = `${Math.round(progressValue)}%`;
    if (label) progressLabel.textContent = label;
  }

  function startProgress() {
    if (progressTimer) clearInterval(progressTimer);
    setProgress(3, 'Planning guarded MCP query...');
    progressTimer = setInterval(() => {
      if (progressValue < 40) {
        setProgress(progressValue + 2.4, 'Applying RAG + Data Domain context...');
        return;
      }
      if (progressValue < 76) {
        setProgress(progressValue + 1.05, 'Executing Splunk MCP tool...');
        return;
      }
      if (progressValue < 93) {
        setProgress(progressValue + 0.42, 'Summarizing evidence...');
      }
    }, 350);
  }

  function stopProgress(ok) {
    if (progressTimer) {
      clearInterval(progressTimer);
      progressTimer = null;
    }
    setProgress(100, ok ? 'MCP query complete.' : 'MCP query failed.');
    setTimeout(() => { progressWrap.style.display = 'none'; }, 700);
  }

  send.onclick = async () => {
    const question = (q.value || '').trim();
    if (!question) return;
    send.disabled = true;
    setStatus('running');
    statusEl.textContent = 'Running MCP query...';
    startProgress();
    appendChat('You', question);
    try {
      const resp = await fetch('/api/mcp/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: question
        })
      });
      setProgress(95, 'Finalizing MCP output...');
      const data = await resp.json();
      if (!resp.ok) {
        statusEl.textContent = `error: ${data.error || `http_${resp.status}`}`;
        setStatus('error', 'bad');
        appendChat('System', statusEl.textContent);
        stopProgress(false);
        return;
      }
      setStatus('complete', 'ok');
      statusEl.textContent = 'Complete';
      appendChat('Assistant', data.summary || '(no summary)');
      intent.textContent = `intent=${data.intent || 'unknown'}`;
      tool.textContent = `tool=${data.selected_tool || 'n/a'}`;
      rows.textContent = `rows=${String(data.rows_returned ?? 0)} total=${String(data.total_rows ?? 0)}`;
      writer.textContent = `writer_model=${String(data.spl_writer_model || 'unknown')}`;
      runtime.textContent = `spl_run_ms=${String(data.spl_run_time_ms ?? 'unknown')}`;
      rag.textContent = `rag=${data.rag_enabled ? 'enabled' : 'disabled'} max_chars=${String(data.rag_max_chars ?? 'n/a')}`;
      const qArgs = data.query_args && typeof data.query_args === 'object' ? data.query_args : {};
      spl.textContent = qArgs.query || '(no splunk_run_query selected for this request)';
      if (qArgs.query) {
        const params = new URLSearchParams({
          q: String(qArgs.query),
          'display.page.search.mode': 'smart',
          'dispatch.sample_ratio': '1',
          workload_pool: '',
          earliest: String(qArgs.earliest_time || '-24h@h'),
          latest: String(qArgs.latest_time || 'now'),
          'display.page.search.tab': 'statistics',
          'display.general.type': 'statistics',
        });
        const splunkBase = String(data.splunk_search_url_base || '');
        if (splunkBase) {
          splLink.href = `${splunkBase}?${params.toString()}`;
          splLink.style.display = 'inline';
        } else {
          splLink.href = '#';
          splLink.style.display = 'none';
        }
      } else {
        splLink.href = '#';
        splLink.style.display = 'none';
      }
      const sample = Array.isArray(data.sample_rows) ? data.sample_rows : [];
      results.textContent = sample.length ? JSON.stringify(sample, null, 2) : '(no sample rows)';
      const hints = Array.isArray(data.domain_hints) ? data.domain_hints : [];
      if (!hints.length) {
        domainHints.innerHTML = '<div class=\"muted\">No strong domain hints were returned for this question.</div>';
      } else {
        domainHints.innerHTML = hints.slice(0, 4).map((h) => {
          const idx = String(h.index || '');
          const sts = Array.isArray(h.sourcetypes) ? h.sourcetypes : [];
          const why = Array.isArray(h.reasons) ? h.reasons.join('; ') : '';
          return (
            `<div class=\"mcp-domain-item\">` +
            `<div><span class=\"idx\">index=${idx}</span> <span class=\"badge\">score=${String(h.score ?? '')}</span></div>` +
            `<div class=\"muted\">sourcetypes: ${sts.join(', ')}</div>` +
            `<div class=\"muted\">why: ${why || 'keyword/domain match'}</div>` +
            `</div>`
          );
        }).join('');
      }
      raw.textContent = JSON.stringify(data, null, 2);
      stopProgress(true);
    } catch (err) {
      setStatus('error', 'bad');
      statusEl.textContent = `request failed: ${String(err)}`;
      appendChat('System', statusEl.textContent);
      stopProgress(false);
    } finally {
      send.disabled = false;
    }
  };
</script>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = f"SOCWebUI/{APP_VERSION}"

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(
        self,
        status: int,
        body_html: str,
        title: str = "A.G.E.N.T. Smith",
        nav_active: str = "docs",
        show_nav: bool = True,
    ) -> None:
        user = self._authenticated_user()
        body = DOCS_SHELL_HTML.format(
            title=html.escape(title),
            body=body_html,
            nav=_global_nav(nav_active) if show_nav else "",
            onboarding_user=html.escape(str((user or {}).get("username", ""))),
            onboarding_role=html.escape(str((user or {}).get("role", ""))),
            onboarding_modal=_admin_onboarding_modal(user),
            app_version=html.escape(APP_VERSION_LABEL),
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _session_token_from_cookie(self) -> str:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        try:
            cookie = SimpleCookie()
            cookie.load(raw)
            morsel = cookie.get(SESSION_COOKIE_NAME)
            return morsel.value if morsel else ""
        except Exception:
            return ""

    def _authenticated_user(self) -> dict[str, Any] | None:
        if not _auth_enabled():
            return {"username": "auth_disabled", "role": "admin"}
        token = self._session_token_from_cookie()
        return _get_session(token)

    def _set_session_cookie(self, token: str) -> None:
        self.send_header(
            "Set-Cookie",
            f"{SESSION_COOKIE_NAME}={token}; Max-Age={SESSION_TTL_SECONDS}; Path=/; HttpOnly; SameSite=Lax",
        )

    def _clear_session_cookie(self) -> None:
        self.send_header(
            "Set-Cookie",
            f"{SESSION_COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax",
        )

    def _redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        self.end_headers()

    def _require_auth(self, *, api_mode: bool = False) -> bool:
        if self._authenticated_user() is not None:
            return True
        if api_mode:
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized", "detail": "login required"})
            return False
        self._redirect("/login")
        return False

    def _login_page_body(self, error: str = "") -> str:
        error_html = ""
        if error:
            error_html = f"<div class=\"login-error\">{html.escape(error)}</div>"
        return (
            "<style>"
            ".login-shell{min-height:78vh;display:grid;place-items:center;padding:20px;}"
            ".login-card{width:min(520px,92vw);border:1px solid #284154;background:linear-gradient(165deg,#091727,#07111f);"
            "border-radius:18px;padding:22px;box-shadow:0 20px 44px rgba(0,0,0,.45);}"
            ".login-brand{display:flex;align-items:center;gap:10px;margin-bottom:8px;}"
            ".login-brand-row{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:8px;}"
            ".login-dot{width:11px;height:11px;border-radius:999px;background:#22c55e;box-shadow:0 0 14px rgba(34,197,94,.7);}"
            ".login-version{display:inline-flex;align-items:center;padding:5px 10px;border-radius:999px;border:1px solid #294560;background:#0b2130;color:#bde6ff;font-size:12px;font-weight:800;}"
            ".login-title{margin:0;font-size:27px;line-height:1.15;letter-spacing:.2px;}"
            ".login-sub{margin:4px 0 14px;color:#9fb4cc;font-size:13px;line-height:1.45;}"
            ".login-form label{display:block;font-size:13px;color:#d7e6f5;margin:10px 0 6px;}"
            ".login-form input{width:100%;box-sizing:border-box;background:#040c18;color:#e5e7eb;border:1px solid #33506a;"
            "border-radius:10px;padding:11px 12px;font-size:14px;outline:none;transition:border-color .15s ease;}"
            ".login-form input:focus{border-color:#58a6d9;}"
            ".login-error{margin:0 0 12px;padding:10px 12px;border-radius:10px;border:1px solid #7f1d1d;"
            "background:#2a0d0d;color:#fecaca;font-size:13px;}"
            ".login-actions{display:flex;gap:10px;align-items:center;margin-top:16px;}"
            ".login-btn{appearance:none;border:0;border-radius:10px;padding:11px 14px;background:#22c55e;color:#03230f;"
            "font-weight:800;cursor:pointer;font-size:14px;}"
            ".login-note{color:#9ca3af;font-size:12px;line-height:1.4;}"
            "</style>"
            "<div class=\"login-shell\">"
            "<div class=\"login-card\">"
            "<div class=\"login-brand-row\">"
            "<div class=\"login-brand\"><span class=\"login-dot\"></span><span class=\"badge\">Lab-Only</span></div>"
            f"<span class=\"login-version\">{html.escape(APP_VERSION_LABEL)}</span>"
            "</div>"
            "<h1 class=\"login-title\">A.G.E.N.T. Smith Login</h1>"
            "<p class=\"login-sub\">Sign in to access A.G.E.N.T. Smith investigation tools, analyst documentation, and guarded Splunk-connected workflows on this LAN host.</p>"
            f"{error_html}"
            "<form class=\"login-form\" method=\"post\" action=\"/login\">"
            "<label>Username</label><input name=\"username\" autocomplete=\"username\" required />"
            "<label>Password</label><input type=\"password\" name=\"password\" autocomplete=\"current-password\" required />"
            "<div class=\"login-actions\">"
            "<button class=\"login-btn\" type=\"submit\">Sign In</button>"
            "<span class=\"login-note\">Session expires automatically for safety.</span>"
            "</div>"
            "</form>"
            "</div>"
            "</div>"
    )


    def _cases_workspace_page_body(self) -> str:
        return (
        "<style>"
        ".cases-wrap{display:grid;grid-template-columns:360px minmax(0,1fr);gap:18px;align-items:start;}"
        ".cases-side{position:sticky;top:94px;display:grid;gap:14px;}"
        ".cases-panel{border:1px solid #203448;border-radius:18px;background:#091423;padding:18px;box-shadow:0 18px 36px rgba(0,0,0,.24);min-width:0;}"
        ".cases-hero{background:linear-gradient(135deg,rgba(12,38,59,.96),rgba(9,24,33,.96) 58%,rgba(8,38,30,.88));}"
        ".cases-kicker{font-size:12px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;color:#7dd3fc;}"
        ".cases-title{margin:8px 0 6px;font-size:34px;line-height:1.05;}"
        ".cases-copy{color:#9fb4cc;font-size:14px;line-height:1.65;max-width:860px;}"
        ".cases-meta{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px;}"
        ".cases-pill{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:999px;border:1px solid #284154;background:#0b2130;color:#cfe8ff;font-size:12px;font-weight:800;}"
        ".cases-list{display:grid;gap:10px;max-height:72vh;overflow:auto;padding-right:4px;}"
        ".case-list-item{width:100%;text-align:left;border:1px solid #203448;border-radius:14px;background:#081523;padding:12px;cursor:pointer;color:#e5eef8;display:grid;gap:6px;}"
        ".case-list-item.active{border-color:#45b8ff;background:#0d2234;box-shadow:0 0 0 1px rgba(69,184,255,.2) inset;}"
        ".case-list-title{font-size:13px;font-weight:800;line-height:1.45;}"
        ".case-list-meta{display:flex;gap:8px;flex-wrap:wrap;color:#9fb4cc;font-size:11px;font-weight:700;}"
        ".cases-main{display:grid;gap:18px;min-width:0;}"
        ".cases-grid{display:grid;grid-template-columns:1.15fr .95fr;gap:18px;align-items:start;min-width:0;}"
        ".case-tree{display:grid;gap:12px;min-width:0;}"
        ".case-tree-node{border:1px solid #203448;border-radius:14px;background:#071523;padding:12px 14px;display:grid;gap:6px;cursor:pointer;min-width:0;}"
        ".case-tree-node.active{border-color:#22c55e;background:#0b1d17;box-shadow:0 0 0 1px rgba(34,197,94,.18) inset;}"
        ".case-tree-head{display:flex;align-items:center;justify-content:space-between;gap:10px;}"
        ".case-tree-title{font-size:13px;font-weight:800;line-height:1.45;min-width:0;}"
        ".case-tree-copy{font-size:12px;color:#a7b8cb;line-height:1.55;}"
        ".case-tree-meta{display:flex;gap:8px;flex-wrap:wrap;}"
        ".case-tree-indent-1{margin-left:22px;}.case-tree-indent-2{margin-left:44px;}.case-tree-indent-3{margin-left:66px;}.case-tree-indent-4{margin-left:88px;}"
        ".case-stat-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;}"
        ".case-stat{border:1px solid #203448;border-radius:14px;background:#071523;padding:12px;display:grid;gap:4px;min-width:0;}"
        ".case-stat-kicker{font-size:11px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:#7dd3fc;}"
        ".case-stat-value{font-size:20px;font-weight:900;color:#f8fafc;}"
        ".case-stat-copy{font-size:12px;color:#9fb4cc;line-height:1.5;}"
        ".case-node-card{display:grid;gap:14px;min-width:0;}"
        ".case-node-section{border:1px solid #203448;border-radius:14px;background:#071523;padding:14px;min-width:0;}"
        ".case-node-section h3{margin:0 0 8px;font-size:14px;}"
        ".case-node-detail-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;}"
        ".case-node-detail{border:1px solid #203448;border-radius:12px;background:#08131f;padding:10px 12px;min-width:0;}"
        ".case-node-detail strong{display:block;font-size:11px;color:#7dd3fc;letter-spacing:.12em;text-transform:uppercase;margin-bottom:5px;}"
        ".case-node-detail span{display:block;color:#e5eef8;font-size:13px;line-height:1.5;word-break:break-word;}"
        ".case-spl-shell{border:1px solid #203448;border-radius:12px;background:#040c18;overflow:auto;max-height:360px;}"
        ".case-spl-shell pre{margin:0;padding:14px;font-size:12px;line-height:1.55;color:#dbeafe;white-space:pre-wrap;word-break:break-word;}"
        ".case-empty{color:#94a3b8;font-size:13px;line-height:1.6;}"
        "@media (max-width: 1180px){.cases-wrap{grid-template-columns:1fr;}.cases-side{position:static;}.cases-grid{grid-template-columns:1fr;}.case-stat-grid{grid-template-columns:repeat(2,minmax(0,1fr));}.case-node-detail-grid{grid-template-columns:1fr;}}"
        "</style>"
        "<section class=\"cases-hero cases-panel\">"
        "<div class=\"cases-kicker\">Case Workspace</div>"
        "<h1 class=\"cases-title\">Persistent Investigation Cases</h1>"
        "<p class=\"cases-copy\">Every investigation and pivot now writes a durable case node. Use this workspace to inspect the original finding, branch through pivots, reopen any prior node without rerunning Splunk, and review the shared investigation state that carried the case forward.</p>"
        f"<div class=\"cases-meta\"><span class=\"cases-pill\">Case Store: <strong>{html.escape(case_store_backend())}</strong></span><span class=\"cases-pill\">Branching: parent/child node timeline</span><span class=\"cases-pill\">Reuse prior findings without rerun</span></div>"
        "</section>"
        "<section class=\"cases-wrap\">"
        "<aside class=\"cases-side\">"
        "<div class=\"cases-panel\">"
        "<div class=\"cases-kicker\">Recent Cases</div>"
        "<h2 style=\"margin:8px 0 6px;font-size:20px;\">Open A Saved Case</h2>"
        "<p class=\"case-empty\">Select a saved case to inspect the branch history and reopen a node.</p>"
        "<div id=\"cases-list\" class=\"cases-list\"></div>"
        "</div>"
        "</aside>"
        "<div class=\"cases-main\">"
        "<div class=\"case-stat-grid\">"
        "<div class=\"case-stat\"><div class=\"case-stat-kicker\">Case</div><div id=\"case-stat-id\" class=\"case-stat-value\">-</div><div class=\"case-stat-copy\">Current selected case id.</div></div>"
        "<div class=\"case-stat\"><div class=\"case-stat-kicker\">Status</div><div id=\"case-stat-status\" class=\"case-stat-value\">-</div><div class=\"case-stat-copy\">Latest known case state.</div></div>"
        "<div class=\"case-stat\"><div class=\"case-stat-kicker\">Nodes</div><div id=\"case-stat-nodes\" class=\"case-stat-value\">0</div><div class=\"case-stat-copy\">Saved investigation and pivot nodes.</div></div>"
        "<div class=\"case-stat\"><div class=\"case-stat-kicker\">Latest Rows</div><div id=\"case-stat-rows\" class=\"case-stat-value\">0</div><div class=\"case-stat-copy\">Rows from the selected node.</div></div>"
        "</div>"
        "<div class=\"cases-grid\">"
        "<section class=\"cases-panel\">"
        "<div class=\"cases-kicker\">Branch View</div>"
        "<h2 style=\"margin:8px 0 6px;font-size:20px;\">Case Timeline</h2>"
        "<p class=\"case-empty\">The current case path appears here as a root investigation with child pivot nodes.</p>"
        "<div id=\"case-tree\" class=\"case-tree\"></div>"
        "</section>"
        "<section class=\"case-node-card\">"
        "<div class=\"cases-panel\">"
        "<div class=\"cases-kicker\">Node Detail</div>"
        "<div style=\"display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;\">"
        "<h2 style=\"margin:8px 0 6px;font-size:20px;\">Selected Node</h2>"
        "<a id=\"case-open-investigation\" class=\"btn-secondary\" href=\"/investigation\" style=\"text-decoration:none;\">Open In Investigation</a>"
        "</div>"
        "<div id=\"case-node-meta\" class=\"case-node-detail-grid\"></div>"
        "</div>"
        "<div class=\"cases-panel\">"
        "<div class=\"cases-kicker\">Saved Summary</div>"
        "<div id=\"case-node-summary\" class=\"case-empty\">Select a node to inspect the saved result.</div>"
        "</div>"
        "<div class=\"cases-panel\">"
        "<div class=\"cases-kicker\">Shared Investigation State</div>"
        "<div id=\"case-node-state\" class=\"case-empty\">Shared case state will appear here after you select a saved node.</div>"
        "</div>"
        "<div class=\"cases-panel\">"
        "<div class=\"cases-kicker\">Executed SPL</div>"
        "<div id=\"case-node-spl\" class=\"case-spl-shell\"><pre>(No saved SPL for this node)</pre></div>"
        "</div>"
        "</section>"
        "</div>"
        "</div>"
        "</section>"
        "<script>"
        "let selectedCaseId='';let selectedNodeId='';"
        "function esc(v){return String(v??'').replace(/[&<>\\\"']/g,(c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','\\\"':'&quot;',\"'\":'&#39;'}[c]));}"
        "function fmtStamp(epoch){const n=Number(epoch||0);if(!n)return 'n/a';return new Date(n*1000).toLocaleString();}"
        "function q(name){return new URLSearchParams(location.search).get(name)||'';}"
        "async function loadCases(){const resp=await fetch('/api/cases?limit=30');const data=await resp.json();const items=Array.isArray(data.items)?data.items:[];const shell=document.getElementById('cases-list');if(!items.length){shell.innerHTML='<div class=\"case-empty\">No saved cases yet. Run an investigation and then a pivot to populate this workspace.</div>';return;}shell.innerHTML=items.map((item)=>`<button class=\"case-list-item${item.case_id===selectedCaseId?' active':''}\" data-case-id=\"${esc(item.case_id)}\"><div class=\"case-list-title\">${esc(item.root_question||item.case_id)}</div><div class=\"case-list-meta\"><span class=\"pill\">${esc(item.status||'unknown')}</span><span class=\"pill\">nodes ${esc(item.node_count)}</span><span class=\"pill\">updated ${esc(fmtStamp(item.updated_at))}</span></div></button>`).join('');shell.querySelectorAll('[data-case-id]').forEach((btn)=>btn.onclick=()=>selectCase(String(btn.getAttribute('data-case-id')||'')));if(!selectedCaseId){selectedCaseId=q('case_id')||String(items[0].case_id||'');}}"
        "function renderCaseTree(payload){const timeline=Array.isArray(payload?.timeline)?payload.timeline:[];document.getElementById('case-stat-id').textContent=payload?.case_id||'-';document.getElementById('case-stat-status').textContent=payload?.status||'-';document.getElementById('case-stat-nodes').textContent=String(timeline.length);const shell=document.getElementById('case-tree');if(!timeline.length){shell.innerHTML='<div class=\"case-empty\">No nodes saved for this case yet.</div>';return;}if(!selectedNodeId){selectedNodeId=String(timeline[timeline.length-1].node_id||'');}shell.innerHTML=timeline.map((node)=>`<button class=\"case-tree-node case-tree-indent-${Math.min(Number(node.depth||0),4)}${String(node.node_id)===selectedNodeId?' active':''}\" data-node-id=\"${esc(node.node_id)}\"><div class=\"case-tree-head\"><div class=\"case-tree-title\">${esc(node.title||node.question||node.node_id)}</div><span class=\"pill\">${esc(node.node_type||'investigation')}</span></div><div class=\"case-tree-meta\"><span class=\"pill\">${esc(node.intent||'unknown')}</span><span class=\"pill\">rows ${esc(node.row_count||0)}</span><span class=\"pill\">${esc(fmtStamp(node.created_at))}</span></div><div class=\"case-tree-copy\">${esc(node.summary||'No saved summary yet.')}</div></button>`).join('');shell.querySelectorAll('[data-node-id]').forEach((btn)=>btn.onclick=()=>selectNode(String(btn.getAttribute('data-node-id')||'')));}"
        "function renderNode(result){const meta=document.getElementById('case-node-meta');const summary=document.getElementById('case-node-summary');const spl=document.getElementById('case-node-spl');const stateShell=document.getElementById('case-node-state');const investigationLink=document.getElementById('case-open-investigation');const qargs=result?.query_args&&typeof result.query_args==='object'?result.query_args:{};const graph=result?.graph_case_state&&typeof result.graph_case_state==='object'?result.graph_case_state:{};const entities=graph?.evidence_entities&&typeof graph.evidence_entities==='object'?graph.evidence_entities:{};const pivots=Array.isArray(graph?.pivot_candidates)?graph.pivot_candidates:[];document.getElementById('case-stat-rows').textContent=String(result?.total_rows ?? result?.rows_returned ?? 0);meta.innerHTML=`<div class=\"case-node-detail\"><strong>Question</strong><span>${esc(result?.active_question||result?.question||'')}</span></div><div class=\"case-node-detail\"><strong>Intent</strong><span>${esc(result?.intent||'')}</span></div><div class=\"case-node-detail\"><strong>Selected Tool</strong><span>${esc(result?.selected_tool||'')}</span></div><div class=\"case-node-detail\"><strong>Supported</strong><span>${esc(String(result?.supported ?? true))}</span></div><div class=\"case-node-detail\"><strong>Rows Returned</strong><span>${esc(result?.rows_returned ?? 0)}</span></div><div class=\"case-node-detail\"><strong>Time Range</strong><span>${esc(graph?.time_range?.earliest_time||graph?.time_range?.earliest||qargs.earliest_time||'-')} → ${esc(graph?.time_range?.latest_time||graph?.time_range?.latest||qargs.latest_time||'-')}</span></div>`;summary.innerHTML=result?.summary?`<div style=\"color:#dbeafe;font-size:14px;line-height:1.7;\">${esc(result.summary).replace(/\\n/g,'<br>')}</div>`:'<div class=\"case-empty\">No saved summary for this node.</div>';const entityHtml=Object.keys(entities).filter((key)=>Array.isArray(entities[key])&&entities[key].length).map((key)=>`<div class=\"case-node-detail\"><strong>${esc(key.replaceAll('_',' '))}</strong><span>${esc(entities[key].slice(0,5).join(', '))}</span></div>`).join('');stateShell.innerHTML=(entityHtml||'<div class=\"case-empty\">No structured evidence entities were saved for this node.</div>') + `<div class=\"case-node-detail-grid\" style=\"margin-top:10px;\"><div class=\"case-node-detail\"><strong>Pivot Candidates</strong><span>${esc(String(pivots.length))}</span></div><div class=\"case-node-detail\"><strong>Case Id</strong><span>${esc(String(graph?.case_id||selectedCaseId||''))}</span></div></div>`;spl.innerHTML=`<pre>${esc(String(qargs.query||'' ).trim()||'(No saved SPL for this node)')}</pre>`;if(investigationLink){investigationLink.href=`/investigation?case_id=${encodeURIComponent(selectedCaseId)}&node_id=${encodeURIComponent(selectedNodeId)}`;}}"
        "async function selectCase(caseId){if(!caseId)return;selectedCaseId=caseId;selectedNodeId='';history.replaceState(null,'',`/cases?case_id=${encodeURIComponent(caseId)}`);await loadCases();const resp=await fetch(`/api/case?case_id=${encodeURIComponent(caseId)}`);const data=await resp.json();if(!resp.ok||!data.case){document.getElementById('case-tree').innerHTML='<div class=\"case-empty\">Unable to load this case.</div>';return;}renderCaseTree(data.case);if(selectedNodeId){await selectNode(selectedNodeId);}else{const t=Array.isArray(data.case.timeline)?data.case.timeline:[];if(t.length) await selectNode(String(t[t.length-1].node_id||''));}}"
        "async function selectNode(nodeId){if(!selectedCaseId||!nodeId)return;selectedNodeId=nodeId;const resp=await fetch(`/api/case-node?case_id=${encodeURIComponent(selectedCaseId)}&node_id=${encodeURIComponent(nodeId)}`);const data=await resp.json();if(resp.ok&&data.result){renderNode(data.result);}await selectCaseRenderOnly(selectedCaseId);}"
        "async function selectCaseRenderOnly(caseId){const resp=await fetch(`/api/case?case_id=${encodeURIComponent(caseId)}`);const data=await resp.json();if(resp.ok&&data.case){renderCaseTree(data.case);}}"
        "window.addEventListener('load',async()=>{await loadCases();if(selectedCaseId) await selectCase(selectedCaseId);});"
        "</script>"
    )

    def _first_run_page_body(self, error: str = "") -> str:
        error_html = ""
        if error:
            error_html = f"<div class=\"login-error\">{html.escape(error)}</div>"
        return (
            "<style>"
            ".setup-shell{min-height:82vh;display:grid;place-items:center;padding:24px;}"
            ".setup-card{width:min(860px,96vw);display:grid;grid-template-columns:minmax(280px,.95fr) minmax(320px,1.05fr);gap:18px;"
            "border:1px solid #284154;background:linear-gradient(160deg,#081525,#07111f 52%,#0b1d17);border-radius:22px;padding:24px;"
            "box-shadow:0 24px 50px rgba(0,0,0,.46);}"
            ".setup-hero{padding:8px 6px 8px 0;}"
            ".setup-kicker{display:inline-flex;align-items:center;gap:8px;padding:6px 10px;border-radius:999px;border:1px solid #294560;background:#0b2130;color:#bde6ff;font-size:12px;font-weight:800;}"
            ".setup-title{margin:14px 0 8px;font-size:30px;line-height:1.05;letter-spacing:.2px;}"
            ".setup-copy{color:#a9bfd6;font-size:14px;line-height:1.65;margin:0 0 14px;}"
            ".setup-list{display:grid;gap:10px;margin-top:14px;}"
            ".setup-item{border:1px solid #203448;border-radius:14px;background:#091423;padding:12px 14px;}"
            ".setup-item strong{display:block;color:#f8fafc;font-size:13px;margin-bottom:4px;}"
            ".setup-item span{color:#b7cadc;font-size:13px;line-height:1.45;}"
            ".setup-form{border:1px solid #294560;border-radius:18px;background:rgba(5,16,29,.84);padding:18px;}"
            ".setup-form h2{margin:0 0 6px;font-size:20px;}"
            ".setup-form p{margin:0 0 12px;color:#9fb4cc;font-size:13px;line-height:1.55;}"
            ".setup-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}"
            ".setup-form label{display:block;font-size:12px;color:#dbeafe;margin:10px 0 6px;font-weight:800;text-transform:uppercase;letter-spacing:.08em;}"
            ".setup-form input,.setup-form select{width:100%;box-sizing:border-box;background:#040c18;color:#f8fafc;border:1px solid #33506a;border-radius:14px;"
            "padding:12px 14px;font-size:14px;outline:none;appearance:none;}"
            ".setup-form input:focus,.setup-form select:focus{border-color:#60a5fa;box-shadow:0 0 0 3px rgba(96,165,250,.15);}"
            ".setup-actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:16px;}"
            ".setup-btn{appearance:none;border:0;border-radius:14px;padding:12px 16px;background:linear-gradient(135deg,#22c55e,#16a34a);color:#03230f;font-weight:900;cursor:pointer;font-size:14px;}"
            ".setup-note{color:#9ca3af;font-size:12px;line-height:1.45;}"
            "@media (max-width: 860px){.setup-card{grid-template-columns:1fr;}.setup-grid{grid-template-columns:1fr;}}"
            "</style>"
            "<div class=\"setup-shell\">"
            "<div class=\"setup-card\">"
            "<div class=\"setup-hero\">"
            "<div class=\"setup-kicker\">First-Run Setup</div>"
            "<h1 class=\"setup-title\">Finish securing A.G.E.N.T. Smith before first use</h1>"
            "<p class=\"setup-copy\">Set the first login, choose the operator role, and lock in credentials before the rest of the platform becomes available.</p>"
            "<div class=\"setup-list\">"
            "<div class=\"setup-item\"><strong>Why this appears</strong><span>A.G.E.N.T. Smith detected a fresh or placeholder UI auth configuration.</span></div>"
            "<div class=\"setup-item\"><strong>What this does</strong><span>Writes the initial local user into <code>config/ui.env</code>, stores a salted password hash, and marks the instance initialized.</span></div>"
            "<div class=\"setup-item\"><strong>What happens next</strong><span>After setup, sign in normally and continue to Configuration to validate Splunk, Ollama, and model assignments.</span></div>"
            "</div>"
            "</div>"
            "<div class=\"setup-form\">"
            "<h2>Create first login</h2>"
            "<p>Use a strong password. This is the credential that gates the web UI on your LAN.</p>"
            f"{error_html}"
            "<form method=\"post\" action=\"/setup/first-run\">"
            "<div class=\"setup-grid\">"
            "<div><label>Username</label><input name=\"username\" autocomplete=\"username\" required placeholder=\"analyst\" /></div>"
            "<div><label>Role</label><select name=\"role\"><option value=\"admin\">admin</option><option value=\"ops\">ops</option><option value=\"analyst\">analyst</option></select></div>"
            "</div>"
            "<label>Password</label><input type=\"password\" name=\"password\" autocomplete=\"new-password\" required minlength=\"12\" />"
            "<label>Confirm Password</label><input type=\"password\" name=\"confirm_password\" autocomplete=\"new-password\" required minlength=\"12\" />"
            "<div class=\"setup-actions\">"
            "<button class=\"setup-btn\" type=\"submit\">Save And Continue</button>"
            "<span class=\"setup-note\">You can change these later from Configuration after sign-in.</span>"
            "</div>"
            "</form>"
            "</div>"
            "</div>"
            "</div>"
        )

    def _handle_first_run_get(self) -> None:
        if not _first_run_setup_required():
            self._redirect("/login")
            return
        self._html(HTTPStatus.OK, self._first_run_page_body(), title="A.G.E.N.T. Smith First-Run Setup", show_nav=False)

    def _handle_first_run_post(self) -> None:
        if not _first_run_setup_required():
            self._redirect("/login")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(length)
        parsed = parse_qs(raw.decode("utf-8", errors="replace"))
        username = str((parsed.get("username", [""])[0] or "")).strip()
        role = str((parsed.get("role", ["admin"])[0] or "admin")).strip().lower()
        password = parsed.get("password", [""])[0] or ""
        confirm_password = parsed.get("confirm_password", [""])[0] or ""

        if not username:
            self._html(HTTPStatus.BAD_REQUEST, self._first_run_page_body("Username is required."), title="A.G.E.N.T. Smith First-Run Setup", show_nav=False)
            return
        if role not in ALLOWED_APP_ROLES:
            role = "admin"
        if len(password) < 12:
            self._html(HTTPStatus.BAD_REQUEST, self._first_run_page_body("Password must be at least 12 characters."), title="A.G.E.N.T. Smith First-Run Setup", show_nav=False)
            return
        if password != confirm_password:
            self._html(HTTPStatus.BAD_REQUEST, self._first_run_page_body("Password and confirmation do not match."), title="A.G.E.N.T. Smith First-Run Setup", show_nav=False)
            return
        if password in DEFAULT_UI_PASSWORDS:
            self._html(HTTPStatus.BAD_REQUEST, self._first_run_page_body("Choose a password that is not one of the default placeholders."), title="A.G.E.N.T. Smith First-Run Setup", show_nav=False)
            return

        hashed = _hash_password(password)
        write_env_file(
            {
                "SOC_UI_AUTH_ENABLED": "1",
                "SOC_UI_AUTH_USERNAME": username,
                "SOC_UI_AUTH_PASSWORD": hashed,
                "SOC_UI_AUTH_ROLE": role,
                "SOC_UI_AUTH_USERS_JSON": json.dumps([{"username": username, "password": hashed, "role": role}], separators=(",", ":")),
                "SOC_UI_AUTH_INITIALIZED": "1",
            },
            UI_ENV_PATH,
        )
        os.environ["SOC_UI_AUTH_ENABLED"] = "1"
        os.environ["SOC_UI_AUTH_USERNAME"] = username
        os.environ["SOC_UI_AUTH_PASSWORD"] = hashed
        os.environ["SOC_UI_AUTH_ROLE"] = role
        os.environ["SOC_UI_AUTH_USERS_JSON"] = json.dumps([{"username": username, "password": hashed, "role": role}], separators=(",", ":"))
        os.environ["SOC_UI_AUTH_INITIALIZED"] = "1"
        token = _create_session(username, role)
        self.send_response(HTTPStatus.FOUND)
        self._set_session_cookie(token)
        self.send_header("Location", "/configure")
        self.end_headers()

    def _handle_login_get(self) -> None:
        if not _auth_enabled():
            self._redirect("/")
            return
        if _first_run_setup_required():
            self._redirect("/setup/first-run")
            return
        if self._authenticated_user() is not None:
            self._redirect("/")
            return
        self._html(HTTPStatus.OK, self._login_page_body(), title="Smith Console Login", show_nav=False)

    def _handle_logout_get(self) -> None:
        token = self._session_token_from_cookie()
        _delete_session(token)
        self.send_response(HTTPStatus.FOUND)
        self._clear_session_cookie()
        self.send_header("Location", "/login")
        self.end_headers()

    def _handle_login_post(self) -> None:
        if not _auth_enabled():
            self._redirect("/")
            return
        if _first_run_setup_required():
            self._redirect("/setup/first-run")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(length)
        body = raw.decode("utf-8", errors="replace")
        parsed = parse_qs(body)
        username = (parsed.get("username", [""])[0] or "").strip()
        password = parsed.get("password", [""])[0] or ""

        users = _load_auth_users()
        user = users.get(username)
        if not user or not _password_matches(str(user.get("password", "")), password):
            self._html(
                HTTPStatus.UNAUTHORIZED,
                self._login_page_body("Invalid username or password."),
                title="Smith Console Login",
                show_nav=False,
            )
            return

        role = str(user.get("role", "analyst")).strip().lower()
        if role not in ALLOWED_APP_ROLES:
            role = "analyst"
        token = _create_session(username, role)
        self.send_response(HTTPStatus.FOUND)
        self._set_session_cookie(token)
        self.send_header("Location", "/")
        self.end_headers()

    def _ops_role(self, parsed_query: dict[str, list[str]]) -> str:
        user = self._authenticated_user()
        if user is not None:
            return str(user.get("role", "")).strip().lower()
        # Fallback path (expected only when auth is disabled).
        query_role = (parsed_query.get("role", [""])[0] or "").strip().lower()
        header_role = (
            self.headers.get("X-User-Role")
            or self.headers.get("X-Role")
            or self.headers.get("X-Lab-Role")
            or ""
        ).strip().lower()
        return query_role or header_role

    def _require_ops_role(self, parsed_query: dict[str, list[str]]) -> bool:
        role = self._ops_role(parsed_query)
        if role_allowed(role):
            return True
        self._json(
            403,
            {
                "error": "forbidden",
                "detail": "ops/admin role required",
            },
        )
        return False

    def _require_ops_page(self) -> bool:
        role = self._ops_role({})
        if role_allowed(role):
            return True
        self._html(
            HTTPStatus.FORBIDDEN,
            "<div class=\"card\"><h1>Configuration</h1><p class=\"muted\">ops/admin role required.</p></div>",
            title="Configuration",
            nav_active="configure",
        )
        return False

    def _require_admin_role(self, parsed_query: dict[str, list[str]]) -> bool:
        role = self._ops_role(parsed_query)
        if role == "admin":
            return True
        self._json(
            403,
            {
                "error": "forbidden",
                "detail": "admin role required",
            },
        )
        return False

    def _require_admin_page(self) -> bool:
        role = self._ops_role({})
        if role == "admin":
            return True
        self._html(
            HTTPStatus.FORBIDDEN,
            "<div class=\"card\"><h1>Users</h1><p class=\"muted\">admin role required.</p></div>",
            title="Users",
            nav_active="control",
        )
        return False

    def _api_config_runtime_get(self) -> None:
        if not self._require_ops_role({}):
            return
        self._json(HTTPStatus.OK, _config_snapshot())

    def _api_config_runtime_secret_get(self, parsed) -> None:
        if not self._require_ops_role({}):
            return
        params = parse_qs(parsed.query or "")
        name = str((params.get("name", [""])[0] or "")).strip()
        if name != "SPLUNK_LAB_BEARER_TOKEN":
            self._json(HTTPStatus.BAD_REQUEST, {"error": "unsupported secret name"})
            return
        self._json(HTTPStatus.OK, {"name": name, "value": get_runtime_secret(name, "")})

    def _api_config_dependencies_get(self) -> None:
        if not self._require_ops_role({}):
            return
        self._json(HTTPStatus.OK, _collect_dependency_status())

    def _api_config_mcp_probe_post(self) -> None:
        if not self._require_ops_role({}):
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode("utf-8")) if raw else {}
        values = payload.get("values", {}) if isinstance(payload, dict) else {}
        if not isinstance(values, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "values must be an object"})
            return
        merged = _config_snapshot().get("values", {})
        if isinstance(merged, dict):
            merged.update({key: _resolve_config_value_for_merge(key, value, merged) for key, value in values.items()})
        self._json(HTTPStatus.OK, _mcp_probe(merged if isinstance(merged, dict) else {}))

    def _api_config_validate_post(self) -> None:
        if not self._require_ops_role({}):
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode("utf-8")) if raw else {}
        values = payload.get("values", {}) if isinstance(payload, dict) else {}
        if not isinstance(values, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "values must be an object"})
            return
        merged = _config_snapshot().get("values", {})
        if isinstance(merged, dict):
            merged.update({key: _resolve_config_value_for_merge(key, value, merged) for key, value in values.items()})
        scope = str(payload.get("scope", "full")).strip().lower() if isinstance(payload, dict) else "full"
        if scope not in {"full", "edge"}:
            scope = "full"
        validation = _validate_runtime_config(merged, scope=scope)
        validation["environment_profile_status"] = _maybe_trigger_environment_profile_bootstrap(validation)
        self._json(HTTPStatus.OK, validation)

    def _api_config_runtime_post(self) -> None:
        if not self._require_ops_role({}):
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode("utf-8")) if raw else {}
        values = payload.get("values", {}) if isinstance(payload, dict) else {}
        if not isinstance(values, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "values must be an object"})
            return
        current_values = _config_snapshot().get("values", {})
        if not isinstance(current_values, dict):
            current_values = {}
        updates = {
            key: _resolve_config_value_for_merge(key, values.get(key, ""), current_values)
            for key in CONFIG_EDITABLE_KEYS
            if key in values
        }
        ollama_host = str(updates.get("OLLAMA_HOST", "")).strip().rstrip("/") or get_ollama_host()
        available_models = _discover_ollama_models(ollama_host)
        updates = _autofill_model_assignments(updates, available_models)
        write_env_file(updates, UI_ENV_PATH)
        snapshot = _config_snapshot()
        validation = _validate_runtime_config(snapshot.get("values", {}) if isinstance(snapshot.get("values", {}), dict) else {})
        snapshot["environment_profile_status"] = _maybe_trigger_environment_profile_bootstrap(validation)
        self._json(HTTPStatus.OK, snapshot)

    def _api_config_users_get(self) -> None:
        if not self._require_admin_role({}):
            return
        self._json(HTTPStatus.OK, _users_snapshot())

    def _api_config_users_post(self) -> None:
        if not self._require_admin_role({}):
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode("utf-8")) if raw else {}
        if not isinstance(payload, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "payload must be an object"})
            return
        action = str(payload.get("action", "")).strip().lower()
        username = str(payload.get("username", "")).strip()
        role = str(payload.get("role", "analyst")).strip().lower()
        password = str(payload.get("password", ""))
        current_user = self._authenticated_user() or {}
        current_username = str(current_user.get("username", "")).strip()

        users = _load_auth_users()
        if action == "create":
            if not username:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "username is required"})
                return
            if username in users:
                self._json(HTTPStatus.CONFLICT, {"error": "user already exists"})
                return
            if role not in ALLOWED_APP_ROLES:
                role = "analyst"
            if len(password) < 12:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "password must be at least 12 characters"})
                return
            users[username] = {"password": _hash_password(password), "role": role}
        elif action == "update":
            if not username or username not in users:
                self._json(HTTPStatus.NOT_FOUND, {"error": "user not found"})
                return
            if role in ALLOWED_APP_ROLES:
                users[username]["role"] = role
            if password:
                if len(password) < 12:
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "password must be at least 12 characters"})
                    return
                users[username]["password"] = _hash_password(password)
        elif action == "delete":
            if not username or username not in users:
                self._json(HTTPStatus.NOT_FOUND, {"error": "user not found"})
                return
            if username == current_username:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "cannot delete the currently signed-in user"})
                return
            if len(users) <= 1:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "at least one user must remain"})
                return
            users.pop(username, None)
        else:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "unsupported action"})
            return

        _persist_auth_users(users)
        self._json(HTTPStatus.OK, {"status": "ok", **_users_snapshot()})

    def _api_query_audit_get(self) -> None:
        if not self._require_admin_role({}):
            return
        self._json(
            HTTPStatus.OK,
            {
                "path": display_path(QUERY_AUDIT_LOG),
                "recent": _recent_query_audit(50),
            },
        )

    def _api_session_onboarding_post(self) -> None:
        user = self._authenticated_user()
        if not isinstance(user, dict):
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        if str(user.get("role", "")).strip().lower() != "admin":
            self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden", "detail": "admin role required"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode("utf-8")) if raw else {}
        if not isinstance(payload, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "payload must be an object"})
            return
        action = str(payload.get("action", "")).strip().lower()
        if action not in {"skip"}:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "unsupported action"})
            return
        token = self._session_token_from_cookie()
        if not _set_session_admin_onboarding_skip(token, True):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "session not found"})
            return
        self._json(HTTPStatus.OK, {"status": "ok", "action": action})

    def _api_config_personalize_post(self) -> None:
        if not self._require_ops_role({}):
            return
        if _personalization_in_progress():
            self._json(
                HTTPStatus.ACCEPTED,
                {
                    "status": "in_progress",
                    "detail": "Personalization build is already running.",
                    "personalization": _personalization_status(),
                },
            )
            return
        if not _environment_profile_exists():
            self._json(
                HTTPStatus.PRECONDITION_FAILED,
                {
                    "error": "environment_profile_missing",
                    "detail": "Build Data Domains first by validating Splunk MCP and waiting for the environment profile to finish.",
                    "environment_profile_status": _environment_profile_bootstrap_state(),
                },
            )
            return
        threading.Thread(target=_run_personalization_refresh, daemon=True).start()
        self._json(
            HTTPStatus.ACCEPTED,
            {
                "status": "started",
                "detail": "Environment-aware SPL personalization build started.",
                "personalization": {
                    "state": "in_progress",
                    "detail": "Environment-aware SPL personalization build is running.",
                    "path": display_path(SPL_SKILLPACK_PATH),
                },
            },
        )

    def _api_config_personalize_get(self) -> None:
        if not self._require_ops_role({}):
            return
        self._json(HTTPStatus.OK, {"personalization": _personalization_status()})

    def _api_config_local_learning_get(self) -> None:
        if not self._require_ops_role({}):
            return
        self._json(HTTPStatus.OK, {"local_learning": _local_learning_status()})

    def _api_config_local_learning_post(self) -> None:
        if not self._require_ops_role({}):
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(length)
        payload = json.loads(raw.decode("utf-8")) if raw else {}
        if not isinstance(payload, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "payload must be an object"})
            return
        action = str(payload.get("action", "")).strip().lower()
        if action == "self_learn":
            if _local_learning_in_progress():
                self._json(
                    HTTPStatus.ACCEPTED,
                    {
                        "status": "in_progress",
                        "detail": "SPL Optimization AI Engine is already running.",
                        "local_learning": _local_learning_status(),
                    },
                )
                return
            threading.Thread(target=_run_local_learning_refresh, daemon=True).start()
            self._json(
                HTTPStatus.ACCEPTED,
                {
                    "status": "started",
                    "detail": "SPL Optimization AI Engine started.",
                    "local_learning": {
                        "state": "in_progress",
                        "detail": "Starting SPL Optimization AI Engine run...",
                        "progress_pct": 5,
                        "phase": "starting",
                        "path": display_path(ensure_learning_registry()),
                        "log_path": display_path(LOCAL_LEARNING_LOG),
                        **learning_registry_summary(),
                    },
                },
            )
            return
        if action in {"approve", "reject", "stale"}:
            record_id = str(payload.get("id", "")).strip()
            if not record_id:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "id is required"})
                return
            status_map = {"approve": "approved", "reject": "rejected", "stale": "stale"}
            target_status = status_map.get(action, action)
            ok = set_learning_record_status(record_id, target_status)
            if not ok:
                self._json(HTTPStatus.NOT_FOUND, {"error": "record not found"})
                return
            self._json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "detail": f"Learning record {record_id} set to {target_status}.",
                    "local_learning": _local_learning_status(),
                },
            )
            return
        self._json(HTTPStatus.BAD_REQUEST, {"error": "unsupported action"})

    def _api_config_env_refresh_get(self) -> None:
        if not self._require_ops_role({}):
            return
        self._json(HTTPStatus.OK, {"refresh": _environment_profile_refresh_status()})

    def _api_config_env_refresh_post(self) -> None:
        if not self._require_ops_role({}):
            return
        if _environment_profile_refresh_in_progress():
            self._json(
                HTTPStatus.ACCEPTED,
                {
                    "status": "in_progress",
                    "detail": "Environment profile refresh is already running.",
                    "refresh": _environment_profile_refresh_status(),
                },
            )
            return
        threading.Thread(target=_run_environment_profile_refresh, daemon=True).start()
        self._json(
            HTTPStatus.ACCEPTED,
            {
                "status": "started",
                "detail": "Environment profile refresh started.",
                "refresh": _environment_profile_refresh_status(),
            },
        )

    def _api_environment_wipe_refresh_post(self) -> None:
        if not self._require_ops_role({}):
            return
        if _environment_profile_refresh_in_progress():
            self._json(
                HTTPStatus.ACCEPTED,
                {
                    "status": "in_progress",
                    "detail": "Environment profile refresh is already running.",
                    "refresh": _environment_profile_refresh_status(),
                },
            )
            return
        threading.Thread(target=_run_environment_profile_wipe_refresh, daemon=True).start()
        self._json(
            HTTPStatus.ACCEPTED,
            {
                "status": "started",
                "detail": "Wiping current Data Domains artifacts and starting a fresh rebuild.",
                "refresh": _environment_profile_refresh_status(),
            },
        )

    def _stream_ollama_logs(self, parsed: Any) -> None:
        query = parse_qs(parsed.query)
        if not self._require_ops_role(query):
            return

        config = _remote_log_config_status()
        if config["mode"] != "remote_windows":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(
                format_sse(
                    "error",
                    {
                        "type": "error",
                        "code": "source_disabled",
                        "message": "OLLAMA_LOG_SOURCE is not set to remote_windows",
                        "ts": "now",
                    },
                )
            )
            self.wfile.flush()
            return

        params = StreamParams.from_values(
            query.get("tail", ["200"])[0],
            query.get("level", [""])[0],
            query.get("grep", [""])[0],
        )

        source = LOG_SOURCE_REGISTRY.get_source(params)
        if not config["config_ok"]:
            missing = ", ".join(config["missing_vars"])
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.write(
                format_sse(
                    "error",
                    {
                        "type": "error",
                        "code": "missing_config",
                        "message": f"Set required server env vars for remote_windows: {missing}",
                        "ts": "now",
                        "missing_vars": config["missing_vars"],
                    },
                )
            )
            self.wfile.flush()
            return

        remote_url = os.getenv("OLLAMA_LOG_REMOTE_URL", "").strip()
        remote_token = os.getenv("OLLAMA_LOG_REMOTE_TOKEN", "").strip()
        health_url = get_remote_health_url(remote_url)
        health_ok, health_detail = check_remote_health(health_url, remote_token, timeout=4.0)

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        sid, sub_q = source.subscribe()
        try:
            if health_ok:
                self.wfile.write(format_sse("status", {"type": "status", "state": "connected", "detail": "health_ok"}))
            else:
                self.wfile.write(
                    format_sse(
                        "error",
                        {
                            "type": "error",
                            "code": "remote_health_check_failed",
                            "message": redact_secrets(health_detail),
                            "ts": "now",
                        },
                    )
                )
                self.wfile.write(
                    format_sse(
                        "status",
                        {"type": "status", "state": "reconnecting", "detail": "waiting_for_remote_source"},
                    )
                )
            self.wfile.flush()

            replay_count = min(200, params.tail)
            for entry in source.get_recent(replay_count):
                payload = dict(entry)
                payload["line"] = redact_secrets(str(payload.get("line", "")))
                self.wfile.write(format_sse("log", payload))
            self.wfile.flush()

            while True:
                try:
                    event = sub_q.get(timeout=15.0)
                except queue.Empty:
                    self.wfile.write(b": heartbeat\\n\\n")
                    self.wfile.flush()
                    continue

                event_type = str(event.get("type", "log"))
                payload = dict(event)
                if "line" in payload:
                    payload["line"] = redact_secrets(str(payload.get("line", "")))
                self.wfile.write(format_sse(event_type, payload))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            source.unsubscribe(sid)

    def _ops_ollama_logs_health(self, parsed: Any) -> None:
        query = parse_qs(parsed.query)
        if not self._require_ops_role(query):
            return

        config = _remote_log_config_status()
        remote_health_ok = False
        remote_health_detail = "remote health check skipped"
        if config["mode"] == "remote_windows" and config["config_ok"]:
            remote_url = os.getenv("OLLAMA_LOG_REMOTE_URL", "").strip()
            remote_token = os.getenv("OLLAMA_LOG_REMOTE_TOKEN", "").strip()
            health_url = get_remote_health_url(remote_url)
            remote_health_ok, remote_health_detail = check_remote_health(health_url, remote_token, timeout=4.0)
            remote_health_detail = redact_secrets(remote_health_detail)

        status_code = 200 if (config["config_ok"] and (config["mode"] != "remote_windows" or remote_health_ok)) else 503
        self._json(
            status_code,
            {
                "mode": config["mode"],
                "config_ok": config["config_ok"],
                "missing_vars": config["missing_vars"],
                "required_vars": config["required_vars"],
                "remote_health_ok": remote_health_ok,
                "remote_health_detail": remote_health_detail,
            },
        )

    def _api_environment_profile(self) -> None:
        payload = _load_environment_profile_payload()
        if not payload:
            self._json(
                HTTPStatus.NOT_FOUND,
                {
                    "error": "environment_profile_missing",
                    "path": str(ENV_PROFILE_PATH),
                    "hint": "Run make env-profile-refresh",
                },
            )
            return
        self._json(HTTPStatus.OK, payload)

    def _api_environment_hint(self, parsed: Any) -> None:
        query = parse_qs(parsed.query)
        question = str(query.get("question", [""])[0]).strip()
        if not question:
            self._json(HTTPStatus.OK, {"hints": [], "question": ""})
            return
        hints = suggest_domains_for_question(question)
        self._json(
            HTTPStatus.OK,
            {
                "question": question,
                "hints": hints,
                "profile_path": str(ENV_PROFILE_PATH),
            },
        )

    def _api_case_node(self, parsed: Any) -> None:
        query = parse_qs(parsed.query)
        case_id = str(query.get("case_id", [""])[0]).strip()
        node_id = str(query.get("node_id", [""])[0]).strip()
        if not case_id or not node_id:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "case_id and node_id are required"})
            return
        result = load_case_node(case_id, node_id)
        if not result:
            self._json(HTTPStatus.NOT_FOUND, {"error": "case node not found"})
            return
        self._json(HTTPStatus.OK, {"case_id": case_id, "node_id": node_id, "result": result})

    def _api_cases(self, parsed: Any) -> None:
        query = parse_qs(parsed.query)
        try:
            limit = max(1, min(100, int(str(query.get("limit", ["30"])[0]))))
        except Exception:
            limit = 30
        items = list_recent_cases(limit=limit)
        self._json(HTTPStatus.OK, {"items": items, "backend": case_store_backend()})

    def _api_case(self, parsed: Any) -> None:
        query = parse_qs(parsed.query)
        case_id = str(query.get("case_id", [""])[0]).strip()
        if not case_id:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "case_id is required"})
            return
        payload = load_case(case_id)
        if not payload:
            self._json(HTTPStatus.NOT_FOUND, {"error": "case not found"})
            return
        self._json(HTTPStatus.OK, {"case": payload, "backend": case_store_backend()})

    def _api_mcp_chat(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        data = json.loads(raw.decode("utf-8")) if raw else {}
        question = str(data.get("message", "")).strip()
        if not question:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "message is required"})
            return

        session_id = str(data.get("session_id", "")).strip()
        # MCP chat is intentionally non-artifact mode: interactive ask/answer only.
        payload = run_multi_model_soc(question, session_id=session_id, write_artifact=False)
        result = payload.get("result", {}) if isinstance(payload, dict) else {}
        if not isinstance(result, dict):
            result = {}
        mitre_bundle = _mitre_attack_bundle(result)
        result["mitre_attack"] = mitre_bundle
        result_compact = dict(result)
        result_compact.pop("tdir_case", None)

        selected_tool = str(result.get("selected_tool", "")).strip()
        query_args = result.get("query_args", {}) if isinstance(result.get("query_args"), dict) else {}
        selected_spl_details = result.get("selected_spl_details", [])
        if not isinstance(selected_spl_details, list):
            selected_spl_details = []
        latest_spl = selected_spl_details[-1] if selected_spl_details and isinstance(selected_spl_details[-1], dict) else {}
        spl_writer_model = str(latest_spl.get("writer_model", "")).strip() or "unknown"
        spl_run_time_ms = latest_spl.get("execution_ms", None)
        if spl_run_time_ms is None:
            spl_run_time_ms = result.get("node_timings_ms", {}).get("run_tool") if isinstance(result.get("node_timings_ms"), dict) else None
        sample_rows: list[dict[str, Any]] = []
        sample_source = "none"
        sample_error = ""
        if selected_tool == "splunk_run_query" and str(query_args.get("query", "")).strip():
            rerun_args = dict(query_args)
            try:
                row_limit = int(rerun_args.get("row_limit", 25))
            except Exception:
                row_limit = 25
            rerun_args["row_limit"] = max(1, min(50, row_limit))
            try:
                rerun = run_splunk_query_args(
                    rerun_args,
                    intent=str(result.get("intent", "mcp_chat")).strip() or "mcp_chat",
                    summary_hint="mcp chat sample rows",
                )
                rows = rerun.get("structured", {}).get("results", []) if isinstance(rerun, dict) else []
                if isinstance(rows, list):
                    sample_rows = [r for r in rows if isinstance(r, dict)][:25]
                    sample_source = "splunk_run_query_rerun"
            except Exception as exc:
                sample_error = f"{type(exc).__name__}: {exc}"

        if not sample_rows:
            evidence = result.get("evidence", {}) if isinstance(result.get("evidence"), dict) else {}
            top = evidence.get("top_entities", []) if isinstance(evidence.get("top_entities"), list) else []
            sample_rows = [r for r in top if isinstance(r, dict)]
            if sample_rows:
                sample_source = "pipeline_evidence_top_entities"
        domain_hints = suggest_domains_for_question(question, max_indexes=4, max_sourcetypes_per_index=4)

        self._json(
            HTTPStatus.OK,
            {
                "question": question,
                "summary": str(result.get("summary", "")),
                "intent": result.get("intent"),
                "supported": result.get("supported"),
                "selected_tool": selected_tool,
                "query_args": query_args,
                "rows_returned": result.get("rows_returned"),
                "total_rows": result.get("total_rows"),
                "spl_writer_model": spl_writer_model,
                "spl_run_time_ms": spl_run_time_ms,
                "rag_enabled": bool(result.get("rag_enabled", False)),
                "rag_max_chars": result.get("rag_max_chars"),
                "domain_hints": domain_hints,
                "sample_rows": sample_rows,
                "sample_rows_source": sample_source,
                "sample_rows_error": sample_error,
                "splunk_search_url_base": _splunk_search_url_base(),
                "selected_spl_details": selected_spl_details,
                "result": result_compact,
                "meta": payload.get("meta", {}) if isinstance(payload, dict) else {},
            },
        )

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path in {"/favicon.ico", "/favicon.svg"}:
            body = FAVICON_SVG.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/login":
            self._handle_login_get()
            return
        if parsed.path == "/setup/first-run":
            self._handle_first_run_get()
            return
        if parsed.path == "/logout":
            self._handle_logout_get()
            return

        if _first_run_setup_required():
            self._redirect("/setup/first-run")
            return

        if parsed.path.startswith("/api/"):
            if not self._require_auth(api_mode=True):
                return
        else:
            if not self._require_auth(api_mode=False):
                return

        if parsed.path == "/api/ops/ollama/logs/stream":
            self._stream_ollama_logs(parsed)
            return
        if parsed.path == "/api/ops/ollama/logs/health":
            self._ops_ollama_logs_health(parsed)
            return
        if parsed.path == "/api/environment/profile":
            self._api_environment_profile()
            return
        if parsed.path == "/api/environment/hint":
            self._api_environment_hint(parsed)
            return
        if parsed.path == "/api/case-node":
            self._api_case_node(parsed)
            return
        if parsed.path == "/api/cases":
            self._api_cases(parsed)
            return
        if parsed.path == "/api/case":
            self._api_case(parsed)
            return
        if parsed.path == "/api/config/runtime":
            self._api_config_runtime_get()
            return
        if parsed.path == "/api/config/runtime-secret":
            self._api_config_runtime_secret_get(parsed)
            return
        if parsed.path == "/api/config/dependencies":
            self._api_config_dependencies_get()
            return
        if parsed.path == "/api/config/mcp-probe":
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED, "POST required")
            return
        if parsed.path == "/api/config/users":
            self._api_config_users_get()
            return
        if parsed.path == "/api/config/audit":
            self._api_query_audit_get()
            return
        if parsed.path == "/api/session/onboarding":
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED, "POST required")
            return
        if parsed.path == "/api/config/env-refresh":
            self._api_config_env_refresh_get()
            return
        if parsed.path == "/api/environment/wipe-refresh":
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED, "POST required")
            return
        if parsed.path == "/api/config/personalize":
            self._api_config_personalize_get()
            return
        if parsed.path == "/api/config/local-learning":
            self._api_config_local_learning_get()
            return
        if parsed.path == "/api/config/validate":
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED, "POST required")
            return

        if parsed.path == "/":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/mcp")
            self.end_headers()
            return

        if parsed.path == "/investigation":
            body = APP_HTML.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/docs":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/docs/view?path=whitepapers/project_one_page_white_paper.md")
            self.end_headers()
            return

        if parsed.path == "/docs/index":
            self._html(HTTPStatus.OK, _docs_index_body(), title="Documentation Portal", nav_active="control")
            return

        if parsed.path == "/docs/view":
            path_value = parse_qs(parsed.query).get("path", [""])[0]
            self._html(HTTPStatus.OK, _docs_view_body(path_value), title="Documentation Viewer", nav_active="control")
            return

        if parsed.path == "/docs/raw":
            path_value = parse_qs(parsed.query).get("path", [""])[0]
            doc_path = _safe_docs_path(path_value)
            if doc_path is None:
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            body = doc_path.read_bytes()
            ctype = "text/plain; charset=utf-8"
            if doc_path.suffix.lower() == ".json":
                ctype = "application/json; charset=utf-8"
            elif doc_path.suffix.lower() == ".csv":
                ctype = "text/csv; charset=utf-8"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/favicon-preview":
            self._html(HTTPStatus.OK, _favicon_preview_body(), title="A.G.E.N.T. Smith Favicon Preview", nav_active="control")
            return

        if parsed.path == "/artifacts/raw":
            path_value = parse_qs(parsed.query).get("path", [""])[0]
            rel = Path(path_value)
            target = (ARTIFACTS_ROOT / rel).resolve()
            try:
                target.relative_to(ARTIFACTS_ROOT.resolve())
            except Exception:
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            if not target.exists() or not target.is_file():
                self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
                return
            body = target.read_bytes()
            ctype = "text/plain; charset=utf-8"
            if target.suffix.lower() == ".json":
                ctype = "application/json; charset=utf-8"
            elif target.suffix.lower() == ".csv":
                ctype = "text/csv; charset=utf-8"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/architecture":
            self._html(HTTPStatus.OK, _architecture_page_body(), title="Architecture Graph", nav_active="control")
            return

        if parsed.path == "/langgraph-graph":
            self._html(HTTPStatus.OK, _langgraph_graph_page_body(), title="LangGraph Graph", nav_active="control")
            return

        if parsed.path == "/artifacts":
            self._html(HTTPStatus.OK, _artifacts_page_body(), title="Artifact Repository", nav_active="artifacts")
            return

        if parsed.path == "/environment":
            if _running_in_container() and not _can_show_environment_page():
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/configure")
                self.end_headers()
                return
            self._html(HTTPStatus.OK, _environment_page_body(), title="Data Domains", nav_active="environment")
            return

        if parsed.path == "/configure":
            if not self._require_ops_page():
                return
            self._html(HTTPStatus.OK, _configure_page_body(), title="Configuration", nav_active="control")
            return

        if parsed.path == "/learning":
            if not self._require_ops_page():
                return
            self._html(HTTPStatus.OK, _learning_page_body(), title="SPL Optimization AI Engine", nav_active="control")
            return

        if parsed.path == "/spl-assets":
            if not self._require_ops_page():
                return
            self._html(HTTPStatus.OK, _spl_asset_repository_page_body(), title="SPL Asset Repository", nav_active="control")
            return

        if parsed.path == "/cases":
            self._html(HTTPStatus.OK, self._cases_workspace_page_body(), title="Case Workspace", nav_active="control")
            return

        if parsed.path == "/users":
            if not self._require_admin_page():
                return
            self._html(HTTPStatus.OK, _users_page_body(), title="Users", nav_active="control")
            return

        if parsed.path == "/mcp":
            self._html(HTTPStatus.OK, _mcp_page_body(), title="Splunk MCP Chat", nav_active="mcp")
            return

        if parsed.path == "/docs/architecture":
            self.send_response(HTTPStatus.MOVED_PERMANENTLY)
            self.send_header("Location", "/architecture")
            self.end_headers()
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            self._handle_login_post()
            return
        if parsed.path == "/setup/first-run":
            self._handle_first_run_post()
            return

        if _first_run_setup_required():
            self._json(HTTPStatus.PRECONDITION_FAILED, {"error": "first_run_setup_required", "redirect": "/setup/first-run"})
            return

        if parsed.path == "/api/mcp/chat":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_mcp_chat()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return
        if parsed.path == "/api/config/runtime":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_config_runtime_post()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return
        if parsed.path == "/api/config/users":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_config_users_post()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return
        if parsed.path == "/api/config/validate":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_config_validate_post()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return
        if parsed.path == "/api/config/mcp-probe":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_config_mcp_probe_post()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return
        if parsed.path == "/api/config/personalize":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_config_personalize_post()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return
        if parsed.path == "/api/config/local-learning":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_config_local_learning_post()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return
        if parsed.path == "/api/config/env-refresh":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_config_env_refresh_post()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return
        if parsed.path == "/api/environment/wipe-refresh":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_environment_wipe_refresh_post()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return
        if parsed.path == "/api/session/onboarding":
            if not self._require_auth(api_mode=True):
                return
            try:
                self._api_session_onboarding_post()
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(exc).__name__}: {exc}"})
            return

        if parsed.path != "/api/ask":
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return
        if not self._require_auth(api_mode=True):
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        try:
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8")) if raw else {}
            question = str(data.get("question", "")).strip()
            if not question:
                self._json(400, {"error": "question is required"})
                return
            session_id = str(data.get("session_id", "")).strip()
            case_id = str(data.get("case_id", "")).strip()
            parent_node_id = str(data.get("parent_node_id", "")).strip()
            max_steps = data.get("max_steps", 3)
            if not isinstance(max_steps, int):
                try:
                    max_steps = int(max_steps)
                except Exception:
                    max_steps = 3
            write_artifact = bool(data.get("write_artifact", True))
            approved_deeper_investigation = bool(data.get("approved_deeper_investigation", False))
            continuation_state = data.get("continuation_state", None)
            pivot_context = data.get("pivot_context", None)
            pivot_candidate = data.get("pivot_candidate", None)
            if isinstance(pivot_context, dict):
                case_id = case_id or str(pivot_context.get("case_id", "")).strip()
                parent_node_id = parent_node_id or str(pivot_context.get("current_node_id", "")).strip()

            pipeline = str(data.get("pipeline", "multi_model")).strip().lower()
            if isinstance(pivot_context, dict) and isinstance(pivot_candidate, dict):
                result = _run_structured_pivot_investigation(
                    question=question,
                    pivot_context=pivot_context,
                    pivot_candidate=pivot_candidate,
                    session_id=session_id,
                    write_artifact=write_artifact,
                )
            elif pipeline == "agentic":
                result = run_agentic_investigation(
                    question,
                    max_steps=max_steps,
                    session_id=session_id,
                    write_artifact=write_artifact,
                    approved_deeper_investigation=approved_deeper_investigation,
                    continuation_state=continuation_state if isinstance(continuation_state, dict) else None,
                )
            else:
                result = run_multi_model_soc(
                    question,
                    session_id=session_id,
                    write_artifact=write_artifact,
                )
            result_body = result.get("result", {}) if isinstance(result, dict) else {}
            if not isinstance(result_body, dict):
                result_body = {}
            user = self._authenticated_user() or {}
            selected_tool = str(result_body.get("selected_tool", "")).strip()
            selected_spl_details = result_body.get("selected_spl_details", [])
            if not isinstance(selected_spl_details, list):
                selected_spl_details = []
            latest_spl = selected_spl_details[-1] if selected_spl_details and isinstance(selected_spl_details[-1], dict) else {}
            executed_query = ""
            query_args = result_body.get("query_args", {}) if isinstance(result_body.get("query_args"), dict) else {}
            if str(latest_spl.get("query", "")).strip():
                executed_query = str(latest_spl.get("query", "")).strip()
            elif str(query_args.get("query", "")).strip():
                executed_query = str(query_args.get("query", "")).strip()
            sample_rows: list[dict[str, Any]] = []
            sample_source = "none"
            sample_error = ""
            if selected_tool == "splunk_run_query" and str(query_args.get("query", "")).strip():
                rerun_args = dict(query_args)
                try:
                    row_limit = int(rerun_args.get("row_limit", 25))
                except Exception:
                    row_limit = 25
                rerun_args["row_limit"] = max(1, min(50, row_limit))
                try:
                    rerun = run_splunk_query_args(
                        rerun_args,
                        intent=str(result_body.get("intent", "investigation_ui")).strip() or "investigation_ui",
                        summary_hint="investigation ui sample rows",
                    )
                    rows = rerun.get("structured", {}).get("results", []) if isinstance(rerun, dict) else []
                    if isinstance(rows, list):
                        sample_rows = [r for r in rows if isinstance(r, dict)][:25]
                        sample_source = "splunk_run_query_rerun"
                except Exception as exc:
                    sample_error = f"{type(exc).__name__}: {exc}"

            if not sample_rows:
                evidence = result_body.get("evidence", {}) if isinstance(result_body.get("evidence"), dict) else {}
                top = evidence.get("top_entities", []) if isinstance(evidence.get("top_entities"), list) else []
                sample_rows = [r for r in top if isinstance(r, dict)]
                if sample_rows:
                    sample_source = "pipeline_evidence_top_entities"
            _append_query_audit(
                {
                    "ts_epoch": int(time.time()),
                    "username": str(user.get("username", "unknown")),
                    "role": str(user.get("role", "unknown")),
                    "pipeline": pipeline,
                    "question": question,
                    "selected_tool": selected_tool,
                    "intent": result_body.get("intent"),
                    "rows_returned": result_body.get("rows_returned"),
                    "total_rows": result_body.get("total_rows"),
                    "query": executed_query,
                    "session_id": session_id,
                }
            )
            if isinstance(result, dict):
                result = dict(result)
                result_body = result.get("result", {}) if isinstance(result.get("result"), dict) else {}
                if isinstance(result_body, dict):
                    result_body = dict(result_body)
                    mitre_bundle = _mitre_attack_bundle(result_body)
                    mitre_bundle["validation"] = _mitre_attack_validate(result_body, mitre_bundle)
                    result_body["mitre_attack"] = mitre_bundle
                    result_body["matching_active_spl_assets"] = _active_spl_asset_matches_for_intent(result_body.get("intent", ""))
                    result["result"] = result_body
                    meta = result.get("meta", {}) if isinstance(result.get("meta"), dict) else {}
                    artifact_path = str(meta.get("artifact", "")).strip()
                    if artifact_path:
                        _persist_mitre_bundle_to_artifact(artifact_path, mitre_bundle)
                    pivot_context_payload = _build_structured_pivot_context(result_body, sample_rows)
                    result_body["pivot_context"] = pivot_context_payload
                    result_body["sample_rows"] = sample_rows
                    result_body["sample_rows_source"] = sample_source
                    result_body["splunk_search_url_base"] = _splunk_search_url_base()
                    previous_graph_state = pivot_context.get("graph_case_state") if isinstance(pivot_context, dict) and isinstance(pivot_context.get("graph_case_state"), dict) else None
                    graph_case_state_payload = _build_graph_case_state_payload(
                        question=question,
                        result_body=result_body,
                        sample_rows=sample_rows,
                        case_id=case_id or "",
                        parent_node_id=parent_node_id or "",
                        node_type="pivot" if isinstance(pivot_context, dict) and isinstance(pivot_candidate, dict) else "investigation",
                        previous_state=previous_graph_state,
                    )
                    result_body["graph_case_state"] = graph_case_state_payload
                    case_context_payload = persist_case_result(
                        session_id=session_id,
                        question=question,
                        result_body=result_body,
                        graph_case_state=graph_case_state_payload,
                        case_id=case_id or None,
                        parent_node_id=parent_node_id or None,
                        node_type="pivot" if isinstance(pivot_context, dict) and isinstance(pivot_candidate, dict) else "investigation",
                    )
                    result_body["case_context"] = case_context_payload
                    result_body["graph_case_state"]["case_id"] = case_context_payload.get("case_id", "")
                    result_body["graph_case_state"]["current_node_id"] = case_context_payload.get("node_id", "")
                    result_body["graph_case_state"]["parent_node_id"] = case_context_payload.get("parent_node_id", "")
                    if isinstance(result_body.get("pivot_context"), dict):
                        result_body["pivot_context"]["case_id"] = case_context_payload.get("case_id", "")
                        result_body["pivot_context"]["current_node_id"] = case_context_payload.get("node_id", "")
                        result_body["pivot_context"]["graph_case_state"] = result_body.get("graph_case_state", {})
                    artifact_path = str(meta.get("artifact", "")).strip()
                    if artifact_path:
                        _persist_result_updates_to_artifact(
                            artifact_path,
                            {
                                "pivot_context": result_body.get("pivot_context", {}),
                                "case_context": case_context_payload,
                                "graph_case_state": result_body.get("graph_case_state", {}),
                            },
                        )
                result["sample_rows"] = sample_rows
                result["sample_rows_source"] = sample_source
                result["sample_rows_error"] = sample_error
                result["splunk_search_url_base"] = _splunk_search_url_base()
            self._json(200, result)
        except Exception as exc:
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local SOC web UI server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--tls-cert-file", default=os.getenv("AGTSMITH_TLS_CERT_FILE", "").strip())
    parser.add_argument("--tls-key-file", default=os.getenv("AGTSMITH_TLS_KEY_FILE", "").strip())
    args = parser.parse_args()

    if _auth_enabled():
        users = _load_auth_users()
        if not users:
            print("Startup validation failed for UI auth.")
            print("No auth users configured. Set SOC_UI_AUTH_USERS_JSON or SOC_UI_AUTH_USERNAME/SOC_UI_AUTH_PASSWORD.")
            return 2
        if "analyst" in users and users["analyst"].get("password") == "changeme123!":
            print("WARNING: default UI auth credential detected (analyst/changeme123!). Change it in config/ui.env.")

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    scheme = "http"
    if args.tls_cert_file and args.tls_key_file:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=args.tls_cert_file, keyfile=args.tls_key_file)
        httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    print(f"Web UI running at {scheme}://{args.host}:{args.port}")
    if scheme == "https":
        print(f"TLS cert: {args.tls_cert_file}")
        print(f"TLS key: {args.tls_key_file}")
    else:
        print("TLS disabled. Set AGTSMITH_TLS_CERT_FILE and AGTSMITH_TLS_KEY_FILE to enable HTTPS.")
    print(f"UI auth enabled: {_auth_enabled()}")
    print("Default landing: /mcp")
    print("Investigation UI: /investigation")
    print("Docs portal: /docs")
    print("Architecture graph: /architecture")
    print("Splunk MCP chat: /mcp")
    print("Artifact repository: /artifacts")
    print("Press Ctrl+C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
