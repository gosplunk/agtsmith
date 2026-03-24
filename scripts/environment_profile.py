#!/usr/bin/env python3
"""Environment awareness helpers for index/sourcetype personalization."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

PROFILE_PATH_DEFAULT = Path("artifacts/environment/environment_profile_latest.json")
PROFILE_PATH_LEGACY = Path("docs/logs/environment_profile_latest.json")

SRC_PRETRAINED = "https://docs.splunk.com/Documentation/Splunk/9.4.2/Data/Listofpretrainedsourcetypes"
SRC_WIN_ADDON = "https://docs.splunk.com/Documentation/WindowsAddOn/8.1.2/User/SourcetypesandCIMdatamodelinfo"
SRC_WIN_HOSTMON = "https://docs.splunk.com/Documentation/Splunk/9.4.2/Data/MonitorWindowshostinformation"
SRC_ADDON_NAMING = "https://docs.splunk.com/Documentation/AddOns/released/Overview/Sourcetypes"
SRC_UNIX_ADDON = "https://docs.splunk.com/Documentation/UnixAddOn/6.0.0/User/SourcetypesandCIMdatamodelinfo"

KNOWN_SOURCETYPE_SEMANTICS: dict[str, dict[str, Any]] = {
    "_audit": {
        "description": "Splunk audit trail for auth, role, and search actions.",
        "use_cases": ["failed_login_activity", "splunk_admin_activity", "search_audit"],
        "field_aliases": {
            "src_ip": ["src", "clientip", "ip", "host"],
            "username": ["user", "username"],
        },
        "confidence": "high",
        "sources": [SRC_PRETRAINED],
    },
    "audittrail": {
        "description": "Splunk audit trail events (auth, search, role/config actions).",
        "use_cases": ["failed_login_activity", "splunk_admin_activity", "search_audit"],
        "field_aliases": {
            "src_ip": ["src", "clientip", "ip", "host"],
            "username": ["user", "username"],
        },
        "confidence": "high",
        "sources": [SRC_PRETRAINED],
    },
    "access_combined": {
        "description": "Apache/Nginx style web access logs.",
        "use_cases": ["apache_access_top_ips", "apache_404_spike", "web_scanning"],
        "field_aliases": {
            "src_ip": ["clientip", "src", "ip"],
            "status_code": ["status", "sc_status"],
            "url_path": ["uri_path", "uri", "url"],
        },
        "confidence": "high",
        "sources": [SRC_PRETRAINED],
    },
    "apache_error": {
        "description": "Apache HTTP server error log events.",
        "use_cases": ["apache_error_spike", "web_app_faults", "web_attack_signals"],
        "field_aliases": {"src_ip": ["clientip", "src", "ip"], "message": ["_raw", "msg"]},
        "confidence": "medium",
        "sources": [SRC_PRETRAINED, SRC_ADDON_NAMING],
    },
    "auth.log": {
        "description": "Linux authentication log stream (ssh/sudo/su/pam).",
        "use_cases": ["linux_auth_failures", "linux_privilege_escalation"],
        "field_aliases": {
            "src_ip": ["src", "rhost", "ip", "clientip"],
            "username": ["user", "account", "uid"],
        },
        "confidence": "high",
        "sources": [SRC_PRETRAINED, SRC_UNIX_ADDON],
    },
    "syslog": {
        "description": "Generic syslog events from Linux/Unix services.",
        "use_cases": ["linux_system_health", "service_error_detection", "timeline_context"],
        "field_aliases": {"host": ["host"], "process": ["process", "proc"], "message": ["_raw", "msg"]},
        "confidence": "high",
        "sources": [SRC_PRETRAINED],
    },
    "dmesg": {
        "description": "Kernel ring-buffer/system boot and device messages.",
        "use_cases": ["kernel_error_hunt", "driver_instability", "boot_troubleshooting"],
        "field_aliases": {"host": ["host"], "message": ["_raw", "msg"]},
        "confidence": "high",
        "sources": [SRC_PRETRAINED],
    },
    "ufw": {
        "description": "Uncomplicated Firewall (UFW) events.",
        "use_cases": ["blocked_connection_analysis", "network_perimeter_triage"],
        "field_aliases": {"src_ip": ["SRC", "src", "src_ip", "ip"], "dest_ip": ["DST", "dest", "dest_ip"]},
        "confidence": "medium",
        "sources": [SRC_UNIX_ADDON],
    },
    "fail2ban.log": {
        "description": "Fail2ban ban/unban and authentication protection events.",
        "use_cases": ["bruteforce_protection_effectiveness", "banned_ip_review"],
        "field_aliases": {"src_ip": ["ip", "src", "src_ip"], "action": ["action", "status"]},
        "confidence": "medium",
        "sources": [SRC_UNIX_ADDON],
    },
    "fail2ban-2": {
        "description": "Fail2ban log variant (line-broken/alt parser form).",
        "use_cases": ["bruteforce_protection_effectiveness", "banned_ip_review"],
        "field_aliases": {"src_ip": ["ip", "src", "src_ip"], "action": ["action", "status"]},
        "confidence": "medium",
        "sources": [SRC_UNIX_ADDON],
    },
    "xmlwineventlog": {
        "description": "Windows Event Log in XML channel format.",
        "use_cases": ["windows_auth_failures", "windows_process_creation", "windows_privilege_events"],
        "field_aliases": {
            "username": ["TargetUserName", "SubjectUserName", "user", "Account_Name"],
            "src_ip": ["IpAddress", "Source_Network_Address", "src"],
            "event_code": ["EventCode", "EventID"],
        },
        "confidence": "high",
        "sources": [SRC_WIN_ADDON],
    },
    "linux_secure": {
        "description": "Linux authentication and sudo/su events from secure/auth logs.",
        "use_cases": ["linux_auth_failures", "linux_privilege_escalation"],
        "field_aliases": {
            "src_ip": ["src", "src_ip", "rhost", "ip"],
            "username": ["user", "uid", "account"],
        },
        "confidence": "high",
        "sources": [SRC_PRETRAINED],
    },
    "wineventlog:security": {
        "description": "Windows Security event log (legacy source type casing).",
        "use_cases": ["windows_auth_failures", "windows_privilege_events"],
        "field_aliases": {
            "username": ["TargetUserName", "user", "Account_Name"],
            "src_ip": ["IpAddress", "Source_Network_Address", "src"],
        },
        "confidence": "high",
        "sources": [SRC_WIN_ADDON],
    },
    "xmlwineventlog:security": {
        "description": "Windows Security event log in XML format.",
        "use_cases": ["windows_auth_failures", "windows_privilege_events"],
        "field_aliases": {
            "username": ["TargetUserName", "user", "Account_Name"],
            "src_ip": ["IpAddress", "Source_Network_Address", "src"],
        },
        "confidence": "high",
        "sources": [SRC_WIN_ADDON],
    },
    "winhostmon": {
        "description": "Windows host monitor inventory/host metadata events.",
        "use_cases": ["host_inventory_context", "os_state_validation", "asset_enrichment"],
        "field_aliases": {"host": ["host"], "os": ["os", "family", "version"]},
        "confidence": "high",
        "sources": [SRC_WIN_HOSTMON, SRC_WIN_ADDON],
    },
    "winnetmon": {
        "description": "Windows network monitoring events from WinNetMon input.",
        "use_cases": ["network_connection_triage", "lateral_movement_hunt"],
        "field_aliases": {"src_ip": ["src", "src_ip", "ip"], "dest_ip": ["dest", "dest_ip", "d_ip"]},
        "confidence": "medium",
        "sources": [SRC_WIN_ADDON],
    },
    "script:listeningports": {
        "description": "Scripted Windows listening port inventory snapshots.",
        "use_cases": ["unexpected_exposure_review", "service_hardening_validation"],
        "field_aliases": {"host": ["host"], "port": ["port", "local_port"], "process": ["process", "process_name"]},
        "confidence": "medium",
        "sources": [SRC_WIN_ADDON],
    },
    "script:installedapps": {
        "description": "Scripted Windows installed software inventory snapshots.",
        "use_cases": ["asset_baselining", "software_risk_review"],
        "field_aliases": {"host": ["host"], "app_name": ["name", "display_name"], "version": ["version"]},
        "confidence": "medium",
        "sources": [SRC_WIN_ADDON],
    },
}


def load_environment_profile(path: str | Path = PROFILE_PATH_DEFAULT) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        # Backward-compatible fallback for older artifact location.
        if p == PROFILE_PATH_DEFAULT and PROFILE_PATH_LEGACY.exists():
            p = PROFILE_PATH_LEGACY
        else:
            return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _normalize_sourcetype(name: str) -> str:
    return (name or "").strip().lower()


def _semantic_for_sourcetype(sourcetype: str) -> dict[str, Any]:
    key = _normalize_sourcetype(sourcetype)
    if key in KNOWN_SOURCETYPE_SEMANTICS:
        return KNOWN_SOURCETYPE_SEMANTICS[key]
    if key.startswith("xmlwineventlog"):
        return KNOWN_SOURCETYPE_SEMANTICS["xmlwineventlog"]
    if key.startswith("perfmomk:") or key.startswith("perfmonmk:") or key.startswith("perfmon:"):
        return {
            "description": "Windows Performance Monitor counter metrics.",
            "use_cases": ["host_performance_triage", "capacity_anomaly_detection"],
            "field_aliases": {"counter": ["counter", "object"], "value": ["Value", "value"]},
            "confidence": "high",
            "sources": [SRC_WIN_ADDON],
        }
    if key.startswith("script:"):
        return {
            "description": "Scripted inventory/telemetry events from endpoint data collection.",
            "use_cases": ["asset_baselining", "host_state_context"],
            "field_aliases": {"host": ["host"], "message": ["_raw", "msg"]},
            "confidence": "medium",
            "sources": [SRC_ADDON_NAMING],
        }
    if key.startswith("splunkd") or key.startswith("splunk_") or key.startswith("splunk"):
        return {
            "description": "Splunk platform internal/service telemetry logs.",
            "use_cases": ["splunk_health_monitoring", "search_pipeline_troubleshooting", "platform_security_audit"],
            "field_aliases": {"component": ["component"], "host": ["host"], "message": ["_raw", "msg"]},
            "confidence": "high",
            "sources": [SRC_PRETRAINED],
        }
    if key.startswith("node:sidecar:") or key.startswith("sup-pkg-") or key == "node:supervisor" or key == "supervisor-2":
        return {
            "description": "Sidecar/supervisor service logs for Splunk platform components.",
            "use_cases": ["platform_component_health", "collector_pipeline_diagnostics"],
            "field_aliases": {"component": ["component", "service"], "host": ["host"], "message": ["_raw", "msg"]},
            "confidence": "medium",
            "sources": [SRC_ADDON_NAMING],
        }
    if key.startswith("ds"):
        return {
            "description": "Deployment server/client management telemetry.",
            "use_cases": ["forwarder_deployment_audit", "configuration_distribution_health"],
            "field_aliases": {"host": ["host"], "client": ["client", "server"]},
            "confidence": "medium",
            "sources": [SRC_PRETRAINED],
        }
    if key.endswith("-too_small"):
        return {
            "description": "Ingested file marker indicating minimal/truncated content variant.",
            "use_cases": ["input_health_monitoring", "parser_quality_review"],
            "field_aliases": {"source": ["source"], "host": ["host"]},
            "confidence": "medium",
            "sources": [SRC_ADDON_NAMING],
        }
    if key in {"df", "interfaces", "ps", "top"}:
        return {
            "description": "Unix/Linux host telemetry metrics from scripted inputs.",
            "use_cases": ["host_performance_triage", "capacity_anomaly_detection"],
            "field_aliases": {"host": ["host"], "metric": ["metric", "value"]},
            "confidence": "high",
            "sources": [SRC_UNIX_ADDON],
        }
    if key in {"postgresql-16-main", "amazon-ssm-agent", "cloud-init-2", "cloud-init-output", "mail-3"}:
        return {
            "description": "Linux service/application logs from common system daemons.",
            "use_cases": ["service_failure_triage", "operational_timeline_context"],
            "field_aliases": {"host": ["host"], "message": ["_raw", "msg"]},
            "confidence": "medium",
            "sources": [SRC_UNIX_ADDON],
        }
    if key in {"secure_gateway_app_internal_log", "mcp_server", "mongod"}:
        return {
            "description": "Splunk app or data service logs used for platform operations.",
            "use_cases": ["app_health_diagnostics", "service_error_timeline"],
            "field_aliases": {"host": ["host"], "message": ["_raw", "msg"]},
            "confidence": "medium",
            "sources": [SRC_ADDON_NAMING],
        }
    if key.startswith("dpkg-") or key.startswith("unattended-upgrades"):
        return {
            "description": "Linux package-management lifecycle events.",
            "use_cases": ["patching_audit", "change_timeline_validation"],
            "field_aliases": {"host": ["host"], "package": ["package", "name"], "action": ["action", "status"]},
            "confidence": "medium",
            "sources": [SRC_UNIX_ADDON],
        }
    if key.startswith("letsencrypt"):
        return {
            "description": "Let's Encrypt certificate issuance/renewal logs.",
            "use_cases": ["tls_certificate_health", "expiration_failure_triage"],
            "field_aliases": {"host": ["host"], "domain": ["domain", "cn"], "message": ["_raw", "msg"]},
            "confidence": "medium",
            "sources": [SRC_UNIX_ADDON],
        }
    if key in {"errors"}:
        return {
            "description": "Generic application/system error stream.",
            "use_cases": ["error_spike_triage", "service_stability_review"],
            "field_aliases": {"host": ["host"], "message": ["_raw", "msg"], "severity": ["level", "severity"]},
            "confidence": "medium",
            "sources": [SRC_ADDON_NAMING],
        }
    if key in {"kvstore", "search_telemetry", "scheduler", "language-server-2"}:
        return {
            "description": "Splunk internal subsystem telemetry.",
            "use_cases": ["splunk_health_monitoring", "search_scheduler_diagnostics"],
            "field_aliases": {"host": ["host"], "component": ["component"], "message": ["_raw", "msg"]},
            "confidence": "high",
            "sources": [SRC_PRETRAINED],
        }
    if key.startswith("enphase:"):
        return {
            "description": "Custom Enphase solar telemetry sourcetype.",
            "use_cases": ["custom_data_ingestion_validation", "asset_specific_monitoring"],
            "field_aliases": {"host": ["host"], "message": ["_raw", "msg"]},
            "confidence": "medium",
            "sources": [SRC_ADDON_NAMING],
        }
    if "access" in key and ("apache" in key or "nginx" in key):
        return {
            "description": "Likely web access logs.",
            "use_cases": ["web_traffic_analysis", "suspicious_ip_activity"],
            "field_aliases": {"src_ip": ["clientip", "src", "ip"]},
            "confidence": "medium",
            "sources": [SRC_PRETRAINED],
        }
    if "secure" in key or "auth" in key:
        return {
            "description": "Likely authentication/security events.",
            "use_cases": ["auth_failures", "credential_abuse"],
            "field_aliases": {"src_ip": ["src", "ip"], "username": ["user", "username"]},
            "confidence": "medium",
            "sources": [SRC_PRETRAINED],
        }
    return {
        "description": "Unclassified sourcetype; manual labeling recommended.",
        "use_cases": ["general_log_review"],
        "field_aliases": {},
        "confidence": "low",
        "sources": [SRC_PRETRAINED],
    }


def attach_semantics(profile: dict[str, Any]) -> dict[str, Any]:
    out = dict(profile)
    sourcetype_to_indexes = out.get("sourcetype_to_indexes", {})
    semantics: dict[str, Any] = {}
    if isinstance(sourcetype_to_indexes, dict):
        for st in sorted(sourcetype_to_indexes.keys()):
            semantics[st] = _semantic_for_sourcetype(st)
    out["sourcetype_semantics"] = semantics
    return out


def build_environment_context(
    question: str,
    *,
    profile_path: str | Path = PROFILE_PATH_DEFAULT,
    max_indexes: int = 10,
    max_sourcetypes_per_index: int = 12,
    max_chars: int = 2400,
) -> str:
    profile = load_environment_profile(profile_path)
    if not profile:
        return ""

    q = (question or "").lower()
    indexes = profile.get("indexes", [])
    semantics = profile.get("sourcetype_semantics", {}) if isinstance(profile.get("sourcetype_semantics"), dict) else {}
    field_inventory = (
        profile.get("sourcetype_field_inventory", {})
        if isinstance(profile.get("sourcetype_field_inventory"), dict)
        else {}
    )
    if not isinstance(indexes, list):
        return ""

    apache_mode = any(tok in q for tok in ("apache", "access_combined", "http", "web", "404", "user agent", "client ip"))
    windows_mode = any(tok in q for tok in ("windows", "eventcode", "xmlwineventlog", "security log", "4625"))
    linux_mode = any(tok in q for tok in ("linux", "rpi5", "sudo", "ssh", "auth.log", "syslog", "linux_secure"))
    failed_auth_mode = any(tok in q for tok in ("failed", "login", "auth", "authentication", "password"))

    scored: list[tuple[int, dict[str, Any]]] = []
    for row in indexes:
        if not isinstance(row, dict):
            continue
        idx = str(row.get("index", "")).strip()
        sts = row.get("sourcetypes", [])
        if not idx or not isinstance(sts, list):
            continue
        score = 0
        if idx.lower() in q:
            score += 8
        for st in sts:
            st_l = str(st).lower()
            if st_l and st_l in q:
                score += 6
            if failed_auth_mode and ("audit" in st_l or "security" in st_l or "auth" in st_l):
                score += 3
            if apache_mode and ("access_combined" in st_l or "apache" in st_l or "access" in st_l):
                score += 6
            if windows_mode and ("xmlwineventlog" in st_l or "wineventlog" in st_l or "security" in st_l):
                score += 6
            if linux_mode and any(tok in st_l for tok in ("auth.log", "linux_secure", "syslog", "sudo", "ufw")):
                score += 4

        idx_l = idx.lower()
        if apache_mode:
            if idx_l == "linux":
                score += 6
            if "perf" in idx_l and not any("access_combined" in str(st).lower() for st in sts):
                score -= 6
        if windows_mode and idx_l.startswith("windows"):
            score += 6
        if linux_mode and idx_l == "linux":
            score += 6
        if failed_auth_mode and idx_l.startswith("_") and not any(tok in q for tok in ("splunk internal", "_audit", "_internal")):
            score -= 4
        scored.append((score, row))

    scored.sort(key=lambda x: x[0], reverse=True)
    positive = [row for score, row in scored if score > 0]
    chosen = positive[:max(1, max_indexes)] if positive else [row for _, row in scored[:max(1, max_indexes)]]

    lines: list[str] = []
    lines.append("[ENVIRONMENT_PROFILE]")
    lines.append("Use only discovered index/sourcetype combinations when drafting SPL.")
    for row in chosen:
        idx = str(row.get("index", "")).strip()
        sts = [str(x).strip() for x in row.get("sourcetypes", []) if str(x).strip()]
        if not idx:
            continue
        preview = sts[:max_sourcetypes_per_index]
        lines.append(f"- index={idx} sourcetypes={', '.join(preview)}")
        for st in preview[:5]:
            sem = semantics.get(st, {}) if isinstance(semantics, dict) else {}
            desc = str(sem.get("description", ""))
            if desc:
                lines.append(f"  - {st}: {desc}")
            field_meta = field_inventory.get(st, {}) if isinstance(field_inventory, dict) else {}
            if isinstance(field_meta, dict):
                field_examples = field_meta.get("interesting_field_examples", [])
                if isinstance(field_examples, list) and field_examples:
                    parts: list[str] = []
                    for item in field_examples[:4]:
                        if not isinstance(item, dict):
                            continue
                        field_name = str(item.get("field", "")).strip()
                        samples = item.get("sample_values", [])
                        if not field_name:
                            continue
                        if isinstance(samples, list) and samples:
                            parts.append(f"{field_name}={{{', '.join(str(x).strip() for x in samples[:2] if str(x).strip())}}}")
                        else:
                            parts.append(field_name)
                    if parts:
                        lines.append(f"  - {st} fields: {'; '.join(parts)}")
                        continue
                field_names = field_meta.get("interesting_fields", [])
                if not isinstance(field_names, list) or not field_names:
                    fields = field_meta.get("fields", [])
                    if isinstance(fields, list) and fields:
                        field_names = [str(item.get("field", "")).strip() for item in fields[:8] if isinstance(item, dict)]
                field_names = [name for name in field_names if str(name).strip()]
                if field_names:
                    lines.append(f"  - {st} fields: {', '.join(field_names[:8])}")

    # Explicit index<->sourcetype bindings for high-value SOC domains.
    reverse_map: dict[str, list[str]] = {}
    for row in indexes:
        if not isinstance(row, dict):
            continue
        idx = str(row.get("index", "")).strip()
        if not idx:
            continue
        for st in row.get("sourcetypes", []):
            st_name = str(st).strip()
            if not st_name:
                continue
            reverse_map.setdefault(st_name, []).append(idx)
    key_sourcetypes = ("access_combined", "XmlWinEventLog", "auth.log", "linux_secure", "auth-4", "apache_error")
    bindings: list[str] = []
    for st in key_sourcetypes:
        idxs = reverse_map.get(st, [])
        if idxs:
            uniq = []
            for idx in idxs:
                if idx not in uniq:
                    uniq.append(idx)
            bindings.append(f"- sourcetype={st} indexes={', '.join(uniq)}")
    if bindings:
        lines.append("[INDEX_SOURCETYPE_BINDINGS]")
        lines.append("Never invent index names; bind these sourcetypes to discovered indexes.")
        lines.extend(bindings)

    text = "\n".join(lines)
    if len(text) > max_chars:
        text = text[:max_chars]
    return text


def build_tag_context(
    question: str,
    *,
    profile_path: str | Path = PROFILE_PATH_DEFAULT,
    max_tags: int = 8,
    max_pairs_per_tag: int = 5,
    max_chars: int = 1200,
) -> str:
    profile = load_environment_profile(profile_path)
    if not profile:
        return ""
    tag_map = profile.get("tag_to_index_sourcetype", {})
    if not isinstance(tag_map, dict) or not tag_map:
        return ""

    q = (question or "").lower()
    tokens = {t for t in re.findall(r"[a-z0-9_]{3,}", q)}
    # Bias common SOC terms toward CIM/security tags.
    if any(t in q for t in ("failed", "login", "auth", "password", "credential")):
        tokens.update({"authentication", "failed", "error", "access"})
    if any(t in q for t in ("apache", "http", "web", "uri", "404")):
        tokens.update({"web", "http", "network"})
    if any(t in q for t in ("linux", "ssh", "sudo", "tty", "rhost")):
        tokens.update({"linux", "endpoint", "authentication"})
    if any(t in q for t in ("windows", "eventcode", "powershell", "security")):
        tokens.update({"windows", "endpoint", "process", "authentication"})

    scored: list[tuple[int, str, list[dict[str, str]]]] = []
    for tag, pairs in tag_map.items():
        if not isinstance(pairs, list):
            continue
        tag_text = str(tag).strip()
        if not tag_text:
            continue
        score = 0
        tl = tag_text.lower()
        for tok in tokens:
            if tok == tl:
                score += 4
            elif tok in tl or tl in tok:
                score += 2
        if tl in {"authentication", "endpoint", "network", "web", "risk"}:
            score += 1
        if score <= 0 and tokens:
            continue
        scored.append((score, tag_text, pairs))

    if not scored:
        # Fall back to a stable subset so writer still gets domain hints.
        for tag in sorted(tag_map.keys())[:max(1, max_tags)]:
            pairs = tag_map.get(tag, [])
            if isinstance(pairs, list):
                scored.append((0, str(tag), pairs))

    scored.sort(key=lambda x: x[0], reverse=True)
    chosen = scored[:max(1, max_tags)]
    lines: list[str] = []
    lines.append("[CIM_TAG_PROFILE]")
    lines.append("Prefer CIM-aligned filters (tag/eventtype) when they match the question and discovered domains.")
    for score, tag, pairs in chosen:
        if not isinstance(pairs, list):
            continue
        formatted: list[str] = []
        for pair in pairs[:max(1, max_pairs_per_tag)]:
            if not isinstance(pair, dict):
                continue
            idx = str(pair.get("index", "")).strip()
            st = str(pair.get("sourcetype", "")).strip()
            if idx and st:
                formatted.append(f"{idx}:{st}")
        if not formatted:
            continue
        if score > 0:
            lines.append(f"- tag={tag} (relevance={score}) domains={', '.join(formatted)}")
        else:
            lines.append(f"- tag={tag} domains={', '.join(formatted)}")

    text = "\n".join(lines)
    if len(text) > max_chars:
        text = text[:max_chars]
    return text


def suggest_domains_for_question(
    question: str,
    *,
    profile_path: str | Path = PROFILE_PATH_DEFAULT,
    max_indexes: int = 5,
    max_sourcetypes_per_index: int = 5,
) -> list[dict[str, Any]]:
    profile = load_environment_profile(profile_path)
    if not profile:
        return []
    indexes = profile.get("indexes", [])
    if not isinstance(indexes, list):
        return []

    q = (question or "").lower().strip()
    if not q:
        return []
    internal_explicit = any(tok in q for tok in ("splunk internal", "_internal", "_audit", "splunk auth", "splunk platform"))

    hints_by_topic: list[tuple[str, tuple[str, ...]]] = [
        ("failed_login", ("failed", "login", "auth", "authentication")),
        ("apache", ("apache", "access", "http", "404", "user agent", "web")),
        ("linux", ("linux", "sudo", "ssh", "auth.log", "syslog", "secure")),
        ("windows", ("windows", "event", "xmlwineventlog", "winhostmon", "winnetmon")),
        ("splunk_internal", ("splunk", "scheduler", "search", "internal", "platform")),
    ]

    scored: list[tuple[int, dict[str, Any], list[str]]] = []
    for row in indexes:
        if not isinstance(row, dict):
            continue
        idx = str(row.get("index", "")).strip()
        sts = row.get("sourcetypes", [])
        if not idx or not isinstance(sts, list):
            continue
        if idx.startswith("_") and not internal_explicit:
            continue
        score = 0
        reasons: list[str] = []

        q_tokens = set(re.findall(r"[a-z0-9_:.+-]+", q))

        if idx.lower() in q_tokens:
            score += 6
            reasons.append(f"question contains index '{idx}'")

        for st in sts:
            st_l = str(st).lower()
            if st_l and st_l in q_tokens:
                score += 5
                reasons.append(f"question contains sourcetype '{st}'")
            if "failed" in q and ("audit" in st_l or "auth" in st_l):
                score += 2
            if any(tok in q for tok in ("apache", "http", "web", "404")) and ("access" in st_l or "apache" in st_l):
                score += 2
            if any(tok in q for tok in ("windows", "event", "security")) and ("win" in st_l or "xmlwineventlog" in st_l):
                score += 2
            if "linux" in q and any(tok in st_l for tok in ("auth.log", "syslog", "secure", "sudo")):
                score += 2

        for topic, tokens in hints_by_topic:
            if any(tok in q for tok in tokens):
                if topic == "failed_login" and idx in {"linux", "windows", "windows_sysmon"}:
                    score += 2
                    reasons.append("failed-login topic weighting")
                if topic == "failed_login" and internal_explicit and idx == "_audit":
                    score += 2
                    reasons.append("explicit-splunk-internal failed-login weighting")
                elif topic == "apache" and idx in {"linux", "main"}:
                    score += 2
                    reasons.append("apache/web topic weighting")
                elif topic == "linux" and idx.startswith("linux"):
                    score += 2
                    reasons.append("linux topic weighting")
                elif topic == "windows" and idx.startswith("windows"):
                    score += 2
                    reasons.append("windows topic weighting")
                elif topic == "splunk_internal" and idx.startswith("_"):
                    score += 1
                    reasons.append("splunk-internal topic weighting")

        if score > 0:
            scored.append((score, row, reasons))

    scored.sort(key=lambda x: x[0], reverse=True)
    out: list[dict[str, Any]] = []
    for score, row, reasons in scored[:max(1, max_indexes)]:
        idx = str(row.get("index", "")).strip()
        sts = [str(x).strip() for x in row.get("sourcetypes", []) if str(x).strip()]
        out.append(
            {
                "index": idx,
                "score": score,
                "reasons": reasons[:4],
                "sourcetypes": sts[:max(1, max_sourcetypes_per_index)],
                "sourcetype_count": len(sts),
            }
        )
    return out


def extract_indexes_from_query(query: str) -> list[str]:
    q = query or ""
    # matches index=foo, index="foo", index='foo'
    matches = re.findall(r"index\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s|()]+))", q, flags=re.IGNORECASE)
    vals: list[str] = []
    for a, b, c in matches:
        v = (a or b or c or "").strip()
        if v:
            vals.append(v)
    # unique preserve order
    out: list[str] = []
    for v in vals:
        if v not in out:
            out.append(v)
    return out


def extract_sourcetypes_from_query(query: str) -> list[str]:
    q = query or ""
    matches = re.findall(r"sourcetype\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s|()]+))", q, flags=re.IGNORECASE)
    vals: list[str] = []
    for a, b, c in matches:
        v = (a or b or c or "").strip()
        if v:
            vals.append(v)
    out: list[str] = []
    for v in vals:
        if v not in out:
            out.append(v)
    return out


def validate_query_against_environment(query_args: dict[str, Any], *, profile_path: str | Path = PROFILE_PATH_DEFAULT) -> tuple[bool, str]:
    if not isinstance(query_args, dict):
        return False, "environment_query_args_not_dict"
    query = str(query_args.get("query", "")).strip()
    if not query:
        return False, "environment_query_missing"

    profile = load_environment_profile(profile_path)
    if not profile:
        return True, "environment_profile_missing_skip"

    indexes_by_name: dict[str, set[str]] = {}
    known_indexes: set[str] = set()
    for row in profile.get("indexes", []):
        if not isinstance(row, dict):
            continue
        idx = str(row.get("index", "")).strip()
        sts = {str(x).strip() for x in row.get("sourcetypes", []) if str(x).strip()}
        if idx:
            known_indexes.add(idx)
            indexes_by_name[idx] = sts

    q_indexes = extract_indexes_from_query(query)
    q_sourcetypes = extract_sourcetypes_from_query(query)

    # index check
    for idx in q_indexes:
        if idx in {"*", "_*"}:
            continue
        if idx not in known_indexes:
            return False, f"environment_unknown_index:{idx}"

    # sourcetype and index pairing check
    if q_sourcetypes:
        if not q_indexes:
            st_to_idx = profile.get("sourcetype_to_indexes", {})
            if isinstance(st_to_idx, dict):
                for st in q_sourcetypes:
                    if st not in st_to_idx:
                        return False, f"environment_unknown_sourcetype:{st}"
            return True, "environment_sourcetype_known_no_index_constraint"

        concrete_indexes = [i for i in q_indexes if i not in {"*", "_*"}]
        if concrete_indexes:
            for st in q_sourcetypes:
                ok_any = False
                for idx in concrete_indexes:
                    if st in indexes_by_name.get(idx, set()):
                        ok_any = True
                        break
                if not ok_any:
                    return False, f"environment_sourcetype_not_in_index:{st}"

    return True, "environment_query_ok"
