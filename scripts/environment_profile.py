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
    "apache:access": {
        "description": "Apache access logs with standard HTTP request lines.",
        "use_cases": ["apache_access_top_ips", "apache_404_spike", "web_scanning"],
        "field_aliases": {
            "src_ip": ["clientip", "src", "src_ip", "ip"],
            "status_code": ["status", "status_code", "sc_status"],
            "url_path": ["uri_path", "uri", "url", "request"],
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
    "apache:error": {
        "description": "Apache error log events with web app failure context.",
        "use_cases": ["apache_error_spike", "web_app_faults", "web_attack_signals"],
        "field_aliases": {"src_ip": ["src", "clientip", "ip"], "message": ["error_message", "_raw", "msg"]},
        "confidence": "high",
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
    "oktaim2:log": {
        "description": "Okta identity activity logs including authentication, MFA, and account access events.",
        "use_cases": ["identity_auth_activity", "failed_login_activity", "credential_abuse"],
        "field_aliases": {
            "username": ["actor.alternateId", "user", "username"],
            "src_ip": ["client.ipAddress", "ipAddress", "src_ip", "src"],
        },
        "confidence": "high",
        "sources": [SRC_ADDON_NAMING],
    },
    "o365:management:activity": {
        "description": "Microsoft 365 management activity logs for user and workload operations.",
        "use_cases": ["identity_auth_activity", "o365_management_activity"],
        "field_aliases": {
            "username": ["UserId", "user", "username"],
            "src_ip": ["ClientIP", "src_ip", "src"],
        },
        "confidence": "high",
        "sources": [SRC_ADDON_NAMING],
    },
    "aws:cloudtrail": {
        "description": "AWS CloudTrail API activity and service events.",
        "use_cases": ["aws_cloudtrail_activity", "cloud_api_activity"],
        "field_aliases": {
            "src_ip": ["sourceIPAddress", "src_ip", "src"],
            "username": ["userIdentity.arn", "userIdentity.principalId", "principal"],
        },
        "confidence": "high",
        "sources": [SRC_ADDON_NAMING],
    },
    "aws:cloudwatchlogs:vpcflow": {
        "description": "AWS VPC Flow Logs for accepted and rejected network flows.",
        "use_cases": ["network_flow", "aws_vpc_flow_activity"],
        "field_aliases": {
            "src_ip": ["src_ip", "srcaddr", "src"],
            "dest_ip": ["dest_ip", "dstaddr", "dest"],
            "dest_port": ["dest_port", "dstport"],
        },
        "confidence": "high",
        "sources": [SRC_ADDON_NAMING],
    },
    "ms:aad:signin": {
        "description": "Azure AD / Entra ID sign-in activity logs.",
        "use_cases": ["identity_auth_activity", "aad_signin_activity"],
        "field_aliases": {
            "username": ["userPrincipalName", "user", "username"],
            "src_ip": ["ipAddress", "src_ip", "src"],
        },
        "confidence": "high",
        "sources": [SRC_ADDON_NAMING],
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
    "auditd": {
        "description": "Linux audit framework events covering authentication, process, and privilege actions.",
        "use_cases": ["linux_auth_failures", "linux_privilege_escalation", "linux_audit_activity"],
        "field_aliases": {
            "src_ip": ["addr", "src", "src_ip", "rhost", "ip"],
            "username": ["acct", "auid", "uid", "user"],
        },
        "confidence": "high",
        "sources": [SRC_UNIX_ADDON],
    },
    "linux_audit": {
        "description": "Linux auditd events normalized into a dedicated sourcetype.",
        "use_cases": ["linux_auth_failures", "linux_privilege_escalation", "linux_audit_activity"],
        "field_aliases": {
            "src_ip": ["addr", "src", "src_ip", "rhost", "ip"],
            "username": ["acct", "auid", "uid", "user"],
        },
        "confidence": "high",
        "sources": [SRC_UNIX_ADDON],
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
    linux_mode = any(tok in q for tok in ("linux", "rpi5", "sudo", "ssh", "auth.log", "/var/log/auth.log", "syslog", "linux_secure"))
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
            if linux_mode and any(tok in st_l for tok in ("auth.log", "linux_secure", "syslog", "sudo", "ufw", "auth")):
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
    key_sourcetypes = ("access_combined", "XmlWinEventLog", "auth.log", "linux_secure", "apache_error")
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


INTENT_USE_CASE_ALIASES: dict[str, tuple[str, ...]] = {
    "failed_login_activity": ("linux_auth_failures", "windows_auth_failures", "credential_abuse"),
    "successful_login_activity": ("linux_auth_failures", "windows_auth_failures", "credential_abuse"),
    "linux_auth_failures": ("linux_auth_failures", "credential_abuse"),
    "linux_successful_logins": ("linux_auth_failures", "credential_abuse"),
    "windows_auth_failures": ("windows_auth_failures", "credential_abuse"),
    "windows_successful_logons": ("windows_auth_failures", "credential_abuse"),
    "linux_privilege_escalation": ("linux_privilege_escalation", "linux_auth_failures"),
    "linux_privilege_escalation_activity": ("linux_privilege_escalation", "linux_auth_failures"),
    "linux_session_activity": ("linux_auth_failures",),
    "linux_audit_activity": ("linux_audit_activity", "linux_privilege_escalation", "linux_auth_failures"),
    "windows_process_activity": ("windows_process_creation", "windows_process_activity"),
    "windows_sysmon_network_activity": ("network_connection_triage", "lateral_movement_hunt"),
    "windows_sysmon_dns_activity": ("windows_process_activity",),
    "windows_credential_access_activity": ("windows_privilege_events", "credential_abuse"),
    "apache_access_top_ips": ("apache_access_top_ips", "web_scanning"),
    "apache_404_spike": ("apache_404_spike", "web_scanning"),
    "aws_cloudtrail_activity": ("aws_cloudtrail_activity", "cloud_api_activity"),
    "aws_vpc_flow_activity": ("network_flow",),
    "aad_signin_activity": ("identity_auth_activity",),
    "o365_management_activity": ("o365_management_activity",),
    "stream_dns_activity": ("dns_activity",),
}


def _question_tokens(question: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9_:.+-]{3,}", str(question or "").lower()) if token}


def _intent_use_cases(intent: str, question: str) -> set[str]:
    derived = set(INTENT_USE_CASE_ALIASES.get(str(intent or "").strip(), ()))
    q = str(question or "").lower()
    if any(tok in q for tok in ("failed", "login", "authentication", "password", "brute force", "failed logon")):
        derived.update({"linux_auth_failures", "windows_auth_failures", "credential_abuse"})
    if any(tok in q for tok in ("successful login", "successful logon", "successful authentication", "accepted password", "accepted publickey", "4624")):
        derived.update({"linux_auth_failures", "windows_auth_failures", "credential_abuse"})
    if any(tok in q for tok in ("sudo", "su", "privilege escalation", "root session")):
        derived.update({"linux_privilege_escalation", "linux_audit_activity"})
    if any(tok in q for tok in ("apache", "http", "404", "web", "client ip", "user agent")):
        derived.update({"apache_access_top_ips", "apache_404_spike", "web_scanning"})
    if any(tok in q for tok in ("cloudtrail", "aws api", "eventname", "eventsource", "sourceipaddress", "iam activity")):
        derived.update({"aws_cloudtrail_activity", "cloud_api_activity"})
    if any(tok in q for tok in ("vpc flow", "vpc flows", "aws vpc flow", "cloudwatchlogs:vpcflow")):
        derived.update({"network_flow", "aws_vpc_flow_activity"})
    if any(tok in q for tok in ("azure ad", "aad sign-in", "aad signin", "ms:aad:signin")):
        derived.update({"identity_auth_activity", "aad_signin_activity"})
    if any(tok in q for tok in ("office 365 management", "o365 management", "ms:o365:management", "o365:management:activity")):
        derived.update({"o365_management_activity"})
    return derived


def _domain_styles(index_name: str, sourcetypes: list[str], semantics: dict[str, Any]) -> set[str]:
    styles: set[str] = set()
    idx_l = str(index_name or "").lower()
    joined = " ".join(str(item or "").lower() for item in sourcetypes)
    for st in sourcetypes:
        sem = semantics.get(st, {}) if isinstance(semantics, dict) else {}
        for use_case in sem.get("use_cases", []) if isinstance(sem.get("use_cases", []), list) else []:
            if str(use_case).startswith("linux_"):
                styles.add("linux")
            if str(use_case).startswith("windows_"):
                styles.add("windows")
            if str(use_case).startswith("apache_") or use_case in {"web_scanning"}:
                styles.add("web")
    if any(tok in joined or tok in idx_l for tok in ("linux_secure", "auth.log", "auditd", "syslog", "sudo", "su")):
        styles.add("linux")
    if any(tok in joined or tok in idx_l for tok in ("xmlwineventlog", "wineventlog", "sysmon")):
        styles.add("windows")
    if any(tok in joined or tok in idx_l for tok in ("access_combined", "apache", "nginx", "http")):
        styles.add("web")
    return styles


def _field_inventory_names(field_meta: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    if not isinstance(field_meta, dict):
        return names
    for key in ("interesting_fields",):
        values = field_meta.get(key, [])
        if isinstance(values, list):
            names.update(str(item).strip() for item in values if str(item).strip())
    fields = field_meta.get("fields", [])
    if isinstance(fields, list):
        for item in fields:
            if isinstance(item, dict):
                name = str(item.get("field", "")).strip()
                if name:
                    names.add(name)
    examples = field_meta.get("interesting_field_examples", [])
    if isinstance(examples, list):
        for item in examples:
            if isinstance(item, dict):
                name = str(item.get("field", "")).strip()
                if name:
                    names.add(name)
    return names


def _field_inventory_populated_names(field_meta: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    if not isinstance(field_meta, dict):
        return names
    examples = field_meta.get("interesting_field_examples", [])
    if isinstance(examples, list):
        for item in examples:
            if isinstance(item, dict):
                name = str(item.get("field", "")).strip()
                if name:
                    names.add(name)
    fields = field_meta.get("fields", [])
    if isinstance(fields, list):
        for item in fields:
            if not isinstance(item, dict):
                continue
            name = str(item.get("field", "")).strip()
            if not name:
                continue
            try:
                count = int(item.get("count", 0))
            except Exception:
                count = 0
            if count > 0:
                names.add(name)
    return names


def _domain_field_meta(
    *,
    index_name: str,
    sourcetype: str,
    field_inventory: dict[str, Any],
    index_sourcetype_inventory: dict[str, Any],
) -> dict[str, Any]:
    domain_bucket = index_sourcetype_inventory.get(index_name, {}) if isinstance(index_sourcetype_inventory, dict) else {}
    if isinstance(domain_bucket, dict):
        domain_meta = domain_bucket.get(sourcetype, {})
        if isinstance(domain_meta, dict) and domain_meta:
            return domain_meta
    meta = field_inventory.get(sourcetype, {}) if isinstance(field_inventory, dict) else {}
    return meta if isinstance(meta, dict) else {}


def _domain_supports_intent(
    intent: str,
    index_name: str,
    sourcetypes: list[str],
    semantics: dict[str, Any],
    field_inventory: dict[str, Any],
    index_sourcetype_inventory: dict[str, Any],
) -> bool:
    auth_linux_fields = {"user", "uid", "acct", "rhost", "addr", "src_ip"}
    auth_windows_fields = {"TargetUserName", "SubjectUserName", "IpAddress", "Source_Network_Address", "LogonType", "FailureReason"}
    sysmon_markers = {"Image", "CommandLine", "DestinationIp", "QueryName", "DestinationPort", "ParentImage"}
    web_fields = {"clientip", "status", "uri", "uri_path", "method"}
    all_fields: set[str] = set()
    all_populated_fields: set[str] = set()
    use_cases: set[str] = set()
    for st in sourcetypes:
        sem = semantics.get(st, {}) if isinstance(semantics, dict) else {}
        st_field_meta = _domain_field_meta(
            index_name=index_name,
            sourcetype=st,
            field_inventory=field_inventory,
            index_sourcetype_inventory=index_sourcetype_inventory,
        )
        st_fields = _field_inventory_names(st_field_meta)
        st_populated_fields = _field_inventory_populated_names(st_field_meta)
        all_fields.update(st_fields)
        all_populated_fields.update(st_populated_fields)
        st_use_cases = {str(item).strip() for item in sem.get("use_cases", []) if str(item).strip()} if isinstance(sem, dict) else set()
        st_l = str(st).strip().lower()
        if st_l == "xmlwineventlog" and not (auth_windows_fields & st_populated_fields):
            st_use_cases.discard("windows_auth_failures")
            st_use_cases.discard("windows_privilege_events")
        use_cases.update(st_use_cases)
    st_joined = " ".join(str(item).lower() for item in sourcetypes)

    if intent in {"failed_login_activity", "successful_login_activity"}:
        return bool(
            {"linux_auth_failures", "windows_auth_failures", "credential_abuse"} & use_cases
            or auth_linux_fields & all_populated_fields
            or auth_windows_fields & all_populated_fields
            or any(tok in st_joined for tok in ("auth", "secure", "auditd", "wineventlog:security", "xmlwineventlog:security"))
        )
    if intent in {"linux_auth_failures", "linux_successful_logins", "linux_privilege_escalation", "linux_privilege_escalation_activity", "linux_session_activity", "linux_audit_activity"}:
        return bool(
            {"linux_auth_failures", "linux_privilege_escalation", "linux_audit_activity"} & use_cases
            or auth_linux_fields & all_populated_fields
            or any(tok in st_joined for tok in ("auth", "secure", "auditd", "linux_audit"))
        )
    if intent in {"windows_auth_failures", "windows_successful_logons", "windows_credential_access_activity"}:
        windows_security_like = (
            ("xmlwineventlog" in st_joined or "wineventlog:security" in st_joined)
            and not (sysmon_markers & all_populated_fields)
            and ("Channel" in all_populated_fields or "EventCode" in all_populated_fields or "EventID" in all_populated_fields)
        )
        return bool(
            {"windows_auth_failures", "windows_privilege_events"} & use_cases
            or auth_windows_fields & all_populated_fields
            or windows_security_like
            or any(tok in st_joined for tok in ("wineventlog:security", "xmlwineventlog:security"))
        )
    if intent in {"apache_access_top_ips", "apache_404_spike"}:
        return bool(
            {"apache_access_top_ips", "apache_404_spike", "web_scanning"} & use_cases
            or web_fields & all_populated_fields
            or any(tok in st_joined for tok in ("access_combined", "apache", "nginx"))
        )
    if intent == "aws_cloudtrail_activity":
        return bool(
            {"aws_cloudtrail_activity", "cloud_api_activity"} & use_cases
            or {"eventSource", "eventName", "sourceIPAddress"} & all_populated_fields
            or "cloudtrail" in st_joined
        )
    if intent == "aws_vpc_flow_activity":
        return bool(
            ({"network_flow", "aws_vpc_flow_activity"} & use_cases and "vpcflow" in st_joined)
            or ("vpcflow" in st_joined)
            or {"src_ip", "dest_ip", "dest_port", "action"} <= all_populated_fields
        )
    if intent == "aad_signin_activity":
        return bool(
            {"aad_signin_activity"} & use_cases
            or "aad:signin" in st_joined
            or {"userPrincipalName", "ipAddress", "appDisplayName"} <= all_populated_fields
        )
    if intent == "o365_management_activity":
        return bool(
            {"o365_management_activity"} & use_cases
            or "o365:management" in st_joined
            or {"UserId", "Operation", "Workload", "ClientIP"} <= all_populated_fields
        )
    if intent in {"windows_process_activity", "windows_sysmon_network_activity", "windows_sysmon_dns_activity"}:
        return bool(
            {"windows_process_creation", "windows_process_activity", "network_connection_triage", "lateral_movement_hunt"} & use_cases
            or {"Image", "CommandLine", "DestinationIp", "QueryName", "Computer", "EventCode", "EventID"} & all_populated_fields
            or any(tok in st_joined for tok in ("xmlwineventlog", "sysmon"))
        )
    return True


def resolve_authoritative_domains_for_question(
    question: str,
    intent: str,
    *,
    profile_path: str | Path = PROFILE_PATH_DEFAULT,
    max_domains: int = 4,
) -> list[dict[str, Any]]:
    profile = attach_semantics(load_environment_profile(profile_path))
    indexes = profile.get("indexes", [])
    semantics = profile.get("sourcetype_semantics", {}) if isinstance(profile.get("sourcetype_semantics"), dict) else {}
    field_inventory = profile.get("sourcetype_field_inventory", {}) if isinstance(profile.get("sourcetype_field_inventory"), dict) else {}
    index_sourcetype_inventory = (
        profile.get("index_sourcetype_field_inventory", {})
        if isinstance(profile.get("index_sourcetype_field_inventory"), dict)
        else {}
    )
    if not isinstance(indexes, list) or not indexes:
        return []

    tokens = _question_tokens(question)
    target_use_cases = _intent_use_cases(intent, question)
    explicit_internal = any(tok in str(question or "").lower() for tok in ("_audit", "_internal", "splunk internal"))

    scored: list[tuple[int, dict[str, Any]]] = []
    for row in indexes:
        if not isinstance(row, dict):
            continue
        idx = str(row.get("index", "")).strip()
        sourcetypes = [str(st).strip() for st in row.get("sourcetypes", []) if str(st).strip()]
        if not idx or not sourcetypes:
            continue
        if not _domain_supports_intent(intent, idx, sourcetypes, semantics, field_inventory, index_sourcetype_inventory):
            continue

        score = 0
        idx_l = idx.lower()
        styles = _domain_styles(idx, sourcetypes, semantics)
        matched_use_cases: set[str] = set()
        for st in sourcetypes:
            sem = semantics.get(st, {}) if isinstance(semantics, dict) else {}
            use_cases = {str(item).strip() for item in sem.get("use_cases", []) if str(item).strip()} if isinstance(sem, dict) else set()
            matched_use_cases.update(use_cases & target_use_cases)
            score += 8 * len(use_cases & target_use_cases)
            desc = str(sem.get("description", "")).lower() if isinstance(sem, dict) else ""
            for token in tokens:
                if token == idx_l:
                    score += 6
                if token in str(st).lower():
                    score += 4
                if token in desc:
                    score += 2
        if idx_l in tokens:
            score += 6
        if idx_l.startswith("_") and not explicit_internal:
            score -= 6
        scored.append(
            (
                score,
                {
                    "index": idx,
                    "sourcetypes": sourcetypes,
                    "styles": sorted(styles),
                    "matched_use_cases": sorted(matched_use_cases),
                    "score": score,
                },
            )
        )

    scored.sort(key=lambda item: item[0], reverse=True)
    chosen = [row for score, row in scored if score > 0][: max(1, max_domains)]
    if chosen:
        return chosen
    return [row for _score, row in scored[: max(1, max_domains)]]


def _format_sourcetype_term(value: str) -> str:
    token = str(value or "").strip()
    if not token:
        return ""
    if re.fullmatch(r"[A-Za-z0-9_:.+-]+", token):
        return f"sourcetype={token}"
    return f'sourcetype="{token}"'


def _select_domain_by_style(domains: list[dict[str, Any]], style: str) -> dict[str, Any] | None:
    for domain in domains:
        styles = domain.get("styles", [])
        if isinstance(styles, list) and style in styles:
            return domain
    return None


def _auth_sourcetype_clause(domain: dict[str, Any], semantics: dict[str, Any]) -> str:
    sourcetypes = [str(item).strip() for item in domain.get("sourcetypes", []) if str(item).strip()]
    selected: list[str] = []
    for st in sourcetypes:
        sem = semantics.get(st, {}) if isinstance(semantics, dict) else {}
        use_cases = {str(item).strip() for item in sem.get("use_cases", []) if str(item).strip()} if isinstance(sem, dict) else set()
        st_l = st.lower()
    if (
            {"linux_auth_failures", "windows_auth_failures", "linux_privilege_escalation", "linux_audit_activity"} & use_cases
            or any(tok in st_l for tok in ("auth", "secure", "audit", "wineventlog", "sysmon", "security"))
        ):
            selected.append(st)
    if not selected:
        selected = sourcetypes[:2]
    terms = [_format_sourcetype_term(st) for st in selected[:4] if _format_sourcetype_term(st)]
    return "(" + " OR ".join(terms) + ")" if terms else ""


def _preferred_sourcetype_for_intent(intent: str, domain: dict[str, Any]) -> str:
    sourcetypes = [str(item).strip() for item in domain.get("sourcetypes", []) if str(item).strip()]
    lowered = [(st, st.lower()) for st in sourcetypes]
    if intent == "linux_audit_activity":
        for st, st_l in lowered:
            if "auditd" in st_l or "linux_audit" in st_l:
                return st
    if intent == "aad_signin_activity":
        for st, st_l in lowered:
            if "aad" in st_l and "signin" in st_l:
                return st
        return ""
    if intent == "o365_management_activity":
        for st, st_l in lowered:
            if "o365" in st_l and "management" in st_l:
                return st
        return ""
    if intent == "aws_cloudtrail_activity":
        for st, st_l in lowered:
            if "cloudtrail" in st_l:
                return st
        return ""
    if intent == "aws_vpc_flow_activity":
        for st, st_l in lowered:
            if "vpcflow" in st_l:
                return st
        return ""
    return ""


def apply_environment_query_constraints(
    question: str,
    intent: str,
    query: str,
    *,
    profile_path: str | Path = PROFILE_PATH_DEFAULT,
) -> str:
    rendered = str(query or "").strip()
    if not rendered:
        return rendered
    if "botsv3" in str(question or "").lower():
        return rendered

    profile = attach_semantics(load_environment_profile(profile_path))
    semantics = profile.get("sourcetype_semantics", {}) if isinstance(profile.get("sourcetype_semantics"), dict) else {}
    domains = resolve_authoritative_domains_for_question(question, intent, profile_path=profile_path, max_domains=4)
    if not domains:
        return rendered

    primary = domains[0]
    linux_domain = _select_domain_by_style(domains, "linux")
    windows_domain = _select_domain_by_style(domains, "windows")
    web_domain = _select_domain_by_style(domains, "web")
    active_domain = primary
    if str(intent or "").startswith("linux_"):
        active_domain = linux_domain or primary
    elif str(intent or "").startswith("windows_"):
        active_domain = windows_domain or primary
    elif str(intent or "").startswith("apache_"):
        active_domain = web_domain or primary

    active_index = str((active_domain or {}).get("index", "")).strip()
    linux_index = str((linux_domain or active_domain or {}).get("index", "")).strip()
    windows_index = str((windows_domain or {}).get("index", "")).strip()
    sourcetype_clause = _auth_sourcetype_clause(active_domain or {}, semantics)
    linux_clause = _auth_sourcetype_clause(linux_domain or active_domain or {}, semantics)
    windows_clause = _auth_sourcetype_clause(windows_domain or {}, semantics) if windows_domain else ""
    web_sourcetypes = [str(item).strip() for item in (web_domain or active_domain or {}).get("sourcetypes", []) if str(item).strip()]
    web_access = next((st for st in web_sourcetypes if any(tok in st.lower() for tok in ("access_combined", "apache:access", "nginx"))), "")
    web_error = next((st for st in web_sourcetypes if any(tok in st.lower() for tok in ("apache:error", "apache_error", "error"))), "")
    preferred_sourcetype = _preferred_sourcetype_for_intent(str(intent or "").strip(), active_domain or {})

    if linux_index and not str(intent or "").startswith("apache_"):
        rendered = re.sub(r"\bindex=linux\b", f"index={linux_index}", rendered, flags=re.IGNORECASE)
    if active_index:
        rendered = re.sub(r"\(index=main OR index=main\)", f"index={active_index}", rendered, flags=re.IGNORECASE)
        rendered = re.sub(r"\bindex=main\b", f"index={active_index}", rendered, flags=re.IGNORECASE)
    if windows_index:
        rendered = re.sub(r"\bindex=windows_sysmon\b", f"index={windows_index}", rendered, flags=re.IGNORECASE)
        rendered = re.sub(r"\bindex=windows\b", f"index={windows_index}", rendered, flags=re.IGNORECASE)
        rendered = re.sub(r"\(index=windows OR index=windows_sysmon\)", f"index={windows_index}", rendered, flags=re.IGNORECASE)
    elif str(intent or "").strip() in {"failed_login_activity", "successful_login_activity"}:
        rendered = re.sub(r"\|\s*append\s*\[\s*search\s+\(index=windows OR index=windows_sysmon\).*?\]\s*", " ", rendered, flags=re.IGNORECASE)
        rendered = re.sub(r"\|\s*append\s*\[\s*search\s+index=windows.*?\]\s*", " ", rendered, flags=re.IGNORECASE)
        rendered = re.sub(
            r"\s+OR\s+\(\(index=windows OR index=windows_sysmon\)\s+sourcetype=XmlWinEventLog\s+\((?:EventCode=4625|EventID=4625|\"An account failed to log on\"|EventCode=4624|EventID=4624|\"An account was successfully logged on\")[^)]*\)\)\s*",
            " ",
            rendered,
            flags=re.IGNORECASE,
        )
        rendered = re.sub(
            r"\|\s*append\s*\[\s*search\s+[^\]]*(EventCode=4625|EventID=4625|An account failed to log on|EventCode=4624|EventID=4624|An account was successfully logged on)[^\]]*\]\s*",
            " ",
            rendered,
            flags=re.IGNORECASE,
        )

    if linux_clause and any(path in rendered.lower() for path in ("/var/log/auth.log", "/var/log/secure")):
        rendered = re.sub(
            r"\(source=\"/var/log/auth\.log\" OR source=\"/var/log/secure\"\)",
            linux_clause,
            rendered,
            flags=re.IGNORECASE,
        )
        rendered = re.sub(r"source=\"/var/log/auth\.log\"", linux_clause, rendered, flags=re.IGNORECASE)
        rendered = re.sub(r"source=\"/var/log/secure\"", linux_clause, rendered, flags=re.IGNORECASE)

    if windows_clause and re.search(r"\bsourcetype=XmlWinEventLog\b", rendered, flags=re.IGNORECASE):
        replacement = windows_clause[1:-1] if windows_clause.startswith("(") and windows_clause.endswith(")") else windows_clause
        first_term = replacement.split(" OR ")[0] if replacement else replacement
        if first_term:
            rendered = re.sub(r"\bsourcetype=XmlWinEventLog\b", first_term, rendered, flags=re.IGNORECASE)

    if web_domain:
        web_index = str(web_domain.get("index", "")).strip()
        if web_index:
            rendered = re.sub(r"\bindex=linux\b", f"index={web_index}", rendered, flags=re.IGNORECASE)
        if web_access:
            rendered = re.sub(r"\bsourcetype=access_combined\b", _format_sourcetype_term(web_access), rendered, flags=re.IGNORECASE)
        if web_error:
            rendered = re.sub(r"\bsourcetype=apache_error\b", _format_sourcetype_term(web_error), rendered, flags=re.IGNORECASE)

    if preferred_sourcetype:
        if str(intent or "").strip() == "linux_audit_activity":
            rendered = re.sub(r"\bsourcetype=linux_audit\b", _format_sourcetype_term(preferred_sourcetype), rendered, flags=re.IGNORECASE)
        elif str(intent or "").strip() in {"aad_signin_activity", "o365_management_activity", "aws_cloudtrail_activity", "aws_vpc_flow_activity"}:
            rendered = re.sub(r"\bsourcetype=[A-Za-z0-9_:.+-]+\b", _format_sourcetype_term(preferred_sourcetype), rendered, count=1, flags=re.IGNORECASE)

    if active_index and not any(idx in rendered for idx in (f"index={active_index}",)):
        q_indexes = extract_indexes_from_query(rendered)
        generic_only = q_indexes and all(idx in {"linux", "windows", "windows_sysmon", "main"} for idx in q_indexes)
        if generic_only:
            rendered = re.sub(r"\bindex=(linux|windows|windows_sysmon|main)\b", f"index={active_index}", rendered, flags=re.IGNORECASE)

    rendered = re.sub(r"\(index=([A-Za-z0-9_:-]+)\s+OR\s+index=\1\)", r"index=\1", rendered, flags=re.IGNORECASE)

    rendered = re.sub(r"\s{2,}", " ", rendered).strip()
    return rendered


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
