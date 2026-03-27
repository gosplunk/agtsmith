#!/usr/bin/env python3
"""Build domain-aware SPL skillpack artifact for query-writing prompts."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from environment_profile import PROFILE_PATH_DEFAULT, load_environment_profile
from query_templates import TEMPLATES

OUT_DEFAULT = Path("artifacts/knowledge/spl_skillpack_latest.json")


AUTHORING_GUIDANCE: tuple[dict[str, Any], ...] = (
    {
        "intent": "linux_auth_failures",
        "match_tokens": ("linux", "failed", "login", "ssh", "invalid user", "authentication failure"),
        "preferred_index": "linux",
        "preferred_sourcetypes": ["auth-too_small", "linux_secure", "syslog"],
        "preferred_fields": ["host", "user", "src_ip", "port"],
        "preferred_query_shape": "search index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") (...) | stats count by host user src_ip port | sort - count",
        "anti_patterns": [
            "do not use match(...(?<capture>...)) as extraction",
            "do not invent eval parsing when user/src_ip/port are already extracted",
            "do not drift to wildcard or internal indexes for Linux-only questions",
        ],
    },
    {
        "intent": "windows_auth_failures",
        "match_tokens": ("windows", "failed", "login", "logon", "4625", "authentication failure"),
        "preferred_index": "windows|windows_sysmon",
        "preferred_sourcetypes": ["XmlWinEventLog"],
        "preferred_fields": ["host", "user_name", "src_ip"],
        "preferred_query_shape": "search (index=windows OR index=windows_sysmon) sourcetype=XmlWinEventLog (...) | eval src_ip=coalesce(...) | eval user_name=coalesce(...) | stats count by index host user_name src_ip | sort - count",
        "anti_patterns": [
            "do not query _audit or _internal unless explicitly requested",
            "do not drift to Linux sourcetypes for Windows-only questions",
        ],
    },
    {
        "intent": "windows_process_activity",
        "match_tokens": ("windows", "sysmon", "process", "process creation", "eventid 1"),
        "preferred_index": "windows|windows_sysmon|botsv3",
        "preferred_sourcetypes": ["XmlWinEventLog", "xmlwineventlog"],
        "preferred_fields": ["Computer", "Image", "CommandLine", "User", "ParentImage"],
        "preferred_query_shape": "search (index=windows OR index=windows_sysmon) sourcetype=xmlwineventlog \"<EventID>1</EventID>\" | rex ... | stats count by Computer Image CommandLine User ParentImage | sort - count | head 20",
        "anti_patterns": [
            "do not answer process creation questions with 4625 failed logons",
            "do not drop CommandLine or ParentImage when process evidence is requested",
        ],
    },
    {
        "intent": "windows_sysmon_network_activity",
        "match_tokens": ("windows", "sysmon", "network", "connections", "eventid 3"),
        "preferred_index": "windows_sysmon",
        "preferred_sourcetypes": ["XmlWinEventLog"],
        "preferred_fields": ["Computer", "Image", "SourceIp", "DestinationIp", "DestinationPort", "Protocol"],
        "preferred_query_shape": "search index=windows_sysmon sourcetype=XmlWinEventLog Channel=\"Microsoft-Windows-Sysmon/Operational\" (EventID=3 OR EventCode=3 OR DestinationIp=*) | table _time Computer Image SourceIp DestinationIp DestinationPort Protocol | head 20",
        "anti_patterns": [
            "do not replace Sysmon network events with firewall flow data",
            "do not drop Image or DestinationIp from the result shape",
        ],
    },
    {
        "intent": "windows_sysmon_dns_activity",
        "match_tokens": ("windows", "sysmon", "dns", "query", "eventid 22"),
        "preferred_index": "windows_sysmon",
        "preferred_sourcetypes": ["XmlWinEventLog"],
        "preferred_fields": ["Computer", "Image", "QueryName", "QueryResults"],
        "preferred_query_shape": "search index=windows_sysmon sourcetype=XmlWinEventLog Channel=\"Microsoft-Windows-Sysmon/Operational\" (EventID=22 OR EventCode=22 OR QueryName=*) | table _time Computer Image QueryName QueryResults | head 20",
        "anti_patterns": [
            "do not answer Sysmon DNS questions with generic stream:dns or auth queries",
            "do not remove QueryName from the result shape",
        ],
    },
    {
        "intent": "linux_privilege_escalation_first_seen",
        "match_tokens": ("linux", "first time", "first seen", "privilege escalation", "sudo", "su"),
        "preferred_index": "linux",
        "preferred_sourcetypes": ["auth-too_small", "linux_secure", "syslog"],
        "preferred_fields": ["host", "user_name", "tty", "src_ip", "first_seen"],
        "preferred_query_shape": "search index=linux (source=\"/var/log/auth.log\" OR source=\"/var/log/secure\") (...) | stats earliest(_time) as first_seen latest(_time) as last_seen count by host user_name tty src_ip",
        "anti_patterns": [
            "do not answer first-seen questions with plain count-only stats",
            "do not use failure-only strings for successful privilege-escalation questions",
        ],
    },
    {
        "intent": "apache_access_top_ips",
        "match_tokens": ("apache", "access_combined", "top", "client ip", "web"),
        "preferred_index": "linux",
        "preferred_sourcetypes": ["access_combined"],
        "preferred_fields": ["clientip", "status", "method", "uri", "uri_path", "useragent"],
        "preferred_query_shape": "search index=linux sourcetype=access_combined | stats count by clientip status method | sort - count",
        "anti_patterns": [
            "do not invent alternate Apache-specific index names",
            "do not group by low-signal fields before clientip/status/method",
        ],
    },
)


def _safe(v: Any) -> str:
    return str(v or "").strip()


def _semantic_map(profile: dict[str, Any]) -> dict[str, Any]:
    sem = profile.get("sourcetype_semantics", {})
    return sem if isinstance(sem, dict) else {}


def _build_domain_skills(profile: dict[str, Any]) -> list[dict[str, Any]]:
    indexes = profile.get("indexes", [])
    semantics = _semantic_map(profile)
    field_inventory = profile.get("sourcetype_field_inventory", {})
    if not isinstance(field_inventory, dict):
        field_inventory = {}
    out: list[dict[str, Any]] = []
    if not isinstance(indexes, list):
        return out
    for row in indexes:
        if not isinstance(row, dict):
            continue
        idx = _safe(row.get("index"))
        sts = row.get("sourcetypes", [])
        if not idx or not isinstance(sts, list):
            continue
        preview: list[dict[str, Any]] = []
        for st in sts[:20]:
            st_name = _safe(st)
            if not st_name:
                continue
            sem = semantics.get(st_name, {}) if isinstance(semantics.get(st_name), dict) else {}
            preview.append(
                {
                    "sourcetype": st_name,
                    "description": _safe(sem.get("description")),
                    "use_cases": sem.get("use_cases", []) if isinstance(sem.get("use_cases"), list) else [],
                    "known_fields": (
                        field_inventory.get(st_name, {}).get("interesting_fields", [])
                        if isinstance(field_inventory.get(st_name, {}), dict)
                        and isinstance(field_inventory.get(st_name, {}).get("interesting_fields", []), list)
                        else []
                    )[:10],
                    "known_field_examples": (
                        field_inventory.get(st_name, {}).get("interesting_field_examples", [])
                        if isinstance(field_inventory.get(st_name, {}), dict)
                        and isinstance(field_inventory.get(st_name, {}).get("interesting_field_examples", []), list)
                        else []
                    )[:6],
                }
            )
        out.append(
            {
                "index": idx,
                "sourcetypes": preview,
                "sourcetype_count": len([x for x in sts if _safe(x)]),
            }
        )
    return sorted(out, key=lambda x: x["index"])


def _build_intent_skills() -> list[dict[str, Any]]:
    skills: list[dict[str, Any]] = []
    for t in TEMPLATES:
        query = t.query
        # Keep non-internal default for wildcard templates.
        if "index=*" in query.lower() and "not index=_*" not in query.lower():
            query = query.replace("index=*", "index=* NOT index=_*")
        skills.append(
            {
                "intent": t.intent,
                "keywords": list(t.keywords),
                "tags": list(t.tags),
                "gold_query": query,
                "earliest_time": t.earliest_time,
                "latest_time": t.latest_time,
                "row_limit": t.row_limit,
                "summary_hint": t.summary_hint,
            }
        )
    return skills


def main() -> int:
    parser = argparse.ArgumentParser(description="Build SPL skillpack artifact")
    parser.add_argument("--profile", default=str(PROFILE_PATH_DEFAULT))
    parser.add_argument("--out", default=str(OUT_DEFAULT))
    args = parser.parse_args()

    profile = load_environment_profile(args.profile)
    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source_profile": str(args.profile),
        "gold_intent_skills": _build_intent_skills(),
        "domain_skills": _build_domain_skills(profile),
        "authoring_guidance": list(AUTHORING_GUIDANCE),
        "notes": [
            "Use discovered index+sourcetype combinations.",
            "Default to non-internal indexes unless question explicitly requests Splunk internal context.",
            "Prefer read-only SPL with bounded row_limit and explicit time windows.",
            "Prefer field-native queries when the environment profile shows the required fields already exist.",
        ],
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print("=== SPL Skillpack ===")
    print(f"out={out}")
    print(f"intent_skills={len(payload.get('gold_intent_skills', []))}")
    print(f"domain_skills={len(payload.get('domain_skills', []))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
