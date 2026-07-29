#!/usr/bin/env python3
"""Deterministic intent field-contract validation for SPL queries."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


def _query_text(query_args: dict[str, Any]) -> str:
    if not isinstance(query_args, dict):
        return ""
    return str(query_args.get("query", "")).strip().lower()


def _group_hit(query: str, tokens: tuple[str, ...]) -> bool:
    return any(tok in query for tok in tokens)


_AUTH_COHERENCE_INTENTS = frozenset(
    {
        "failed_login_activity",
        "successful_login_activity",
        "linux_auth_failures",
        "windows_auth_failures",
    }
)

_WINDOWS_EVENT_SIGNALS = ("eventcode=4625", "eventid=4625", "eventcode=4624", "eventid=4624")
_LINUX_ONLY_SOURCETYPE_TOKENS = ("linux_secure", 'source="/var/log/auth.log"', 'source="/var/log/secure"')
_WINDOWS_SOURCETYPE_TOKENS = ("xmlwineventlog", "wineventlog:security")


def _subsearch_segments(query: str) -> list[str]:
    parts = re.split(r"\|\s*append\s*\[\s*search\s+", query, flags=re.IGNORECASE)
    segments = [parts[0].strip()]
    for part in parts[1:]:
        branch = part.rsplit("]", 1)[0] if "]" in part else part
        segments.append(f"search {branch}".strip())
    return [segment for segment in segments if segment]


def validate_platform_sourcetype_coherence(query: str, intent: str) -> tuple[bool, str]:
    """Fail when Windows auth event IDs appear beside Linux-only sourcetypes."""
    query_l = str(query or "").strip().lower()
    intent_l = str(intent or "").strip().lower()
    if not query_l:
        return False, "coherence_query_missing"
    if intent_l not in _AUTH_COHERENCE_INTENTS:
        return True, "coherence_not_applicable"

    if re.search(r"linux_secure[^|\]]*(?:4625|4624|eventcode=4625|eventid=4625)", query_l):
        return False, "coherence_linux_secure_with_windows_4625"
    if re.search(r"(?:4625|4624|eventcode=4625|eventid=4625)[^|\]]*linux_secure", query_l):
        return False, "coherence_windows_4625_with_linux_secure"

    for segment in _subsearch_segments(query_l):
        has_windows_event = any(tok in segment for tok in _WINDOWS_EVENT_SIGNALS)
        has_linux_only_st = any(tok in segment for tok in _LINUX_ONLY_SOURCETYPE_TOKENS)
        has_windows_st = any(tok in segment for tok in _WINDOWS_SOURCETYPE_TOKENS)
        if has_windows_event and has_linux_only_st and not has_windows_st:
            return False, "coherence_windows_event_in_linux_branch"
        if has_linux_only_st and has_windows_event:
            return False, "coherence_mixed_platform_markers"

    if intent_l == "failed_login_activity" and "| append [" in query_l:
        linux_branch = 'eval platform="linux"' in query_l or "failed password" in query_l
        windows_branch = 'eval platform="windows"' in query_l or "4625" in query_l
        if not (linux_branch and windows_branch):
            return False, "coherence_cross_platform_missing_branch_markers"

    return True, "coherence_ok"


def validate_intent_platform_scope(
    query: str,
    intent: str,
    question: str = "",
    *,
    profile_path: str | Path | None = None,
) -> tuple[bool, str]:
    """Fail when a linux-only profile still carries cross-platform Windows auth append branches."""
    query_l = str(query or "").strip().lower()
    intent_l = str(intent or "").strip().lower()
    if not query_l or intent_l not in _AUTH_COHERENCE_INTENTS:
        return True, "scope_not_applicable"

    from environment_profile import (
        PROFILE_PATH_DEFAULT,
        _has_linux_only_domain,
        _has_windows_only_domain,
        load_environment_profile,
        resolve_authoritative_domains_for_question,
    )

    path = profile_path if profile_path is not None else PROFILE_PATH_DEFAULT
    profile = load_environment_profile(path)
    if not profile:
        return True, "scope_profile_missing_skip"

    routing_intent = intent_l
    if intent_l in {"linux_auth_failures", "linux_successful_logins"}:
        probe_intent = "failed_login_activity" if "fail" in intent_l else "successful_login_activity"
    elif intent_l in {"windows_auth_failures", "windows_successful_logons"}:
        probe_intent = "failed_login_activity" if "fail" in intent_l else "successful_login_activity"
    else:
        probe_intent = intent_l

    domains = resolve_authoritative_domains_for_question(
        question or "failed login activity",
        probe_intent,
        profile_path=path,
        max_domains=4,
    )
    if not domains:
        return True, "scope_no_domains_skip"

    has_linux_only = _has_linux_only_domain(domains)
    has_windows_only = _has_windows_only_domain(domains)
    if not (has_linux_only and not has_windows_only):
        return True, "scope_not_linux_only"

    if "| append [" not in query_l:
        return True, "scope_ok"

    if any(tok in query_l for tok in _WINDOWS_EVENT_SIGNALS) or "xmlwineventlog" in query_l:
        return False, "scope_linux_only_profile_with_windows_append"

    return True, "scope_ok"


def validate_query_for_intent(intent: str, query_args: dict[str, Any]) -> tuple[bool, str]:
    """Return True only when required intent-specific field/shape signals are present."""
    query = _query_text(query_args)
    intent_l = (intent or "").strip().lower()
    if not query:
        return False, "intent_contract_query_missing"

    # Common minimum shape for all run-query intents.
    if not query.startswith("search "):
        return False, "intent_contract_query_not_search_prefix"

    # Per-intent required token groups. Each tuple is "one-of" required.
    required_groups: dict[str, tuple[tuple[str, ...], ...]] = {
        "failed_login_activity": (
            ("failed", "action=failure", "info=failed", "failed password", "authentication failure", "eventtype=failed_login", "eventcode=4625", "eventid=4625"),
            ("stats ", "timechart "),
            ("user", "username", "targetusername", "subjectusername", "account_name", "user_name"),
            ("src", "src_ip", "clientip", "source_network_address", "ipaddress", "rhost"),
            ("platform",),
        ),
        "linux_auth_failures": (
            ("index=linux", "index=soc_linux", "sourcetype=auth.log", "sourcetype=linux_secure", 'source="/var/log/auth.log"', 'source="/var/log/secure"'),
            ("source=\"/var/log/auth.log\"", "source=\"/var/log/secure\"", "sourcetype=auth.log", "sourcetype=linux_secure", "eventtype=failed_login", "tag=authentication"),
            ("failed", "authentication failure", "invalid user"),
            ("stats ", "timechart "),
        ),
        "windows_auth_failures": (
            ("index=windows", "index=windows_sysmon"),
            ("sourcetype=xmlwineventlog",),
            ("eventcode=4625", "eventid=4625", "an account failed to log on"),
            ("table ", "stats ", "timechart "),
            ("user_name", "targetusername", "subjectusername", "account_name", "user"),
            ("src_ip", "source_network_address", "ipaddress", "src"),
        ),
        "windows_process_activity": (
            ("index=windows", "index=windows_sysmon", "index=botsv3"),
            ("sourcetype=xmlwineventlog", "sourcetype=XmlWinEventLog"),
            ("<eventid>1</eventid>", "eventid>1<"),
            ("image",),
            ("commandline",),
            ("parentimage",),
            ("stats ",),
        ),
        "windows_sysmon_network_activity": (
            ("index=windows_sysmon", "index=botsv3"),
            ("sourcetype=xmlwineventlog",),
            ("channel=\"microsoft-windows-sysmon/operational\"", "eventid=3", "eventcode=3", "destinationip=*"),
            ("destinationip",),
            ("destinationport",),
            ("protocol",),
            ("image",),
            ("table ",),
        ),
        "windows_sysmon_dns_activity": (
            ("index=windows_sysmon", "index=botsv3"),
            ("sourcetype=xmlwineventlog",),
            ("channel=\"microsoft-windows-sysmon/operational\"", "eventid=22", "eventcode=22", "queryname=*"),
            ("queryname",),
            ("queryresults",),
            ("image",),
            ("table ",),
        ),
        "windows_credential_access_activity": (
            ("index=windows", "index=botsv3", "index=soc_windows"),
            ("sourcetype=xmlwineventlog",),
            ("5379", "countofcredentialsreturned"),
            ("subjectusername",),
            ("targetname",),
            ("table ",),
        ),
        "windows_process_audit_activity": (
            ("index=windows", "index=botsv3", "index=soc_windows"),
            ("sourcetype=xmlwineventlog",),
            ("4688",),
            ("new_process_name", "process_command_line"),
            ("table ",),
        ),
        "windows_privilege_assigned_activity": (
            ("index=windows", "index=botsv3", "index=soc_windows"),
            ("sourcetype=xmlwineventlog",),
            ("4672", "privilegelist"),
            ("table ",),
        ),
        "windows_successful_logons": (
            ("index=windows", "index=botsv3", "index=soc_windows"),
            ("sourcetype=xmlwineventlog",),
            ("4624", "successfully logged on"),
            ("table ",),
        ),
        "linux_privilege_escalation": (
            ("index=linux", "index=botsv3"),
            ("source=\"/var/log/auth.log\"", "source=\"/var/log/secure\"", "sourcetype=auth.log", "sourcetype=linux_secure"),
            ("sudo", " su "),
            ("stats ", "timechart "),
            ("process_name",),
        ),
        "linux_privilege_escalation_activity": (
            ("index=linux", "index=botsv3"),
            ("source=\"/var/log/auth.log\"", "source=\"/var/log/secure\"", "sourcetype=auth.log", "sourcetype=linux_secure"),
            ("sudo:", "su:", "pam_unix(sudo:session)", "pam_unix(su:session)", "command="),
            ("table ",),
            ("process_name",),
            ("outcome",),
            ("actor",),
            ("target_user",),
        ),
        "linux_session_activity": (
            ("index=",),
            ("source=\"/var/log/auth.log\"", "source=\"/var/log/secure\"", "sourcetype=auth.log", "sourcetype=linux_secure"),
            ("session opened for user", "session closed for user", "pam_unix(cron:session)"),
            ("session_state",),
            ("actor",),
            ("tty",),
            ("src_ip",),
            ("table ",),
        ),
        "linux_audit_activity": (
            ("index=linux", "index=botsv3"),
            ("sourcetype=linux_audit",),
            ("audit_type",),
            ("audit_op",),
            ("audit_res",),
            ("stats ",),
        ),
        "linux_privilege_escalation_first_seen": (
            ("index=linux", "index=botsv3"),
            ("source=\"/var/log/auth.log\"", "source=\"/var/log/secure\"", "sourcetype=auth.log", "sourcetype=linux_secure"),
            ("session opened for user root by", "command=", "pam_unix(sudo:session)", "pam_unix(su:session)", "sudo:", "su:"),
            ("earliest(_time)", "min(_time)"),
            ("first_seen",),
            ("stats ",),
        ),
        "apache_access_top_ips": (
            ("index=",),
            ("sourcetype=access_combined", "sourcetype=apache:access"),
            ("clientip", "src_ip"),
            ("stats ",),
        ),
        "apache_404_spike": (
            ("index=",),
            ("sourcetype=access_combined", "sourcetype=apache:access"),
            ("status=404",),
            ("timechart ", "bin "),
        ),
        "apache_suspicious_user_agents": (
            ("index=",),
            ("sourcetype=access_combined", "sourcetype=apache:access"),
            ("useragent", "http_user_agent"),
            ("stats ",),
        ),
        "aws_cloudtrail_activity": (
            ("index=",),
            ("sourcetype=aws:cloudtrail",),
            ("eventsource",),
            ("eventname",),
            ("principal",),
            ("stats ",),
        ),
        "cisco_asa_network_flows": (
            ("index=main", "index=botsv3"),
            ("sourcetype=cisco:asa",),
            ("action",),
            ("src_ip",),
            ("dest_ip",),
            ("stats ",),
        ),
        "stream_http_activity": (
            ("index=main", "index=botsv3"),
            ("sourcetype=stream:http",),
            ("spath ",),
            ("http_method",),
            ("status",),
            ("site",),
            ("src_ip",),
            ("stats ",),
        ),
        "osquery_process_activity": (
            ("index=main", "index=botsv3"),
            ("sourcetype=osquery:results",),
            ("spath ",),
            ("hostidentifier",),
            ("path",),
            ("cmdline",),
            ("stats ",),
        ),
        "aws_vpc_flow_activity": (
            ("index=",),
            ("sourcetype=aws:cloudwatchlogs:vpcflow",),
            ("rex ",),
            ("action",),
            ("src_ip",),
            ("dest_ip",),
            ("dest_port",),
            ("stats ",),
        ),
        "aad_signin_activity": (
            ("index=",),
            ("sourcetype=ms:aad:signin",),
            ("spath ",),
            ("userprincipalname",),
            ("ipaddress",),
            ("appdisplayname",),
            ("loginstatus",),
            ("stats ",),
        ),
        "stream_dns_activity": (
            ("index=",),
            ("sourcetype=stream:dns",),
            ("spath ",),
            ("query",),
            ("reply_code",),
            ("src_ip",),
            ("dest_ip",),
            ("stats ",),
        ),
        "o365_management_activity": (
            ("index=",),
            ("sourcetype=ms:o365:management", "sourcetype=o365:management:activity"),
            ("spath ",),
            ("userid",),
            ("operation",),
            ("workload",),
            ("clientip",),
            ("stats ",),
        ),
        "botsv3_named_sourcetype_overview": (
            ("index=main", "index=botsv3"),
            ("sourcetype=",),
            ("stats ",),
            (" by host",),
            (" source",),
        ),
        "top_indexes": (
            ("index=*", "index=botsv3"),
            ("stats ",),
            (" by index",),
        ),
        "internal_sourcetypes": (
            ("index=_internal",),
            ("stats ",),
            (" by sourcetype",),
        ),
        "internal_auth_failures": (
            ("index=_audit",),
            ("sourcetype=audittrail",),
            ("info=failed",),
            ("stats ",),
            (" by user", " by src", " by user src", " by host user src"),
        ),
    }

    groups = required_groups.get(intent_l)
    if not groups:
        return True, "intent_contract_not_defined_skip"

    for idx, group in enumerate(groups, start=1):
        if not _group_hit(query, group):
            return False, f"intent_contract_missing_group_{idx}"

    if intent_l == "linux_auth_failures":
        if "match(" in query and "?<" in query:
            return False, "intent_contract_linux_auth_invalid_match_capture"
        if "eval user_name=case(" in query or "eval src_ip=case(" in query:
            return False, "intent_contract_linux_auth_overengineered_eval"
        if "stats count by host user src_ip port" not in query and "stats count by host sourcetype user src_ip port" not in query:
            return False, "intent_contract_linux_auth_missing_field_native_stats"

    # Extra guard: apache intent should not drift to known wrong index aliases.
    if intent_l in {"apache_access_top_ips", "apache_404_spike", "apache_suspicious_user_agents"}:
        if any(bad in query for bad in ("index=apache", "index=apache_access_logs", "index=linux_perf")):
            return False, "intent_contract_apache_wrong_index_alias"

    if intent_l in _AUTH_COHERENCE_INTENTS:
        coherent, coherence_reason = validate_platform_sourcetype_coherence(query, intent_l)
        if not coherent:
            return False, coherence_reason

    return True, "intent_contract_ok"
