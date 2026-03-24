#!/usr/bin/env python3
"""Deterministic intent field-contract validation for SPL queries."""

from __future__ import annotations

from typing import Any


def _query_text(query_args: dict[str, Any]) -> str:
    if not isinstance(query_args, dict):
        return ""
    return str(query_args.get("query", "")).strip().lower()


def _group_hit(query: str, tokens: tuple[str, ...]) -> bool:
    return any(tok in query for tok in tokens)


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
            ("index=linux",),
            ("sourcetype=auth.log", "sourcetype=auth-4", "sourcetype=linux_secure", "eventtype=failed_login", "tag=authentication"),
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
            ("index=windows",),
            ("sourcetype=xmlwineventlog",),
            ("5379", "countofcredentialsreturned"),
            ("subjectusername",),
            ("targetname",),
            ("table ",),
        ),
        "linux_privilege_escalation": (
            ("index=linux",),
            ("sourcetype=auth.log", "sourcetype=auth-4", "sourcetype=linux_secure"),
            ("sudo", " su "),
            ("stats ", "timechart "),
            ("process_name",),
        ),
        "linux_privilege_escalation_activity": (
            ("index=linux",),
            ("sourcetype=auth.log", "sourcetype=auth-4", "sourcetype=linux_secure"),
            ("sudo:", "su:", "pam_unix(sudo:session)", "pam_unix(su:session)", "command="),
            ("table ",),
            ("process_name",),
            ("outcome",),
            ("actor",),
            ("target_user",),
        ),
        "linux_session_activity": (
            ("index=linux",),
            ("sourcetype=auth.log", "sourcetype=auth-4"),
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
            ("index=linux",),
            ("sourcetype=auth.log", "sourcetype=auth-4", "sourcetype=linux_secure"),
            ("session opened for user root by", "command=", "pam_unix(sudo:session)", "pam_unix(su:session)", "sudo:", "su:"),
            ("earliest(_time)", "min(_time)"),
            ("first_seen",),
            ("stats ",),
        ),
        "apache_access_top_ips": (
            ("index=linux",),
            ("sourcetype=access_combined",),
            ("clientip", "src_ip"),
            ("stats ",),
        ),
        "apache_404_spike": (
            ("index=linux",),
            ("sourcetype=access_combined",),
            ("status=404",),
            ("timechart ", "bin "),
        ),
        "apache_suspicious_user_agents": (
            ("index=linux",),
            ("sourcetype=access_combined",),
            ("useragent", "http_user_agent"),
            ("stats ",),
        ),
        "aws_cloudtrail_activity": (
            ("index=main", "index=botsv3"),
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
            ("index=main", "index=botsv3"),
            ("sourcetype=aws:cloudwatchlogs:vpcflow",),
            ("rex ",),
            ("action",),
            ("src_ip",),
            ("dest_ip",),
            ("dest_port",),
            ("stats ",),
        ),
        "aad_signin_activity": (
            ("index=main", "index=botsv3"),
            ("sourcetype=ms:aad:signin",),
            ("spath ",),
            ("userprincipalname",),
            ("ipaddress",),
            ("appdisplayname",),
            ("loginstatus",),
            ("stats ",),
        ),
        "stream_dns_activity": (
            ("index=main", "index=botsv3"),
            ("sourcetype=stream:dns",),
            ("spath ",),
            ("query",),
            ("reply_code",),
            ("src_ip",),
            ("dest_ip",),
            ("stats ",),
        ),
        "o365_management_activity": (
            ("index=main", "index=botsv3"),
            ("sourcetype=ms:o365:management",),
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

    return True, "intent_contract_ok"
