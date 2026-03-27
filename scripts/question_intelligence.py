#!/usr/bin/env python3
"""Deterministic question-family parsing for query routing and SPL grounding."""

from __future__ import annotations

import re
from typing import Any


def infer_question_dimensions(question: str) -> dict[str, Any]:
    q = (question or "").strip().lower()
    tokens = {t for t in re.findall(r"[a-z0-9_]+", q)}

    platforms: list[str] = []
    if any(tok in q for tok in ("windows", "wineventlog", "xmlwineventlog", "eventcode", "event id", "sysmon")):
        platforms.append("windows")
    if any(tok in q for tok in ("linux", "ubuntu", "rpi5", "auth.log", "auth-4", "auth-too_small", "linux_secure", "/var/log/auth.log", "sudo", "su ", " ssh", "ssh ")):
        platforms.append("linux")
    if any(tok in q for tok in ("apache", "access_combined", "http", "web", "404", "user agent", "useragent")):
        platforms.append("web")
    if any(tok in q for tok in ("stream:http", "stream http", "http methods", "destination sites")) and "web" not in platforms:
        platforms.append("web")
    if any(tok in q for tok in ("cloudtrail", "aws cloudtrail", "aws api", "eventname", "eventsource")):
        platforms.append("aws")
    if any(tok in q for tok in ("vpc flow", "vpc flows", "cloudwatchlogs:vpcflow")) and "aws" not in platforms:
        platforms.append("aws")
    if any(tok in q for tok in ("cisco asa", "asa firewall", "blocked flows", "firewall flows")):
        platforms.append("network")
    if any(tok in q for tok in ("stream:dns", "stream dns", "dns activity", "dns query")) and "network" not in platforms:
        platforms.append("network")
    if any(tok in q for tok in ("azure ad", "aad sign-in", "aad signin", "ms:aad:signin")):
        platforms.append("identity")
    if any(tok in q for tok in ("splunk internal", "_audit", "_internal", "splunk platform", "scheduler", "audittrail")):
        platforms.append("splunk_internal")
    if "internal auth" in q and "splunk_internal" not in platforms:
        platforms.append("splunk_internal")
    if "splunk" in q and any(tok in q for tok in (" login", "logins", "auth", "authentication")) and "splunk_internal" not in platforms:
        platforms.append("splunk_internal")
    if not platforms:
        platforms.append("cross_domain")

    activities: list[str] = []
    if any(
        tok in q
        for tok in (
            "failed login",
            "failed logon",
            "authentication failure",
            "auth failure",
            "failed password",
            "password spray",
            "brute force",
            "brute-force",
            "bruteforce",
        )
    ):
        activities.append("auth_failure")
    if any(tok in q for tok in ("sudo", " su ", "privilege escalation", "root session", "session opened for user root by")):
        activities.append("privilege_escalation")
    if any(tok in q for tok in ("process creation", "process activity", "sysmon process", "new processes")):
        activities.append("process_activity")
    if any(tok in q for tok in ("sysmon network", "network connections", "event id 3", "sysmon event 3")):
        activities.append("network_activity")
    if any(tok in q for tok in ("sysmon dns", "dns queries", "event id 22", "sysmon event 22")):
        activities.append("dns_activity")
    if any(tok in q for tok in ("credential access", "credential manager", "stored credentials", "event 5379")):
        activities.append("credential_access")
    if any(tok in q for tok in ("session opened", "session closed", "cron session", "pam_unix session")):
        activities.append("session_activity")
    if any(tok in q for tok in ("linux audit", "auditd", "linux_audit", "audit operations")):
        activities.append("audit_activity")
    if any(tok in q for tok in ("client ip", "top ips", "source ip", "web access", "access log")):
        activities.append("web_access")
    if "404" in q:
        activities.append("web_404")
    if any(tok in q for tok in ("user agent", "useragent", "bot", "scanner")):
        activities.append("user_agent")
    if any(tok in q for tok in ("cloudtrail", "aws api", "eventname", "eventsource", "iam activity")):
        activities.append("cloud_api")
    if any(tok in q for tok in ("vpc flow", "vpc flows", "accepted and rejected flows", "cloudwatchlogs:vpcflow")):
        activities.append("network_flow")
    if any(tok in q for tok in ("cisco asa", "blocked flows", "firewall flows", "blocked traffic")):
        activities.append("network_flow")
    if any(tok in q for tok in ("osquery", "process monitoring", "added processes")):
        activities.append("process_activity")
    if any(tok in q for tok in ("azure ad sign-in", "azure ad signin", "aad sign-in", "aad signin", "login status")):
        activities.append("signin_activity")
    if any(tok in q for tok in ("stream:dns", "stream dns", "dns activity", "reply code", "dns query")):
        activities.append("dns_activity")
    if any(tok in q for tok in ("office 365 management", "o365 management", "sharepoint activity", "onedrive activity", "ms:o365:management")):
        activities.append("saas_activity")
    if any(tok in q for tok in ("index", "indexes")):
        activities.append("inventory")
    if any(tok in q for tok in ("sourcetype", "sourcetypes", "metadata", "hosts metadata", "sources metadata")):
        activities.append("metadata")

    shapes: list[str] = []
    if any(tok in q for tok in ("first time", "first seen", "newly observed", "first observed", "new ")):
        shapes.append("first_seen")
    if any(tok in q for tok in ("top", "most", "highest")):
        shapes.append("top_n")
    if any(tok in q for tok in ("timeline", "spike", "trend", "over time")):
        shapes.append("time_series")
    if any(tok in q for tok in ("investigate", "drill down", "what happened")):
        shapes.append("investigate")
    if not shapes:
        shapes.append("summary")

    entities: list[str] = []
    if any(tok in tokens for tok in ("host", "hosts")):
        entities.append("host")
    if any(tok in tokens for tok in ("user", "users", "username")):
        entities.append("user")
    if any(tok in tokens for tok in ("src", "ip", "clientip", "source")):
        entities.append("src_ip")

    return {
        "platforms": platforms,
        "activities": activities,
        "shapes": shapes,
        "entities": entities,
        "tokens": sorted(tokens),
    }


def score_template_for_question(template: Any, question: str) -> tuple[int, list[str]]:
    dims = infer_question_dimensions(question)
    q = (question or "").lower()
    score = 0
    reasons: list[str] = []

    matched_keywords = [kw for kw in getattr(template, "keywords", ()) if kw in q]
    if matched_keywords:
        score += 10 * len(matched_keywords)
        reasons.append(f"keyword_hits={len(matched_keywords)}")

    tags = {str(t).strip().lower() for t in getattr(template, "tags", ()) if str(t).strip()}
    platforms = set(dims.get("platforms", []))
    activities = set(dims.get("activities", []))
    shapes = set(dims.get("shapes", []))

    if tags & platforms:
        score += 18
        reasons.append(f"platform_match={','.join(sorted(tags & platforms))}")
    if tags & activities:
        score += 18
        reasons.append(f"activity_match={','.join(sorted(tags & activities))}")
    if tags & shapes:
        score += 10
        reasons.append(f"shape_match={','.join(sorted(tags & shapes))}")

    intent = str(getattr(template, "intent", "")).lower()
    if "windows" in platforms and intent.startswith("linux_"):
        score -= 25
        reasons.append("platform_penalty:linux_for_windows_question")
    if "linux" in platforms and intent.startswith("windows_"):
        score -= 25
        reasons.append("platform_penalty:windows_for_linux_question")
    if "web" in platforms and "access_combined" not in str(getattr(template, "query", "")).lower() and intent.startswith("apache_"):
        score -= 10
        reasons.append("web_template_missing_access_combined")
    if "first_seen" in shapes and "first_seen" not in intent:
        score -= 15
        reasons.append("shape_penalty:first_seen_mismatch")
    if "first_seen" in shapes and intent == "linux_privilege_escalation_first_seen":
        score += 18
        reasons.append("first_seen_priv_esc_bonus")
    if "first_seen" not in shapes and "first_seen" in intent:
        score -= 12
        reasons.append("shape_penalty:avoid_first_seen_without_explicit_signal")
    if "auth_failure" in activities and "auth" not in intent and "failed_login" not in intent:
        score -= 8
        reasons.append("activity_penalty:auth_failure_mismatch")
    if "ssh" in q and "auth_failure" in activities and intent == "linux_auth_failures":
        score += 15
        reasons.append("ssh_auth_bonus")
    if "web" in platforms and "auth_failure" in activities and intent.startswith("apache_"):
        score -= 12
        reasons.append("web_auth_penalty:prefer_auth_templates_over_apache_access")
    if "splunk_internal" in platforms and intent == "failed_login_activity":
        score -= 15
        reasons.append("internal_penalty:prefer_splunk_internal_specific_templates")
    if "crawler" in q and intent == "apache_suspicious_user_agents":
        score += 10
        reasons.append("crawler_bonus")
    if "crawler" in q and intent == "apache_access_top_ips":
        score -= 8
        reasons.append("crawler_penalty:prefer_user_agent_intent")
    if "failed privilege escalation" in q and intent == "linux_privilege_escalation":
        score += 15
        reasons.append("failed_priv_esc_bonus")
    if any(tok in q for tok in ("sudo behavior", "sudo activity", "su behavior", "su activity", "root session", "sudo sessions")):
        if intent == "linux_privilege_escalation_activity":
            score += 18
            reasons.append("priv_esc_activity_bonus")
        if intent == "linux_privilege_escalation":
            score -= 10
            reasons.append("priv_esc_activity_penalty:avoid_failed_only_template")
        if "first_seen" in shapes and intent == "linux_privilege_escalation_activity":
            score -= 14
            reasons.append("priv_esc_activity_penalty:prefer_first_seen_when_requested")
    if "bot" in q and intent == "apache_suspicious_user_agents":
        score += 12
        reasons.append("bot_bonus")
    if "bot" in q and intent == "apache_access_top_ips":
        score -= 8
        reasons.append("bot_penalty:prefer_user_agent_intent")
    if any(tok in q for tok in ("stream:http", "stream http", "http methods", "destination sites")):
        if intent == "stream_http_activity":
            score += 18
            reasons.append("stream_http_bonus")
        if intent == "apache_access_top_ips":
            score -= 10
            reasons.append("stream_http_penalty:prefer_stream_http")
    if any(tok in q for tok in ("osquery", "process monitoring", "added processes")):
        if intent == "osquery_process_activity":
            score += 18
            reasons.append("osquery_process_bonus")
    if any(tok in q for tok in ("vpc flow", "vpc flows", "accepted and rejected flows", "cloudwatchlogs:vpcflow")):
        if intent == "aws_vpc_flow_activity":
            score += 18
            reasons.append("vpc_flow_bonus")
        if intent == "aws_cloudtrail_activity":
            score -= 15
            reasons.append("vpc_flow_penalty:avoid_cloudtrail")
    if any(tok in q for tok in ("azure ad", "aad sign-in", "aad signin", "login status")):
        if intent == "aad_signin_activity":
            score += 18
            reasons.append("aad_signin_bonus")
    if any(tok in q for tok in ("process creation", "process activity", "sysmon process", "new processes")):
        if intent == "windows_process_activity":
            score += 18
            reasons.append("windows_process_bonus")
    if any(tok in q for tok in ("sysmon network", "network connections", "event id 3", "sysmon event 3")):
        if intent == "windows_sysmon_network_activity":
            score += 18
            reasons.append("windows_sysmon_network_bonus")
    if any(tok in q for tok in ("sysmon dns", "dns queries", "event id 22", "sysmon event 22")):
        if intent == "windows_sysmon_dns_activity":
            score += 18
            reasons.append("windows_sysmon_dns_bonus")
    if any(tok in q for tok in ("credential access", "credential manager", "stored credentials", "event 5379")):
        if intent == "windows_credential_access_activity":
            score += 18
            reasons.append("windows_credential_bonus")
    if any(tok in q for tok in ("session opened", "session closed", "cron session", "pam_unix session")):
        if intent == "linux_session_activity":
            score += 18
            reasons.append("linux_session_bonus")
    if any(tok in q for tok in ("linux audit", "auditd", "linux_audit", "audit operations")):
        if intent == "linux_audit_activity":
            score += 18
            reasons.append("linux_audit_bonus")
    if any(tok in q for tok in ("stream:dns", "stream dns", "dns activity", "reply code", "dns query")):
        if intent == "stream_dns_activity":
            score += 18
            reasons.append("stream_dns_bonus")
    if any(tok in q for tok in ("office 365 management", "o365 management", "sharepoint activity", "onedrive activity", "ms:o365:management")):
        if intent == "o365_management_activity":
            score += 18
            reasons.append("o365_management_bonus")
        if intent == "aad_signin_activity":
            score -= 12
            reasons.append("o365_management_penalty:avoid_aad_signin")
    if "cloudtrail" in q and any(tok in q for tok in ("event name", "service", "eventname", "eventsource")):
        if intent == "aws_cloudtrail_activity":
            score += 20
            reasons.append("cloudtrail_event_service_bonus")
        if intent in {"inventory", "metadata_inventory", "top_indexes"}:
            score -= 15
            reasons.append("cloudtrail_event_service_penalty:avoid_metadata_inventory")

    return score, reasons


def build_question_profile_text(question: str) -> str:
    dims = infer_question_dimensions(question)
    lines = ["[QUESTION_PROFILE]"]
    lines.append(f"- platforms={', '.join(dims.get('platforms', [])) or 'none'}")
    lines.append(f"- activities={', '.join(dims.get('activities', [])) or 'none'}")
    lines.append(f"- shapes={', '.join(dims.get('shapes', [])) or 'none'}")
    if dims.get("entities"):
        lines.append(f"- entities={', '.join(dims.get('entities', []))}")
    return "\n".join(lines)


def infer_time_window(question: str, *, default_earliest: str = "-24h", default_latest: str = "now") -> tuple[str, str]:
    q = (question or "").strip().lower()
    if not q:
        return default_earliest, default_latest

    for pattern, unit in (
        (r"last\s+(\d+)\s+hour", "h"),
        (r"last\s+(\d+)\s+hours", "h"),
        (r"last\s+(\d+)\s+day", "d"),
        (r"last\s+(\d+)\s+days", "d"),
        (r"last\s+(\d+)\s+minute", "m"),
        (r"last\s+(\d+)\s+minutes", "m"),
    ):
        match = re.search(pattern, q)
        if match:
            count = int(match.group(1))
            return f"-{count}{unit}", "now"

    if "last week" in q:
        return "-7d", "now"
    if "last day" in q:
        return "-1d", "now"
    if "last hour" in q:
        return "-1h", "now"
    if "all time" in q or "full botsv3 dataset" in q or "entire botsv3 dataset" in q:
        return "0", "now"
    if "today" in q:
        return "@d", "now"
    if "yesterday" in q:
        return "-1d@d", "@d"
    return default_earliest, default_latest
