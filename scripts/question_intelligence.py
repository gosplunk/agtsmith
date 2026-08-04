#!/usr/bin/env python3
"""Deterministic question-family parsing for query routing and SPL grounding."""

from __future__ import annotations

import re
from typing import Any

from apache_intent import APACHE_INTENTS, apache_intent_profile


# One canonical bounded window is used whenever a question does not state a
# time range. Explicit question ranges always take precedence over this
# contract, including partial earliest/latest literals.
DEFAULT_UNBOUNDED_EARLIEST = "-7d"
DEFAULT_UNBOUNDED_LATEST = "now"


def infer_question_dimensions(question: str) -> dict[str, Any]:
    q = (question or "").strip().lower()
    tokens = {t for t in re.findall(r"[a-z0-9_]+", q)}

    platforms: list[str] = []
    if any(tok in q for tok in ("windows", "wineventlog", "xmlwineventlog", "eventcode", "event id", "sysmon")):
        platforms.append("windows")
    if any(tok in q for tok in ("linux", "ubuntu", "rpi5", "auth.log", "auth-4", "linux_secure", "/var/log/auth.log", "sudo", "su ", " ssh", "ssh ")):
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
    if (
        any(
            tok in q
            for tok in (
                "successful login",
                "successful logon",
                "successful authentication",
                "successfully logged on",
                "accepted password",
                "accepted publickey",
                "4624",
                "logon success",
                "successful ssh",
            )
        )
        or ("successful" in q and any(tok in q for tok in ("login", "logon", "authentication", "ssh")))
    ):
        activities.append("auth_success")
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
    if any(tok in q for tok in ("client ip", "top ips", "source ip", "web access", "access log", "hits", "hit count", "page views", "requests")):
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
    if any(
        phrase in q
        for phrase in (
            "how many",
            "how much",
            "total number",
            "total count",
            "count of",
            "number of",
        )
    ):
        shapes.append("cardinality")
    if any(tok in q for tok in ("first time", "first seen", "newly observed", "first observed", "new ")):
        shapes.append("first_seen")
    if "cardinality" not in shapes and any(tok in q for tok in ("top", "most", "highest")):
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

    apache_profile = apache_intent_profile(question)
    return {
        "platforms": platforms,
        "activities": activities,
        "shapes": shapes,
        "entities": entities,
        "tokens": sorted(tokens),
        "apache_intent": apache_profile.get("intent", ""),
        "requested_roles": apache_profile.get("roles", []),
        "suspicious_required": bool(apache_profile.get("suspicious_required")),
    }


def question_requests_privilege_first_seen(question: str) -> bool:
    """Return whether a Linux privilege question requires first-seen aggregation."""
    dims = infer_question_dimensions(question)
    activities = set(dims.get("activities", []))
    shapes = set(dims.get("shapes", []))
    return "privilege_escalation" in activities and "first_seen" in shapes


def score_template_for_question(template: Any, question: str) -> tuple[int, list[str]]:
    dims = infer_question_dimensions(question)
    q = (question or "").lower()
    tokens = {t for t in re.findall(r"[a-z0-9_]+", q)}
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
    if "auth_success" in activities and "success" not in intent and "session" not in intent:
        score -= 8
        reasons.append("activity_penalty:auth_success_mismatch")
    if "auth_success" in activities and "failed_login" in intent:
        score -= 28
        reasons.append("success_penalty:avoid_failed_login_templates")
    if "auth_success" in activities and intent in {"successful_login_activity", "linux_successful_logins", "windows_successful_logons"}:
        score += 22
        reasons.append("auth_success_bonus")
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
    if "apache" in q and any(tok in q for tok in ("weird", "suspicious", "odd", "strange", "anomal")):
        if intent == "apache_suspicious_user_agents":
            score += 16
            reasons.append("apache_weirdness_bonus")
        if intent == "apache_access_top_ips":
            score -= 6
            reasons.append("apache_weirdness_penalty:prefer_suspicious_user_agents")
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
    if {"bot", "bots"} & tokens and intent == "apache_suspicious_user_agents":
        score += 12
        reasons.append("bot_bonus")
    if {"bot", "bots"} & tokens and intent == "apache_access_top_ips":
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
    if any(tok in q for tok in ("4688", "security audit process", "process creation audit", "audit process creation")):
        if intent == "windows_process_audit_activity":
            score += 22
            reasons.append("windows_process_audit_bonus")
        if intent == "windows_process_activity":
            score -= 15
            reasons.append("windows_process_audit_penalty:prefer_4688_audit")
    if any(tok in q for tok in ("4672", "special privileges assigned", "privileges assigned to new logon")):
        if intent == "windows_privilege_assigned_activity":
            score += 22
            reasons.append("windows_privilege_assigned_bonus")
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
    if "cardinality" in shapes:
        if "top_n" in tags and "top_n" in shapes:
            score -= 18
            reasons.append("cardinality_penalty:avoid_top_n_templates")
        if "first_seen" in intent:
            score -= 16
            reasons.append("cardinality_penalty:avoid_first_seen_templates")
        if "summary" in tags or intent.endswith("_activity"):
            score += 8
            reasons.append("cardinality_bonus:summary_shape")
        if "apache" in q and "web_access" in activities:
            if intent == "apache_access_top_ips":
                score += 22
                reasons.append("cardinality_apache_hits_bonus")
            if intent == "stream_http_activity":
                score -= 18
                reasons.append("cardinality_apache_penalty:prefer_access_top_ips")

    return score, reasons


def build_question_profile_text(question: str) -> str:
    dims = infer_question_dimensions(question)
    lines = ["[QUESTION_PROFILE]"]
    lines.append(f"- platforms={', '.join(dims.get('platforms', [])) or 'none'}")
    lines.append(f"- activities={', '.join(dims.get('activities', [])) or 'none'}")
    lines.append(f"- shapes={', '.join(dims.get('shapes', [])) or 'none'}")
    if "cardinality" in dims.get("shapes", []):
        lines.append("- cardinality_hint=return scalar total via '| stats count' (avoid table or count-by breakdowns)")
    if dims.get("entities"):
        lines.append(f"- entities={', '.join(dims.get('entities', []))}")
    if dims.get("apache_intent"):
        lines.append(f"- apache_intent={dims.get('apache_intent')}")
    if dims.get("requested_roles"):
        lines.append(f"- required_output_roles={', '.join(dims.get('requested_roles', []))}")
    if dims.get("suspicious_required"):
        lines.append("- suspicious_criteria_required=true (a plain traffic summary is incomplete)")
    if question_requests_all_time(question):
        lines.append("- time_window_hint=earliest_time=0 latest_time=now (question requests all available history)")
    elif question_has_explicit_relative_window(question):
        earliest, latest = infer_time_window(question)
        lines.append(f"- time_window_hint=earliest_time={earliest} latest_time={latest}")
    else:
        lines.append(
            "- time_window_hint="
            f"earliest_time={DEFAULT_UNBOUNDED_EARLIEST} latest_time={DEFAULT_UNBOUNDED_LATEST} "
            "(default when no range is stated); "
            f"{describe_supported_time_windows()}"
        )
    return "\n".join(lines)


def _normalize_time_question(question: str) -> str:
    q = (question or "").strip().lower()
    q = q.replace("'", "'").replace("'", "'")
    q = re.sub(r"\s+", " ", q)
    return q


_SPLUNK_TIME_UNIT: dict[str, str] = {
    "second": "s",
    "seconds": "s",
    "sec": "s",
    "secs": "s",
    "minute": "m",
    "minutes": "m",
    "min": "m",
    "mins": "m",
    "hour": "h",
    "hours": "h",
    "hr": "h",
    "hrs": "h",
    "day": "d",
    "days": "d",
    "week": "w",
    "weeks": "w",
    "wk": "w",
    "wks": "w",
    "month": "mon",
    "months": "mon",
    "mon": "mon",
    "quarter": "q",
    "quarters": "q",
    "qtr": "q",
    "qtrs": "q",
    "year": "y",
    "years": "y",
    "yr": "y",
    "yrs": "y",
}

_RELATIVE_COUNT_RE = re.compile(
    r"\b(?:in\s+the\s+|within\s+the\s+|over\s+the\s+|during\s+the\s+|for\s+the\s+)?"
    r"(?:last|past|previous|recent)\s+(\d+)\s+"
    r"(second|seconds|sec|secs|minute|minutes|min|mins|hour|hours|hr|hrs|"
    r"day|days|week|weeks|wk|wks|month|months|mon|quarter|quarters|qtr|qtrs|year|years|yr|yrs)\b"
)

_AGO_COUNT_RE = re.compile(
    r"\b(\d+)\s+"
    r"(second|seconds|sec|secs|minute|minutes|min|mins|hour|hours|hr|hrs|"
    r"day|days|week|weeks|wk|wks|month|months|mon|quarter|quarters|qtr|qtrs|year|years|yr|yrs)\s+ago\b"
)

_SINCE_AGO_RE = re.compile(
    r"\bsince\s+(\d+)\s+"
    r"(second|seconds|sec|secs|minute|minutes|min|mins|hour|hours|hr|hrs|"
    r"day|days|week|weeks|wk|wks|month|months|mon|quarter|quarters|qtr|qtrs|year|years|yr|yrs)\s+ago\b"
)

_SINCE_WEEKDAY_RE = re.compile(
    r"\bsince\s+(last\s+)?(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b"
)

_SPLUNK_LITERAL_RE = re.compile(
    r"\b(?:earliest(?:_time)?|latest(?:_time)?)\s*[=:]\s*([^\s,;|]+)",
    flags=re.IGNORECASE,
)

_ISO_DATE_RE = re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b")
_US_DATE_RE = re.compile(r"\b(\d{1,2})/(\d{1,2})/(\d{4})\b")

_WEEKDAY_TO_SPLUNK: dict[str, str] = {
    "sunday": "@w0",
    "monday": "@w1",
    "tuesday": "@w2",
    "wednesday": "@w3",
    "thursday": "@w4",
    "friday": "@w5",
    "saturday": "@w6",
}

# Longer phrases first when scanning substring maps.
_NAMED_BOUNDED_WINDOWS: tuple[tuple[str, str, str], ...] = (
    ("day before yesterday", "-2d@d", "-1d@d"),
    ("last 24 hours", "-24h", "now"),
    ("past 24 hours", "-24h", "now"),
    ("previous 24 hours", "-24h", "now"),
    ("last 48 hours", "-48h", "now"),
    ("last 72 hours", "-72h", "now"),
    ("last 90 days", "-90d", "now"),
    ("past 90 days", "-90d", "now"),
    ("last 30 days", "-30d", "now"),
    ("past 30 days", "-30d", "now"),
    ("last 60 days", "-60d", "now"),
    ("last 12 months", "-12mon", "now"),
    ("last 6 months", "-6mon", "now"),
    ("last 3 months", "-3mon", "now"),
    ("year to date", "@y", "now"),
    ("month to date", "@mon", "now"),
    ("quarter to date", "@q", "now"),
    ("so far today", "@d", "now"),
    ("today so far", "@d", "now"),
    ("this morning", "@d", "now"),
    ("this afternoon", "@d", "now"),
    ("this evening", "@d", "now"),
    ("over the weekend", "-2d@w6", "@w0"),
    ("during the weekend", "-2d@w6", "@w0"),
    ("business hours today", "@d+9h", "@d+17h"),
    ("after hours today", "@d+17h", "now"),
    ("previous hour", "-1h", "now"),
    ("past hour", "-1h", "now"),
    ("last hour", "-1h", "now"),
    ("previous day", "-1d", "now"),
    ("past day", "-1d", "now"),
    ("last day", "-1d", "now"),
    ("previous week", "-7d@w0", "@w0"),
    ("previous calendar week", "-7d@w0", "@w0"),
    ("prior week", "-7d@w0", "@w0"),
    ("past week", "-7d", "now"),
    ("last week", "-7d", "now"),
    ("previous month", "-1mon@mon", "@mon"),
    ("prior month", "-1mon@mon", "@mon"),
    ("past month", "-1mon", "now"),
    ("last month", "-1mon", "now"),
    ("previous quarter", "-1q@q", "@q"),
    ("prior quarter", "-1q@q", "@q"),
    ("past quarter", "-1q", "now"),
    ("last quarter", "-1q", "now"),
    ("previous year", "-1y@y", "@y"),
    ("prior year", "-1y@y", "@y"),
    ("past year", "-1y", "now"),
    ("last year", "-1y", "now"),
    ("this week", "@w0", "now"),
    ("this month", "@mon", "now"),
    ("this quarter", "@q", "now"),
    ("this year", "@y", "now"),
    ("yesterday", "-1d@d", "@d"),
    ("today", "@d", "now"),
    ("ytd", "@y", "now"),
    ("mtd", "@mon", "now"),
    ("qtd", "@q", "now"),
)

_ALL_TIME_PHRASES: tuple[str, ...] = (
    "all time",
    "all-time",
    "all available time",
    "all available history",
    "all indexed time",
    "all indexed data",
    "all retained data",
    "all retention",
    "full botsv3 dataset",
    "entire botsv3 dataset",
    "at any point ever",
    "at any point",
    "any point ever",
    "at any time ever",
    "at any time",
    "any time ever",
    "entire history",
    "whole history",
    "all history",
    "full history",
    "complete history",
    "maximum history",
    "max history",
    "full retention",
    "maximum lookback",
    "max lookback",
    "as far back as",
    "since the beginning",
    "since beginning",
    "from the beginning",
    "from beginning",
    "over all time",
    "across all time",
    "throughout history",
    "historically",
    "ever recorded",
    "ever logged",
    "ever observed",
    "ever seen",
)


def _splunk_relative(count: int, unit_word: str) -> str:
    unit = _SPLUNK_TIME_UNIT.get(unit_word.lower(), "d")
    return f"-{max(1, int(count))}{unit}"


def _match_relative_count_window(q: str) -> tuple[str, str] | None:
    for pattern in (_RELATIVE_COUNT_RE, _AGO_COUNT_RE):
        match = pattern.search(q)
        if not match:
            continue
        count = int(match.group(1))
        unit_word = match.group(2)
        return _splunk_relative(count, unit_word), "now"
    since_ago = _SINCE_AGO_RE.search(q)
    if since_ago:
        count = int(since_ago.group(1))
        unit_word = since_ago.group(2)
        return _splunk_relative(count, unit_word), "now"
    return None


def _match_named_window(q: str) -> tuple[str, str] | None:
    for phrase, earliest, latest in _NAMED_BOUNDED_WINDOWS:
        if phrase in q:
            return earliest, latest
    return None


def _match_since_anchor(q: str) -> tuple[str, str] | None:
    if "since yesterday" in q:
        return "-1d@d", "now"
    if "since today" in q or "since this morning" in q:
        return "@d", "now"
    if "since start of week" in q or "since beginning of week" in q:
        return "@w0", "now"
    if "since start of month" in q or "since beginning of month" in q:
        return "@mon", "now"
    if "since start of quarter" in q or "since beginning of quarter" in q:
        return "@q", "now"
    if "since start of year" in q or "since beginning of year" in q:
        return "@y", "now"
    weekday = _SINCE_WEEKDAY_RE.search(q)
    if weekday:
        snap = _WEEKDAY_TO_SPLUNK.get(weekday.group(2), "@w0")
        return snap, "now"
    iso = _ISO_DATE_RE.search(q)
    if iso and "since" in q:
        return iso.group(0), "now"
    us_date = _US_DATE_RE.search(q)
    if us_date and "since" in q:
        month, day, year = us_date.groups()
        return f"{month}/{day}/{year}", "now"
    return None


def _match_until_anchor(q: str) -> tuple[str, str] | None:
    if any(phrase in q for phrase in ("until yesterday", "through yesterday", "up to yesterday", "before today")):
        return "-30d", "@d"
    if any(phrase in q for phrase in ("until today", "through today", "up to now", "through now", "until now")):
        return "-30d", "now"
    if "end of yesterday" in q:
        return "-2d@d", "@d"
    return None


def _match_range_window(q: str) -> tuple[str, str] | None:
    if re.search(r"\bfrom\s+yesterday\b.*\b(to|through|until)\b.*\btoday\b", q):
        return "-1d@d", "now"
    if re.search(r"\bfrom\s+today\b.*\b(to|through|until)\b.*\bnow\b", q):
        return "@d", "now"
    if re.search(r"\bbetween\s+yesterday\s+and\s+today\b", q):
        return "-1d@d", "now"
    if re.search(r"\bbetween\s+today\s+and\s+now\b", q):
        return "@d", "now"
    from_last = re.search(
        r"\bfrom\s+(?:the\s+)?(?:last|past|previous)\s+(\d+)\s+"
        r"(day|days|week|weeks|hour|hours|month|months|year|years)\b",
        q,
    )
    if from_last:
        count = int(from_last.group(1))
        unit_word = from_last.group(2)
        return _splunk_relative(count, unit_word), "now"
    return None


def _match_splunk_literal_window(
    q: str,
    *,
    default_earliest: str = DEFAULT_UNBOUNDED_EARLIEST,
    default_latest: str = DEFAULT_UNBOUNDED_LATEST,
) -> tuple[str, str] | None:
    earliest = ""
    latest = ""
    for match in _SPLUNK_LITERAL_RE.finditer(q):
        key = match.group(0).split("=")[0].split(":")[0].strip().lower()
        value = match.group(1).strip()
        if key.startswith("earliest"):
            earliest = value
        elif key.startswith("latest"):
            latest = value
    if earliest or latest:
        return earliest or default_earliest, latest or default_latest
    return None


def _parse_bounded_time_window(
    question: str,
    *,
    default_earliest: str = DEFAULT_UNBOUNDED_EARLIEST,
    default_latest: str = DEFAULT_UNBOUNDED_LATEST,
) -> tuple[str, str] | None:
    q = _normalize_time_question(question)
    if not q:
        return None
    matchers = (
        lambda value: _match_splunk_literal_window(
            value,
            default_earliest=default_earliest,
            default_latest=default_latest,
        ),
        _match_range_window,
        _match_relative_count_window,
        _match_since_anchor,
        _match_until_anchor,
        _match_named_window,
    )
    for matcher in matchers:
        parsed = matcher(q)
        if parsed:
            earliest, latest = parsed
            return (
                str(earliest).strip() or default_earliest,
                str(latest).strip() or default_latest,
            )
    return None


def question_has_explicit_relative_window(question: str) -> bool:
    return _parse_bounded_time_window(question) is not None


def question_requests_all_time(question: str) -> bool:
    q = _normalize_time_question(question)
    if not q:
        return False
    if question_has_explicit_relative_window(question):
        return False
    if any(phrase in q for phrase in _ALL_TIME_PHRASES):
        return True
    if re.search(r"\bever\s+(in|on|for|across|recorded|logged|observed|seen)\b", q):
        return True
    if re.search(r"\b(were there any|have there been any|has there ever been|has there been any)\b", q):
        return True
    if re.search(r"\bdid\b.+\bever\b", q):
        return True
    if re.search(r"\bany(?:one|body)?\s+ever\b", q):
        return True
    return False


def infer_time_window(
    question: str,
    *,
    default_earliest: str = DEFAULT_UNBOUNDED_EARLIEST,
    default_latest: str = DEFAULT_UNBOUNDED_LATEST,
) -> tuple[str, str]:
    if not (question or "").strip():
        return default_earliest, default_latest
    bounded = _parse_bounded_time_window(question)
    if bounded:
        return bounded
    if question_requests_all_time(question):
        return "0", "now"
    return default_earliest, default_latest


def apply_question_time_window(
    question: str,
    tool_args: dict[str, Any],
    *,
    default_earliest: str = DEFAULT_UNBOUNDED_EARLIEST,
    default_latest: str = DEFAULT_UNBOUNDED_LATEST,
) -> None:
    """Apply the question-owned time contract to query tool arguments."""
    inferred_e, inferred_l = infer_time_window(
        question,
        default_earliest=default_earliest,
        default_latest=default_latest,
    )
    tool_args["earliest_time"] = inferred_e
    tool_args["latest_time"] = inferred_l


def spl_time_values_equivalent(left: str, right: str) -> bool:
    """Compare exact or equivalent rolling Splunk relative-time values."""
    left_value = str(left or "").strip().lower()
    right_value = str(right or "").strip().lower()
    if left_value == right_value:
        return True

    def rolling_seconds(value: str) -> int | None:
        normalized = value[3:] if value.startswith("now-") else value
        match = re.fullmatch(r"-(\d+)(s|m|h|d|w)", normalized)
        if not match:
            return None
        multipliers = {
            "s": 1,
            "m": 60,
            "h": 60 * 60,
            "d": 24 * 60 * 60,
            "w": 7 * 24 * 60 * 60,
        }
        return int(match.group(1)) * multipliers[match.group(2)]

    left_seconds = rolling_seconds(left_value)
    right_seconds = rolling_seconds(right_value)
    return left_seconds is not None and left_seconds == right_seconds


def describe_supported_time_windows() -> str:
    """Short planner hint listing major supported natural-language time forms."""
    return (
        "Supported time phrases include: last/past/previous N seconds|minutes|hours|days|weeks|months|quarters|years; "
        "N units ago; since N units ago; since yesterday/today/start of week|month|quarter|year; since YYYY-MM-DD; "
        "today/yesterday/this week|month|quarter|year; last 24/48/72 hours; last 30/60/90 days; YTD/MTD/QTD; "
        "previous calendar week/month/quarter/year; until/through/before anchors; earliest_time=/latest_time= literals; "
        "and all-time phrases (all time, at any point ever, were there any, ever in/on); "
        f"unspecified questions default to {DEFAULT_UNBOUNDED_EARLIEST} through {DEFAULT_UNBOUNDED_LATEST}."
    )


EXPLICIT_SOURCETYPE_MARKERS: tuple[str, ...] = (
    "access_combined",
    "auth.log",
    "aws:cloudtrail",
    "aws:cloudwatchlogs:vpcflow",
    "cisco:asa",
    "linux_audit",
    "ms:aad:signin",
    "ms:o365:management",
    "osquery:results",
    "stream:http",
    "stream:dns",
    "audittrail",
    "xmlwineventlog",
)

APACHE_WEB_INTENTS: frozenset[str] = APACHE_INTENTS


def extract_explicit_indexes(question: str) -> list[str]:
    """Return index names explicitly supplied by the analyst, preserving order."""
    q = str(question or "")
    positioned: list[tuple[int, str]] = []
    patterns = (
        r'\bindex\s*=\s*(?:"([^"]+)"|\'([^\']+)\'|([A-Za-z0-9_.:-]+))',
        r"\bindex\s+([A-Za-z0-9_.:-]+)\s+sourcetype\b",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, q, flags=re.IGNORECASE):
            value = next((part for part in match.groups() if part), "").strip()
            if value:
                positioned.append((match.start(), value))
    # Cross-event questions may use the compact ``index/sourcetype`` form.
    # Keep the same conservative shape check used by sourcetype extraction so
    # ordinary prose containing fractions or path-like text is not locked.
    for match in re.finditer(
        r"(?<![A-Za-z0-9_.:-])([A-Za-z0-9_.:-]+)/"
        r"[A-Za-z0-9_.:-]*(?::|_)[A-Za-z0-9_.:-]*"
        r"(?![A-Za-z0-9_.:-])",
        q,
    ):
        positioned.append((match.start(1), match.group(1)))
    found: list[str] = []
    seen: set[str] = set()
    for _, value in sorted(positioned, key=lambda item: item[0]):
        if value.casefold() not in seen:
            found.append(value)
            seen.add(value.casefold())
    if re.search(r"\bbotsv3\b", q, flags=re.IGNORECASE) and "botsv3" not in {
        item.lower() for item in found
    }:
        found.append("botsv3")
    return found


def extract_explicit_sourcetypes(question: str) -> list[str]:
    """Return all explicitly named sourcetypes in analyst order."""
    q = str(question or "")
    if not q.strip():
        return []
    positioned: list[tuple[int, str]] = []
    ignored_bare_values = {
        "field",
        "fields",
        "inventory",
        "metadata",
        "value",
        "values",
        "volume",
        "volumes",
        "count",
        "counts",
    }
    for match in re.finditer(
        r"\bsourcetype\b\s*(?:=\s*)?"
        r"(?:\"([^\"]+)\"|'([^']+)'|([A-Za-z0-9_*.:/-]+))",
        q,
        flags=re.IGNORECASE,
    ):
        value = next((part for part in match.groups() if part), "").strip()
        if value and value.casefold() not in ignored_bare_values:
            positioned.append((match.start(), value))
    for marker in EXPLICIT_SOURCETYPE_MARKERS:
        match = re.search(
            rf"(?<![a-z0-9_:-]){re.escape(marker)}(?![a-z0-9_:-])",
            q,
            flags=re.IGNORECASE,
        )
        if match:
            positioned.append((match.start(), marker))
    # Generated and analyst-authored cross-event questions commonly use the
    # compact ``index/sourcetype`` notation. Require a colon or underscore in
    # the right-hand token so dates, fractions, and ordinary slash text do not
    # become hard dataset locks.
    for match in re.finditer(
        r"(?<![A-Za-z0-9_.:-])[A-Za-z0-9_.:-]+/"
        r"([A-Za-z0-9_.:-]*(?::|_)[A-Za-z0-9_.:-]*)"
        r"(?![A-Za-z0-9_.:-])",
        q,
    ):
        value = match.group(1).strip()
        if value:
            positioned.append((match.start(1), value))
    found: list[str] = []
    seen: set[str] = set()
    for _, value in sorted(positioned, key=lambda item: item[0]):
        key = value.casefold()
        if key not in seen:
            found.append(value)
            seen.add(key)
    return found


def extract_explicit_sourcetype(question: str) -> str:
    """Return the first explicit sourcetype for legacy single-scope callers."""
    values = extract_explicit_sourcetypes(question)
    return values[0] if values else ""


def extract_explicit_dataset_locks(question: str) -> dict[str, list[str]]:
    """Build hard dataset locks from exact index/sourcetype names in a question."""
    return {
        "indexes": extract_explicit_indexes(question),
        "sourcetypes": extract_explicit_sourcetypes(question),
    }


def validate_query_dataset_locks(question: str, query: str) -> tuple[bool, str]:
    """Require final SPL to use exactly the analyst's explicit dataset scope."""
    locks = extract_explicit_dataset_locks(question)
    query_text = str(query or "")
    query_indexes = {
        next((part for part in match if part), "").strip().lower()
        for match in re.findall(
            r'\bindex\s*=\s*(?:"([^"]+)"|\'([^\']+)\'|([A-Za-z0-9_*.:-]+))',
            query_text,
            flags=re.IGNORECASE,
        )
        if any(match)
    }
    query_sourcetypes = {
        next((part for part in match if part), "").strip().lower()
        for match in re.findall(
            r'\bsourcetype\s*=\s*(?:"([^"]+)"|\'([^\']+)\'|([A-Za-z0-9_*.:/-]+))',
            query_text,
            flags=re.IGNORECASE,
        )
        if any(match)
    }
    locked_indexes = {item.lower() for item in locks["indexes"]}
    locked_sourcetypes = {item.lower() for item in locks["sourcetypes"]}
    if locked_indexes and query_indexes != locked_indexes:
        return False, "explicit_index_lock_violation"
    if locked_sourcetypes and query_sourcetypes != locked_sourcetypes:
        return False, "explicit_sourcetype_lock_violation"
    return True, "dataset_locks_ok"


_COMPOSITION_ROLE_ALIASES: tuple[tuple[str, str], ...] = (
    ("client ip", "src_ip"),
    ("clientip", "src_ip"),
    ("source ip", "src_ip"),
    ("src ip", "src_ip"),
    ("src_ip", "src_ip"),
    ("source", "src_ip"),
    ("src", "src_ip"),
    ("ip address", "src_ip"),
    ("ipaddress", "src_ip"),
    ("destination ip", "dest_ip"),
    ("dest ip", "dest_ip"),
    ("dest_ip", "dest_ip"),
    ("destinationip", "dest_ip"),
    ("observed dest ip", "dest_ip"),
    ("observed_dest_ip", "dest_ip"),
    ("user", "user"),
    ("username", "user"),
    ("target user name", "user"),
    ("target username", "user"),
    ("targetusername", "user"),
    ("target account", "user"),
    ("user principal name", "user"),
    ("userprincipalname", "user"),
    ("account", "user"),
    ("principal", "user"),
    ("host", "host"),
    ("system", "host"),
    ("computer", "host"),
    ("operation", "operation"),
    ("event name", "operation"),
    ("eventname", "operation"),
    ("activity", "operation"),
    ("method", "operation"),
    ("verb", "operation"),
    ("resource", "resource"),
    ("uri", "resource"),
    ("url", "resource"),
    ("target", "resource"),
    ("query", "query"),
    ("domain", "query"),
    ("requested domain", "query"),
    ("answer", "answer"),
    ("response value", "answer"),
    ("response", "answer"),
    ("resolver", "resolver"),
    ("dns server", "resolver"),
    ("port", "port"),
    ("state", "state"),
    ("status", "state"),
    ("result", "state"),
    ("outcome", "state"),
    ("action", "state"),
)


def _composition_role_hint(value: Any) -> str:
    """Map analyst-facing field language to a stable plan role."""
    text = re.sub(r"\s+", " ", str(value or "").strip().casefold())
    text = re.sub(r"^(?:the|shared|observed|distinct)\s+", "", text)
    text = re.sub(r"\s+(?:values?|fields?|sets?)$", "", text)
    for phrase, role in sorted(_COMPOSITION_ROLE_ALIASES, key=lambda item: -len(item[0])):
        if text == phrase or re.search(rf"\b{re.escape(phrase)}\b", text):
            return role
    compact = re.sub(r"[^a-z0-9_.:-]+", "_", text).strip("_")
    return compact if re.fullmatch(r"[a-z_][a-z0-9_.:-]*", compact) else ""


def _composition_field_hints(question: str) -> list[str]:
    """Extract field roles used by value-set/intersection requests."""
    q = str(question or "").casefold()
    found: list[str] = []
    patterns = (
        r"\b(?:collect|retain|preserve)\b[^,.!?;]*?"
        r"\b(?:observed\s+)?(.+?)\s+(?:values?|sets?)\b",
        r"\b(?:both|overlap|intersection)\s+"
        r"([a-z][a-z0-9_.:/ -]*?)\s+and\s+([a-z][a-z0-9_.:/ -]*?)"
        r"(?:\s+(?:fields?|values?))?\s+(?:are\s+)?present\b",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, q, flags=re.IGNORECASE):
            parts = list(match.groups())
            if len(parts) == 1:
                parts = re.split(r"\s+(?:and|&)\s+", parts[0])
            for part in parts:
                role = _composition_role_hint(part)
                if role and role not in found:
                    found.append(role)
    return found


def _composition_dimensions(question: str, existing: list[str]) -> list[str]:
    """Extract grouping roles without treating output-function words as fields."""
    q = str(question or "").casefold()
    result = list(existing)
    grouping = (
        r"\b(?:group(?:ed)?\s+by|break(?:ed)?\s+down\s+by|by|per|for\s+each|"
        r"through|via|map)\s+(?:the\s+)?([^,.!?;]+?)"
        r"(?=\s+(?:through|via)\b|[,.!?;]|$)"
    )
    stop_words = (
        r"(?:values?|records?|events?|results?|outcomes?|activity|activities|"
        r"calculate|collect|count|report|show|where|and|over|during|with|"
        r"that|whose|which|to|from|in|on|using|requiring|retaining|through|via|then|"
        r"rank|order|return|last|past|for|the|percentage|percent|share|ratio|rate|"
        r"distinct|unique|top|at\s+least|more|less|exceeds?|above|below)"
    )
    for match in re.finditer(grouping, q, flags=re.IGNORECASE):
        prefix = q[: match.start()]
        if re.search(r"\b(?:rank|ranking|order|sort)\b[^,.!?;]*$", prefix):
            continue
        fragment = re.split(rf"\s+\b{stop_words}\b", match.group(1), maxsplit=1)[0]
        if fragment.strip().casefold() == "shared":
            continue
        if "/" in fragment:
            role_alias_present = any(
                re.search(rf"\b{re.escape(phrase)}\b", fragment)
                for phrase, _ in _COMPOSITION_ROLE_ALIASES
            )
            if not role_alias_present:
                continue
        # Compact cross-source notation such as ``src / src_ip`` is one role.
        for part in re.split(r"\s+(?:and|&)\s+|/", fragment):
            role = _composition_role_hint(part)
            if role and role not in result:
                result.append(role)
    return result


def _comparison_state_field(question: str) -> str:
    q = str(question or "").casefold()
    for phrase, role in (
        ("result_state", "state"),
        ("status_code", "state"),
        ("status", "state"),
        ("result", "state"),
        ("outcome", "state"),
        ("state", "state"),
        ("action", "state"),
    ):
        if re.search(rf"\b{re.escape(phrase)}\b", q):
            return role
    return ""


def infer_analytical_shape_hints(question: str) -> dict[str, Any]:
    """Derive reusable, non-authoritative plan-shape hints without inventing literals."""
    q = str(question or "").strip()
    q_lower = q.lower()
    dimensions = infer_question_dimensions(q)
    locks = extract_explicit_dataset_locks(q)

    requested_dimensions: list[str] = []
    role_names = {
        "host": "host",
        "hosts": "host",
        "user": "user",
        "users": "user",
        "username": "user",
        "source ip": "src_ip",
        "src ip": "src_ip",
        "src_ip": "src_ip",
        "client ip": "src_ip",
        "client_ip": "src_ip",
        "destination ip": "dest_ip",
        "dest ip": "dest_ip",
        "dest_ip": "dest_ip",
        "status": "status",
        "method": "method",
        "uri": "uri",
        "user agent": "user_agent",
    }
    for phrase, role in role_names.items():
        if re.search(rf"\b(?:by|per|for each)\s+(?:the\s+)?{re.escape(phrase)}s?\b", q_lower):
            if role not in requested_dimensions:
                requested_dimensions.append(role)
    for role in dimensions.get("entities", []):
        if role not in requested_dimensions and re.search(
            rf"\b(?:by|per|for each)\b[^,.?!;]*\b{re.escape(role.replace('_', ' '))}s?\b",
            q_lower,
        ):
            requested_dimensions.append(role)
    requested_dimensions = _composition_dimensions(q, requested_dimensions)

    measures: list[dict[str, str]] = []
    if any(
        phrase in q_lower
        for phrase in (
            "how many",
            "count",
            "number of",
            "total events",
            "total requests",
            "event volume",
            "volume of",
            "percentage of events",
            "share of events",
            "proportion of events",
        )
    ):
        measures.append({"function": "count", "name_hint": "events"})
    distinct = re.search(
        r"\b(?:distinct|unique)\s+(hosts?|users?|source ips?|src ips?|client ips?|uris?|values?)\b",
        q_lower,
    )
    if distinct:
        field_hint = role_names.get(distinct.group(1).rstrip("s"), distinct.group(1).replace(" ", "_").rstrip("s"))
        measures.append({"function": "dc", "field_hint": field_hint, "name_hint": f"distinct_{field_hint}"})
    for phrase, function in (
        ("average", "avg"),
        ("mean", "avg"),
        ("sum", "sum"),
        ("minimum", "min"),
        ("maximum", "max"),
        ("earliest", "earliest"),
        ("latest", "latest"),
        ("first seen", "earliest"),
        ("last seen", "latest"),
    ):
        if re.search(rf"\b{re.escape(phrase)}\b", q_lower) and not any(
            item.get("function") == function for item in measures
        ):
            measures.append({"function": function, "field_hint": "", "name_hint": phrase.replace(" ", "_")})

    value_fields = _composition_field_hints(q)
    if value_fields:
        for field_name in value_fields:
            measures.append(
                {
                    "function": "values",
                    "field_hint": field_name,
                    "name_hint": f"{field_name}_values",
                }
            )

    state_field = _comparison_state_field(q)
    has_positive = bool(re.search(r"\b(success(?:ful)?|succeeded|allowed|ok|good)\b", q))
    has_negative = bool(
        re.search(r"\b(unsuccess(?:ful)?|failed?|failure|denied|error|bad|non-good)\b", q)
    )
    if state_field and has_positive and has_negative:
        positive_literal = "allowed" if "allowed" in q else "ok" if re.search(r"\bok\b", q) else "success"
        if has_positive:
            measures.append(
                {
                    "function": "count",
                    "name_hint": "successful_events",
                    "condition": {"field": state_field, "operator": "eq", "value": positive_literal},
                }
            )
        if has_negative:
            measures.append(
                {
                    "function": "count",
                    "name_hint": "unsuccessful_events",
                    "condition": {"field": state_field, "operator": "neq", "value": positive_literal},
                }
            )

    explicit_filters: list[dict[str, Any]] = []
    for match in re.finditer(
        r"\b([A-Za-z_][A-Za-z0-9_.:-]*)\s*(=|!=|>=|<=|>|<)\s*"
        r'(?:"([^"]+)"|\'([^\']+)\'|([A-Za-z0-9_.:/-]+))',
        q,
    ):
        field_name, symbol = match.group(1), match.group(2)
        if field_name.lower() in {"index", "sourcetype", "earliest", "latest", "earliest_time", "latest_time"}:
            continue
        value = next((part for part in match.groups()[2:] if part is not None), "")
        if re.fullmatch(r"-?\d+", value):
            value = int(value)
        elif re.fullmatch(r"-?\d+\.\d+", value):
            value = float(value)
        operator = {"=": "eq", "!=": "neq", ">": "gt", ">=": "gte", "<": "lt", "<=": "lte"}[symbol]
        explicit_filters.append({"field": field_name, "operator": operator, "value": value})

    thresholds: list[dict[str, Any]] = []
    threshold = re.search(
        r"\b(at least|more than|greater than|over|fewer than|less than|at most|"
        r"exceeds?|exceeding|above|below)\s+(\d+(?:\.\d+)?)\b",
        q_lower,
    )
    if threshold:
        thresholds.append(
            {
                "operator": {
                    "at least": "gte",
                    "more than": "gt",
                    "greater than": "gt",
                    "over": "gt",
                    "fewer than": "lt",
                    "less than": "lt",
                    "at most": "lte",
                    "exceed": "gt",
                    "exceeds": "gt",
                    "exceeding": "gt",
                    "above": "gt",
                    "below": "lt",
                }[threshold.group(1)],
                "value": float(threshold.group(2)) if "." in threshold.group(2) else int(threshold.group(2)),
            }
        )

    time_bin = ""
    time_match = re.search(
        r"\b(?:every|per)\s+(\d+\s*)?(second|minute|hour|day|week)s?\b",
        q_lower,
    )
    if time_match:
        number = (time_match.group(1) or "1").strip()
        unit = {"second": "s", "minute": "m", "hour": "h", "day": "d", "week": "w"}[time_match.group(2)]
        time_bin = f"{number}{unit}"
    else:
        bucket_match = re.search(
            r"\b(\d+)[ -]?(second|minute|hour|day|week)s?\s+(?:bucket|buckets|bin|bins)\b",
            q_lower,
        )
        if bucket_match:
            unit = {
                "second": "s",
                "minute": "m",
                "hour": "h",
                "day": "d",
                "week": "w",
            }[bucket_match.group(2)]
            time_bin = f"{bucket_match.group(1)}{unit}"
    if not time_bin and any(phrase in q_lower for phrase in ("over time", "timeline", "time series", "trend")):
        time_bin = "1h"

    ranking: dict[str, Any] = {}
    top_match = re.search(r"\btop\s+(\d+)\b", q_lower)
    if top_match:
        ranking = {"direction": "desc", "limit": min(int(top_match.group(1)), 200)}
    elif re.search(r"\b(?:rank|ranking)\b.*\b(?:highest|largest|most|descending)\b", q_lower):
        ranking = {"direction": "desc"}
    elif re.search(r"\b(?:rank|ranking)\b.*\b(?:lowest|smallest|least|ascending)\b", q_lower):
        ranking = {"direction": "asc"}

    comparisons: list[dict[str, Any]] = []
    if re.search(r"\b(?:compare|comparison|versus|vs\.?|against)\b", q_lower):
        comparisons.append({"kind": "requested"})

    ratio_requested = bool(
        re.search(r"\b(?:percentage|percent|share|proportion|ratio|rate)\b", q_lower)
    )
    ratios: list[dict[str, Any]] = []
    if ratio_requested:
        ratio_name = "ratio"
        if re.search(r"\b(?:unsuccessful|failed|failure|denied|error)\b", q_lower):
            ratio_name = "unsuccessful_pct"
        elif re.search(r"\b(?:successful|success|succeeded|allowed|ok)\b", q_lower):
            ratio_name = "selected_pct"
        ratios.append({"name_hint": ratio_name, "scale": 100})

    intersections: list[dict[str, Any]] = []
    if value_fields and (
        re.search(r"\b(?:both|overlap|intersection|co-occurrence|co occurrence)\b", q_lower)
        or re.search(r"\b(?:collect|retain|preserve)\b[^,.!?;]*\b(?:both|overlap)\b", q_lower)
    ):
        intersections.append(
            {
                "name_hint": "intersection_events",
                "fields": value_fields[:2],
            }
        )

    required_outputs = list(requested_dimensions)
    required_outputs.extend(
        str(item.get("name_hint", "")).strip()
        for item in measures
        if str(item.get("name_hint", "")).strip()
    )
    required_outputs.extend(
        str(item.get("name_hint", "")).strip()
        for item in intersections + ratios
        if str(item.get("name_hint", "")).strip()
    )
    if time_bin:
        required_outputs.append("bucket")

    return {
        "requested_datasets": locks,
        "filters": explicit_filters,
        "dimensions": requested_dimensions,
        "measures": measures,
        "comparisons": comparisons,
        "thresholds": thresholds,
        "cardinality": "cardinality" in dimensions.get("shapes", []),
        "time_bin": time_bin,
        "ranking": ranking,
        "ratios": ratios,
        "intersections": intersections,
        "output_fields": list(dict.fromkeys(required_outputs)),
    }


def query_conflicts_with_explicit_sourcetype(question: str, query: str) -> bool:
    """True when generated SPL ignores a sourcetype the analyst explicitly scoped."""
    explicit_values = extract_explicit_sourcetypes(question)
    if not explicit_values:
        return False
    query_l = (query or "").strip().lower()
    expected = {item.casefold() for item in explicit_values}
    actual = {
        next((part for part in match if part), "").strip().casefold()
        for match in re.findall(
            r'\bsourcetype\s*=\s*(?:"([^"]+)"|\'([^\']+)\'|([A-Za-z0-9_*.:/-]+))',
            query_l,
            flags=re.IGNORECASE,
        )
        if any(match)
    }
    if actual == expected:
        return False
    if len(expected) > 1:
        return True
    explicit_l = next(iter(expected))
    if explicit_l == "access_combined":
        return any(
            tok in query_l
            for tok in (
                "osquery",
                "hostidentifier",
                "columns.path",
                "columns.cmdline",
                "sourcetype=stream:http",
            )
        )
    if explicit_l == "auth.log":
        return "osquery" in query_l or "access_combined" in query_l
    if explicit_l == "aws:cloudtrail":
        return "osquery" in query_l or "access_combined" in query_l
    if explicit_l.startswith("osquery"):
        return "access_combined" in query_l
    return False


def domain_oracle_threshold_for_question(
    question: str,
    *,
    domain_intent: str = "",
    mapped_intent: str = "",
) -> float:
    """Lower oracle short-circuit threshold when the question names an explicit sourcetype."""
    explicit = extract_explicit_sourcetype(question)
    if not explicit:
        return 0.85
    domain_intent = str(domain_intent or "").strip()
    mapped_intent = str(mapped_intent or "").strip()
    if explicit == "access_combined" and domain_intent in APACHE_WEB_INTENTS:
        return 0.75
    if domain_intent and mapped_intent and domain_intent == mapped_intent:
        return 0.75
    return 0.85
