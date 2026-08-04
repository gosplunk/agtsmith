#!/usr/bin/env python3
"""Deterministic Apache access-log intent classification and canonical SPL."""

from __future__ import annotations

import re


APACHE_INTENTS = frozenset(
    {
        "apache_access_top_ips",
        "apache_suspicious_activity",
        "apache_404_spike",
        "apache_404_scanning",
        "apache_suspicious_user_agents",
        "apache_sensitive_path_probing",
    }
)

APACHE_DIMENSION_FIELDS: dict[str, tuple[str, ...]] = {
    "src_ip": ("clientip", "src_ip", "src"),
    "status": ("status", "status_code", "sc_status"),
    "method": ("method", "http_method"),
    "uri": ("uri_path", "uri", "url", "path"),
    "user_agent": ("useragent", "user_agent", "http_user_agent"),
}

_APACHE_CONTEXT = (
    "apache",
    "access_combined",
    "access log",
    "web access",
    "web server",
)
_NON_APACHE_CONTEXT = ("stream:http", "stream http", "osquery", "cloudtrail")
_SUSPICIOUS_WORDS = (
    "suspicious",
    "malicious",
    "anomal",
    "weird",
    "odd",
    "strange",
    "threat",
    "attack",
    "recon",
)
_BENIGN_ONLY_PHRASES = (
    "not suspicious",
    "without suspicious",
    "all traffic",
    "just traffic",
    "simple traffic",
    "traffic summary",
    "request volume",
    "do not filter",
    "without filtering",
)
_SENSITIVE_PATH_WORDS = (
    "sensitive path",
    "sensitive uri",
    "sensitive endpoint",
    "admin path",
    "admin endpoint",
    "secret file",
    "configuration file",
    ".env",
    ".git",
    "wp-admin",
    "wp-login",
    "phpmyadmin",
    "server-status",
    "path probing",
    "endpoint probing",
)

APACHE_FALLBACK_REX = (
    'rex field=_raw "^(?<clientip>\\S+) \\S+ \\S+ \\[[^\\]]+\\] '
    '\\"(?<method>[A-Z]+) (?<uri_path>\\S+) [^\\"]+\\" (?<status>\\d{3}) '
    '\\S+ \\"[^\\"]*\\" \\"(?<useragent>[^\\"]*)\\""'
)
APACHE_ALIAS_EVAL = (
    "eval clientip=coalesce(clientip,src_ip,src,ip), "
    "status=coalesce(status,status_code,sc_status,http_status,response_code), "
    "method=coalesce(method,http_method,verb), "
    "uri_path=coalesce(uri_path,uri,url,url_path,path), "
    "useragent=coalesce(useragent,user_agent,http_user_agent)"
)
_ALIAS_EVAL_BY_FIELD: dict[str, str] = {
    "clientip": "clientip=coalesce(clientip,src_ip,src,ip)",
    "status": "status=coalesce(status,status_code,sc_status,http_status,response_code)",
    "method": "method=coalesce(method,http_method,verb)",
    "uri_path": "uri_path=coalesce(uri_path,uri,url,url_path,path)",
    "useragent": "useragent=coalesce(useragent,user_agent,http_user_agent)",
}
SENSITIVE_PATH_REGEX = (
    r"(?i)(?:^|/)(?:\.env(?:$|[/?])|\.git(?:$|/)|wp-admin(?:$|/)|"
    r"wp-login\.php|phpmyadmin(?:$|/)|admin(?:$|/)|login(?:\.php)?(?:$|[/?])|"
    r"config(?:\.php|\.json|\.yml|\.yaml)?(?:$|[/?])|backup(?:$|[/.?])|"
    r"server-status(?:$|[/?])|actuator(?:$|/)|vendor/phpunit(?:$|/))"
)
SUSPICIOUS_UA_REGEX = (
    r"(?i)(?:bot|crawl|spider|scanner|sqlmap|nikto|nmap|masscan|acunetix|"
    r"nessus|curl|wget|python-requests|go-http-client|libwww-perl|zgrab)"
)


def _normalized(question: str) -> str:
    return re.sub(r"\s+", " ", str(question or "").strip().lower())


def is_apache_question(question: str) -> bool:
    q = _normalized(question)
    if not q or any(marker in q for marker in _NON_APACHE_CONTEXT):
        return False
    return any(marker in q for marker in _APACHE_CONTEXT)


def requested_apache_roles(question: str, *, include_defaults: bool = False) -> list[str]:
    """Return semantic output roles explicitly requested by the analyst."""
    q = _normalized(question)
    roles: list[str] = []
    signals: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("src_ip", ("client ip", "client ips", "source ip", "source ips", "remote ip", "top ips", "top ip")),
        ("status", ("status", "status code", "response code", "http code", "4xx", "5xx")),
        ("method", ("method", "methods", "http verb", "http verbs")),
        ("uri", ("requested path", "requested paths", "request path", "request paths", "uri", "uris", "url", "urls", "path", "paths", "endpoint", "endpoints")),
        ("user_agent", ("user agent", "user agents", "user-agent", "useragent", "browser agent", "bot", "bots", "crawler", "crawlers", "scanner", "scanners")),
    )
    for role, phrases in signals:
        if any(phrase in q for phrase in phrases):
            roles.append(role)
    if include_defaults:
        for role in ("src_ip", "status", "method"):
            if role not in roles:
                roles.append(role)
    return roles


def classify_apache_intent(question: str) -> str:
    """Classify Apache questions before generic keyword scoring can tie."""
    if not is_apache_question(question):
        return ""
    q = _normalized(question)
    roles = requested_apache_roles(question)
    benign_only = any(phrase in q for phrase in _BENIGN_ONLY_PHRASES)
    suspicious = not benign_only and any(word in q for word in _SUSPICIOUS_WORDS)
    has_404 = bool(re.search(r"\b404(?:s)?\b", q))
    scanning = any(word in q for word in ("scan", "scanner", "scanning", "recon", "enumerat", "probe", "probing"))
    ua_hunt = any(word in q for word in ("bot", "crawler", "spider", "user agent", "user-agent"))
    sensitive_path = any(word in q for word in _SENSITIVE_PATH_WORDS)
    trend = any(word in q for word in ("spike", "trend", "timeline", "over time", "rate by time", "timechart"))

    if sensitive_path:
        return "apache_sensitive_path_probing"
    if has_404 and scanning:
        return "apache_404_scanning"
    if has_404 and trend:
        return "apache_404_spike"
    if ua_hunt and not benign_only and len(roles) <= 2:
        return "apache_suspicious_user_agents"
    if suspicious or scanning:
        return "apache_suspicious_activity"
    if has_404:
        return "apache_404_scanning"
    return "apache_access_top_ips"


def apache_intent_profile(question: str) -> dict[str, object]:
    intent = classify_apache_intent(question)
    return {
        "intent": intent,
        "roles": requested_apache_roles(question, include_defaults=intent == "apache_suspicious_activity"),
        "suspicious_required": intent
        in {
            "apache_suspicious_activity",
            "apache_404_scanning",
            "apache_suspicious_user_agents",
            "apache_sensitive_path_probing",
        },
    }


def _fallback_rex(required_fields: tuple[str, ...]) -> str:
    wanted = set(required_fields)
    client = r"(?<clientip>\S+)" if "clientip" in wanted else r"\S+"
    method = r"(?<method>[A-Z]+)" if "method" in wanted else r"[A-Z]+"
    uri_path = r"(?<uri_path>\S+)" if "uri_path" in wanted else r"\S+"
    status = r"(?<status>\d{3})" if "status" in wanted else r"\d{3}"
    useragent = r"(?<useragent>[^\"]*)" if "useragent" in wanted else r"[^\"]*"
    return (
        'rex field=_raw "^'
        + client
        + r' \S+ \S+ \[[^\]]+\] \"'
        + method
        + " "
        + uri_path
        + r' [^\"]+\" '
        + status
        + r' \S+ \"[^\"]*\" \"'
        + useragent
        + r'\""'
    )


def _base_query(required_fields: tuple[str, ...] = ("clientip", "status", "method", "uri_path", "useragent")) -> str:
    evals = ", ".join(
        _ALIAS_EVAL_BY_FIELD[field]
        for field in required_fields
        if field in _ALIAS_EVAL_BY_FIELD
    )
    return (
        "search index=linux sourcetype=access_combined "
        f"| {_fallback_rex(required_fields)} "
        f"| eval {evals}"
    )


def _group_fields(question: str, *, defaults: tuple[str, ...]) -> list[str]:
    role_to_field = {
        "src_ip": "clientip",
        "status": "status",
        "method": "method",
        "uri": "uri_path",
        "user_agent": "useragent",
    }
    requested = requested_apache_roles(question)
    fields = list(defaults)
    fields.extend(role_to_field[role] for role in requested if role in role_to_field)
    return list(dict.fromkeys(fields))


def build_apache_query(intent: str, question: str = "") -> str:
    """Build fields-first Apache SPL with raw extraction only as fallback."""
    intent = str(intent or "").strip()
    q = _normalized(question)
    if intent == "apache_404_spike":
        base = _base_query(("status",))
        return base + " | search status=404 | timechart span=1h count by host limit=10"

    if intent == "apache_404_scanning":
        base = _base_query(("clientip", "status", "method", "uri_path", "useragent"))
        return (
            base
            + " | search status=404 "
            "| stats count as request_count dc(uri_path) as distinct_paths "
            "values(uri_path) as requested_paths values(method) as methods "
            "values(useragent) as user_agents by clientip "
            "| where request_count>=3 OR distinct_paths>=3 "
            "| sort - request_count"
        )

    if intent == "apache_suspicious_user_agents":
        base = _base_query(("clientip", "status", "method", "uri_path", "useragent"))
        return (
            base
            + f' | where isnull(useragent) OR useragent="" OR useragent="-" '
            f'OR match(useragent,"{SUSPICIOUS_UA_REGEX}") '
            "| stats count as request_count values(status) as status_codes "
            "values(method) as methods values(uri_path) as requested_paths by useragent clientip "
            "| sort - request_count | head 20"
        )

    if intent == "apache_sensitive_path_probing":
        base = _base_query(("clientip", "status", "method", "uri_path", "useragent"))
        return (
            base
            + f' | where match(uri_path,"{SENSITIVE_PATH_REGEX}") '
            "| stats count as request_count values(status) as status_codes "
            "values(method) as methods values(useragent) as user_agents by clientip uri_path "
            "| sort - request_count"
        )

    if intent == "apache_suspicious_activity":
        base = _base_query(("clientip", "status", "method", "uri_path", "useragent"))
        fields = _group_fields(
            question,
            defaults=("clientip", "status", "method", "uri_path", "useragent"),
        )
        return (
            base
            + f' | eval suspicious_reason=case(match(uri_path,"{SENSITIVE_PATH_REGEX}"),"sensitive_path_probe",'
            f'isnull(useragent) OR useragent="" OR useragent="-" OR match(useragent,"{SUSPICIOUS_UA_REGEX}"),"suspicious_user_agent",'
            'match(upper(method),"^(TRACE|CONNECT|PROPFIND|DEBUG)$"),"unusual_method",'
            'status>=500,"server_error",status=404,"not_found_or_scan",status>=400,"http_error") '
            "| where isnotnull(suspicious_reason) "
            f"| stats count as request_count by {' '.join(fields)} suspicious_reason "
            "| sort - request_count | head 50"
        )

    if any(phrase in q for phrase in ("unique client", "distinct client", "how many client ip")):
        base = _base_query(("clientip",))
        return base + " | stats dc(clientip) as client_ip_count"
    if any(phrase in q for phrase in ("how many", "total requests", "request count", "number of requests", "total hits")):
        return (
            "search index=linux sourcetype=access_combined"
            " | stats count as request_count"
        )

    fields = _group_fields(question, defaults=("clientip", "status", "method"))
    base = _base_query(tuple(fields))
    return base + f" | stats count by {' '.join(fields)} | sort - count"


def query_has_requested_apache_dimensions(question: str, query: str) -> tuple[bool, str]:
    """Validate requested roles in the final result-producing command."""
    if not is_apache_question(question):
        return True, "apache_dimensions_not_applicable"
    required = requested_apache_roles(question)
    if not required:
        return True, "apache_dimensions_not_explicit"
    query_l = str(query or "").lower()
    result_shape = query_l.rsplit("| stats", 1)[-1] if "| stats" in query_l else query_l.rsplit("| table", 1)[-1]
    for role in required:
        if not any(re.search(rf"(?<![a-z0-9_.]){re.escape(field)}(?![a-z0-9_.])", result_shape) for field in APACHE_DIMENSION_FIELDS[role]):
            return False, f"intent_contract_missing_requested_apache_dimension:{role}"
    return True, "apache_dimensions_ok"
