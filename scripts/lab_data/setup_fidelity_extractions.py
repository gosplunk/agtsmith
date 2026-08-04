#!/usr/bin/env python3
"""Install search-time field extractions used by production-shaped lab fixtures."""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from lab_data.config import load_ui_env


PROPS_STANZAS: dict[str, dict[str, str]] = {
    "XmlWinEventLog": {
        "KV_MODE": "xml",
        "REPORT-agtsmith_xml_fields": (
            "agtsmith_xml_event_id, agtsmith_xml_channel, "
            "agtsmith_xml_computer, agtsmith_xml_provider, agtsmith_xml_eventdata"
        ),
        "FIELDALIAS-agtsmith_event_code": "EventID AS EventCode",
    },
    "aws:cloudtrail": {
        "KV_MODE": "json",
        "AUTO_KV_JSON": "true",
    },
    "o365:management:activity": {
        "KV_MODE": "json",
        "AUTO_KV_JSON": "true",
    },
    "stream:dns": {
        "KV_MODE": "json",
        "AUTO_KV_JSON": "true",
    },
}

TRANSFORMS_STANZAS: dict[str, dict[str, str]] = {
    "agtsmith_xml_event_id": {
        "REGEX": r"<EventID(?:\s+[^>]*)?>([^<]+)</EventID>",
        "FORMAT": "EventID::$1",
    },
    "agtsmith_xml_channel": {
        "REGEX": r"<Channel>([^<]+)</Channel>",
        "FORMAT": "Channel::$1",
    },
    "agtsmith_xml_computer": {
        "REGEX": r"<Computer>([^<]+)</Computer>",
        "FORMAT": "Computer::$1",
    },
    "agtsmith_xml_provider": {
        "REGEX": r"<Provider\s+Name=[\"']([^\"']+)[\"']",
        "FORMAT": "SourceName::$1",
    },
    "agtsmith_xml_eventdata": {
        "REGEX": r"<Data\s+Name=[\"']([^\"']+)[\"']>([^<]*)</Data>",
        "FORMAT": "$1::$2",
        "REPEAT_MATCH": "true",
        "MV_ADD": "true",
    },
}


def _ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _auth_headers(ui_env: dict[str, str]) -> dict[str, str]:
    user = str(ui_env.get("SPLUNK_USER", "")).strip()
    password = str(
        ui_env.get("SPLUNK_PASS", ui_env.get("SPLUNK_PASSWORD", ""))
    ).strip()
    if not user or not password:
        raise RuntimeError(
            "fidelity_extractions_auth_missing:"
            "SPLUNK_USER and SPLUNK_PASS required in config/ui.env"
        )
    encoded = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode(
        "ascii"
    )
    return {
        "Authorization": f"Basic {encoded}",
        "Content-Type": "application/x-www-form-urlencoded",
    }


def _request(
    method: str,
    url: str,
    headers: dict[str, str],
    fields: dict[str, str] | None = None,
) -> dict[str, Any]:
    data = (
        urllib.parse.urlencode(fields).encode("utf-8")
        if fields is not None
        else None
    )
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(
            request,
            timeout=60,
            context=_ssl_context(),
        ) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:800]
        raise RuntimeError(f"rest_error:{exc.code}:{detail}") from exc
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = {"raw": body}
    return payload if isinstance(payload, dict) else {"raw": body}


def _collection_url(base: str, conf_name: str) -> str:
    return (
        f"{base}/servicesNS/nobody/search/configs/conf-{conf_name}"
        "?output_mode=json"
    )


def _stanza_url(base: str, conf_name: str, stanza: str) -> str:
    encoded = urllib.parse.quote(stanza, safe="")
    return (
        f"{base}/servicesNS/nobody/search/configs/conf-{conf_name}/{encoded}"
        "?output_mode=json"
    )


def _stanza_exists(
    base: str,
    headers: dict[str, str],
    conf_name: str,
    stanza: str,
) -> bool:
    try:
        _request("GET", _stanza_url(base, conf_name, stanza), headers)
        return True
    except RuntimeError as exc:
        if "rest_error:404:" in str(exc):
            return False
        raise


def _upsert_stanza(
    base: str,
    headers: dict[str, str],
    conf_name: str,
    stanza: str,
    values: dict[str, str],
) -> str:
    exists = _stanza_exists(base, headers, conf_name, stanza)
    if not exists:
        _request(
            "POST",
            _collection_url(base, conf_name),
            headers,
            {"name": stanza},
        )
    _request(
        "POST",
        _stanza_url(base, conf_name, stanza),
        headers,
        values,
    )
    return "updated" if exists else "created"


def install(*, dry_run: bool = False) -> dict[str, Any]:
    ui_env = load_ui_env()
    base = str(
        ui_env.get("SPLUNK_BASE_URL", "https://127.0.0.1:8089")
    ).rstrip("/")
    report: dict[str, Any] = {
        "base_url": base,
        "dry_run": dry_run,
        "props": {},
        "transforms": {},
    }
    if dry_run:
        report["props"] = {name: "planned" for name in PROPS_STANZAS}
        report["transforms"] = {
            name: "planned" for name in TRANSFORMS_STANZAS
        }
        return report

    headers = _auth_headers(ui_env)
    for name, values in TRANSFORMS_STANZAS.items():
        report["transforms"][name] = _upsert_stanza(
            base,
            headers,
            "transforms",
            name,
            values,
        )
    for name, values in PROPS_STANZAS.items():
        report["props"][name] = _upsert_stanza(
            base,
            headers,
            "props",
            name,
            values,
        )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Install lab fidelity search-time field extractions"
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        report = install(dry_run=args.dry_run)
    except Exception as exc:
        print(f"ERROR setup_fidelity_extractions: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
