#!/usr/bin/env python3
"""Launch a loopback-only web UI for previewing and generating Splunk lab data."""

from __future__ import annotations

import argparse
import json
import math
import random
import secrets
import sys
import threading
import time
import webbrowser
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from environment_profile import PROFILE_PATH_DEFAULT  # noqa: E402
from lab_data.config import (  # noqa: E402
    get_layout,
    load_event_catalog,
    load_layout_config,
    load_ui_env,
    resolve_domain_target,
    resolve_layout_name,
)
from lab_data_generate import _build_events_for_set, generate  # noqa: E402

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8790
MAX_BODY_BYTES = 64 * 1024
MAX_COUNT_PER_SET = 500
MAX_HOURS = 24 * 90
MAX_RANGE_SECONDS = MAX_HOURS * 3600
MAX_FUTURE_SKEW_SECONDS = 5 * 60
MAX_EVENTS_PER_REQUEST = 10_000
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
TIME_RANGE_PRESETS: dict[str, tuple[str, float]] = {
    "last_hour": ("Last hour", 1.0),
    "last_6_hours": ("Last 6 hours", 6.0),
    "last_24_hours": ("Last 24 hours", 24.0),
    "last_7_days": ("Last 7 days", 24.0 * 7),
}


def _available_layouts() -> list[dict[str, str]]:
    layouts = load_layout_config().get("layouts", {})
    if not isinstance(layouts, dict):
        return []
    return [
        {
            "name": str(name),
            "description": str(layout.get("description", "")) if isinstance(layout, dict) else "",
        }
        for name, layout in layouts.items()
    ]


def _default_layout() -> str:
    selected = resolve_layout_name(
        "",
        profile_path=PROFILE_PATH_DEFAULT,
        ui_env=load_ui_env(),
    )
    names = {row["name"] for row in _available_layouts()}
    if selected in names:
        return selected
    return "expanded_lab" if "expanded_lab" in names else next(iter(names), "existing_lab")


def _sample_text(event: Any) -> str:
    if isinstance(event, dict):
        return json.dumps(event, indent=2, sort_keys=True)
    return str(event)


def build_catalog(layout_name: str) -> dict[str, Any]:
    """Build UI-safe layout, sourcetype, event-set, and sample metadata."""
    layout = get_layout(layout_name)
    indexes = layout.get("indexes", {})
    if not isinstance(indexes, dict):
        raise ValueError("layout_indexes_missing")

    catalog = load_event_catalog()
    defaults = catalog.get("defaults", {}) if isinstance(catalog.get("defaults"), dict) else {}
    sets_raw = catalog.get("event_sets", {})
    if not isinstance(sets_raw, dict):
        raise ValueError("event_sets_missing")

    sourcetype_map: dict[str, dict[str, Any]] = {}
    for domain, target in indexes.items():
        if not isinstance(target, dict):
            continue
        index = str(target.get("index", "")).strip()
        sourcetype = str(target.get("sourcetype", "")).strip()
        if not index or not sourcetype:
            continue
        key = sourcetype
        entry = sourcetype_map.setdefault(
            key,
            {
                "key": sourcetype,
                "indexes": [],
                "sourcetype": sourcetype,
                "domains": [],
                "event_sets": [],
            },
        )
        entry["indexes"].append(index)
        entry["domains"].append(str(domain))

    event_sets: list[dict[str, Any]] = []
    for name, event_set in sets_raw.items():
        if not isinstance(event_set, dict):
            continue
        domain = str(event_set.get("domain", "")).strip()
        try:
            target = resolve_domain_target(layout_name, domain)
        except (KeyError, ValueError):
            continue
        rows = _build_events_for_set(
            event_set,
            layout_name=layout_name,
            count=1,
            hours=1,
            defaults=defaults,
            rng=random.Random(f"{layout_name}:{name}"),
        )
        if not rows:
            continue
        sample = rows[0]
        index = target["index"]
        sourcetype = target["sourcetype"]
        sourcetype_key = sourcetype
        row = {
            "id": str(name),
            "title": str(name).replace("_", " ").title(),
            "benchmark_case": str(event_set.get("benchmark_case", "")),
            "domain": domain,
            "format": str(event_set.get("format", "raw")).lower(),
            "index": index,
            "sourcetype": sourcetype,
            "sourcetype_key": sourcetype_key,
            "source": str(event_set.get("source", "")),
            "sample": _sample_text(sample.get("event")),
        }
        event_sets.append(row)
        sourcetype_entry = sourcetype_map.setdefault(
            sourcetype,
            {
                "key": sourcetype_key,
                "indexes": [index],
                "sourcetype": sourcetype,
                "domains": [domain],
                "event_sets": [],
            },
        )
        sourcetype_entry["indexes"].append(index)
        sourcetype_entry["event_sets"].append(str(name))

    sourcetypes = sorted(
        sourcetype_map.values(),
        key=lambda row: str(row["sourcetype"]).lower(),
    )
    for row in sourcetypes:
        row["indexes"] = sorted(set(row["indexes"]))
        row["domains"] = sorted(set(row["domains"]))
        row["event_sets"] = sorted(set(row["event_sets"]))

    return {
        "layout": layout_name,
        "description": str(layout.get("description", "")),
        "sourcetypes": sourcetypes,
        "event_sets": event_sets,
    }


def _finite_float(value: Any, *, error: str) -> float:
    if isinstance(value, bool):
        raise ValueError(error)
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(error) from exc
    if not math.isfinite(parsed):
        raise ValueError(error)
    return parsed


def _timestamp(value: Any, *, field: str) -> float:
    parsed = _finite_float(value, error=f"invalid_{field}")
    try:
        datetime.fromtimestamp(parsed, timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise ValueError(f"invalid_{field}") from exc
    return parsed


def validate_generate_request(
    payload: Any,
    *,
    now_epoch: float | None = None,
) -> dict[str, Any]:
    """Validate browser generation input against catalog allow-lists."""
    if not isinstance(payload, dict):
        raise ValueError("request_body_must_be_object")
    allowed_fields = {
        "layout",
        "event_sets",
        "count",
        "time_range",
        "start_time",
        "end_time",
        "hours",
    }
    if any(not isinstance(key, str) or key not in allowed_fields for key in payload):
        raise ValueError("unknown_request_field")

    layout = str(payload.get("layout", "")).strip()
    layout_names = {row["name"] for row in _available_layouts()}
    if layout not in layout_names:
        raise ValueError("unknown_layout")

    requested = payload.get("event_sets")
    if not isinstance(requested, list) or not requested:
        raise ValueError("event_sets_required")
    if len(requested) > 100 or any(not isinstance(item, str) for item in requested):
        raise ValueError("invalid_event_sets")
    event_sets = list(dict.fromkeys(str(item).strip() for item in requested if str(item).strip()))

    allowed = {row["id"] for row in build_catalog(layout)["event_sets"]}
    if not event_sets or any(item not in allowed for item in event_sets):
        raise ValueError("unknown_event_set")

    count_number = _finite_float(payload.get("count", 50), error="invalid_count")
    if not count_number.is_integer():
        raise ValueError("invalid_count")
    count = int(count_number)
    if count < 1 or count > MAX_COUNT_PER_SET:
        raise ValueError(f"count_out_of_range:1-{MAX_COUNT_PER_SET}")

    selection = str(payload.get("time_range", "")).strip()
    if not selection:
        selection = "relative_hours" if "hours" in payload else "last_6_hours"

    start_time: float | None = None
    end_time: float | None = None
    if selection in TIME_RANGE_PRESETS:
        if "start_time" in payload or "end_time" in payload or "hours" in payload:
            raise ValueError("preset_range_has_unexpected_fields")
        label, hours = TIME_RANGE_PRESETS[selection]
        range_details: dict[str, Any] = {
            "selection": selection,
            "mode": "relative",
            "label": label,
            "hours": hours,
        }
    elif selection == "custom":
        if "hours" in payload:
            raise ValueError("custom_range_has_unexpected_hours")
        start_time = _timestamp(payload.get("start_time"), field="start_time")
        end_time = _timestamp(payload.get("end_time"), field="end_time")
        if start_time >= end_time:
            raise ValueError("time_range_start_must_precede_end")
        span_seconds = end_time - start_time
        if span_seconds > MAX_RANGE_SECONDS:
            raise ValueError(f"time_range_exceeds_max_days:{MAX_HOURS // 24}")
        current_time = time.time() if now_epoch is None else _finite_float(
            now_epoch,
            error="invalid_current_time",
        )
        if end_time > current_time + MAX_FUTURE_SKEW_SECONDS:
            raise ValueError("time_range_end_too_far_in_future")
        hours = span_seconds / 3600.0
        range_details = {
            "selection": "custom",
            "mode": "explicit",
            "label": "Custom range",
            "hours": hours,
            "start_epoch": start_time,
            "end_epoch": end_time,
        }
    elif selection == "relative_hours":
        if "start_time" in payload or "end_time" in payload:
            raise ValueError("relative_range_has_unexpected_fields")
        hours = _finite_float(payload.get("hours", 6), error="invalid_hours")
        if hours < 0.1 or hours > MAX_HOURS:
            raise ValueError(f"hours_out_of_range:0.1-{MAX_HOURS}")
        range_details = {
            "selection": "relative_hours",
            "mode": "relative",
            "label": f"Last {hours:g} hours",
            "hours": hours,
        }
    else:
        raise ValueError("unknown_time_range")

    if count * len(event_sets) > MAX_EVENTS_PER_REQUEST:
        raise ValueError(f"event_limit_exceeded:{MAX_EVENTS_PER_REQUEST}")

    return {
        "layout": layout,
        "event_sets": event_sets,
        "count": count,
        "hours": hours,
        "start_time": start_time,
        "end_time": end_time,
        "time_range": range_details,
    }


class LabDataWebServer(ThreadingHTTPServer):
    """HTTP server state for CSRF, CSP, and one-at-a-time generation."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int]) -> None:
        self.csrf_token = secrets.token_urlsafe(32)
        self.csp_nonce = secrets.token_urlsafe(24)
        self.generation_lock = threading.Lock()
        super().__init__(server_address, LabDataRequestHandler)


class LabDataRequestHandler(BaseHTTPRequestHandler):
    """Serve the lab-data page and its narrow JSON API."""

    server_version = "AgtsmithLabData"
    sys_version = ""

    def version_string(self) -> str:
        return self.server_version

    @property
    def app(self) -> LabDataWebServer:
        return self.server  # type: ignore[return-value]

    def _host_allowed(self) -> bool:
        host = self.headers.get("Host", "")
        try:
            hostname = urlsplit(f"//{host}").hostname
        except ValueError:
            return False
        return hostname in LOOPBACK_HOSTS

    def _origin_allowed(self) -> bool:
        origin = self.headers.get("Origin", "").strip()
        if not origin:
            return True
        try:
            parsed = urlsplit(origin)
            expected_port = int(self.app.server_address[1])
            origin_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except (TypeError, ValueError):
            return False
        return (
            parsed.scheme == "http"
            and parsed.hostname in LOOPBACK_HOSTS
            and origin_port == expected_port
        )

    def _security_headers(self, content_type: str) -> None:
        nonce = self.app.csp_nonce
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            (
                "default-src 'none'; "
                f"style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; "
                "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            ),
        )

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._security_headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_page(self) -> None:
        page = (
            PAGE_HTML.replace("__CSRF_TOKEN__", json.dumps(self.app.csrf_token))
            .replace("__CSP_NONCE__", self.app.csp_nonce)
        )
        body = page.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self._security_headers("text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _reject_bad_host(self) -> bool:
        if self._host_allowed():
            return False
        self._send_json(HTTPStatus.MISDIRECTED_REQUEST, {"ok": False, "error": "invalid_host"})
        return True

    def do_GET(self) -> None:  # noqa: N802
        if self._reject_bad_host():
            return
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            self._send_page()
            return
        if parsed.path == "/api/health":
            ui_env = load_ui_env()
            hec_url = str(ui_env.get("SPLUNK_HEC_URL", "")).strip()
            parsed_hec = urlsplit(hec_url) if hec_url else None
            target = (
                f"{parsed_hec.hostname}:{parsed_hec.port or 443}"
                if parsed_hec and parsed_hec.hostname
                else "Not configured"
            )
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "hec_configured": bool(hec_url and ui_env.get("SPLUNK_HEC_TOKEN")),
                    "target": target,
                    "default_layout": _default_layout(),
                    "layouts": _available_layouts(),
                },
            )
            return
        if parsed.path == "/api/catalog":
            layout = parse_qs(parsed.query).get("layout", [_default_layout()])[0]
            try:
                payload = build_catalog(str(layout))
            except (KeyError, ValueError) as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
                return
            self._send_json(HTTPStatus.OK, {"ok": True, **payload})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self._reject_bad_host():
            return
        if self.path != "/api/generate":
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})
            return
        if not self._origin_allowed():
            self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "invalid_origin"})
            return
        supplied_token = self.headers.get("X-CSRF-Token", "")
        if not secrets.compare_digest(supplied_token, self.app.csrf_token):
            self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "csrf_rejected"})
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._send_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                {"ok": False, "error": "application_json_required"},
            )
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = -1
        if content_length < 1 or content_length > MAX_BODY_BYTES:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"ok": False, "error": "request_size_invalid"},
            )
            return
        try:
            body = json.loads(self.rfile.read(content_length))
            request = validate_generate_request(body)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return

        if not self.app.generation_lock.acquire(blocking=False):
            self._send_json(
                HTTPStatus.CONFLICT,
                {"ok": False, "error": "generation_already_running"},
            )
            return
        try:
            generate_options: dict[str, Any] = {
                "layout": request["layout"],
                "count": request["count"],
                "hours": request["hours"],
                "event_sets": request["event_sets"],
                "dry_run": False,
            }
            if request["start_time"] is not None and request["end_time"] is not None:
                generate_options["start_time"] = request["start_time"]
                generate_options["end_time"] = request["end_time"]
            report = generate(
                **generate_options,
            )
        except Exception as exc:
            self._send_json(
                HTTPStatus.BAD_GATEWAY,
                {"ok": False, "error": str(exc)},
            )
            return
        finally:
            self.app.generation_lock.release()

        errors = [str(item) for item in report.get("errors", [])]
        status = HTTPStatus.OK if not errors else HTTPStatus.BAD_GATEWAY
        generated_range = report.get("time_range", {})
        response_range = (
            dict(generated_range)
            if isinstance(generated_range, dict)
            else {}
        )
        response_range.update(
            {
                "selection": request["time_range"]["selection"],
                "label": request["time_range"]["label"],
            }
        )
        self._send_json(
            status,
            {
                "ok": not errors,
                "layout": report.get("layout"),
                "event_count": report.get("event_count", 0),
                "sent": report.get("sent", 0),
                "transport": report.get("transport", ""),
                "hours": report.get("hours"),
                "time_range": response_range,
                "selected_event_sets": request["event_sets"],
                "errors": errors[:5],
            },
        )

    def log_message(self, format_string: str, *args: Any) -> None:
        message = format_string % args
        sys.stderr.write(f"[lab-data-web] {self.address_string()} {message}\n")


PAGE_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Splunk Lab Data Studio</title>
  <style nonce="__CSP_NONCE__">
    :root {
      color-scheme: dark;
      --bg: #0b0f14;
      --panel: #111821;
      --panel-2: #151e29;
      --line: #263241;
      --text: #e8eef6;
      --muted: #91a0b3;
      --accent: #50d890;
      --accent-strong: #24b36b;
      --warning: #f1b84b;
      --danger: #ff6b6b;
      --code: #090d12;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    button, input, select { font: inherit; }
    button { cursor: pointer; }
    .shell { max-width: 1480px; margin: 0 auto; padding: 28px; }
    header { display: flex; justify-content: space-between; gap: 24px; align-items: flex-start; margin-bottom: 24px; }
    .eyebrow { color: var(--accent); font-size: 12px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; }
    h1 { margin: 4px 0 6px; font-size: clamp(28px, 4vw, 46px); line-height: 1.05; letter-spacing: -.035em; }
    h2 { margin: 0; font-size: 18px; }
    p { margin: 0; color: var(--muted); }
    .status {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--panel);
      color: var(--muted);
      white-space: nowrap;
    }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--warning); }
    .dot.ok { background: var(--accent); }
    .panel { border: 1px solid var(--line); border-radius: 16px; background: var(--panel); }
    .controls { display: grid; grid-template-columns: 2fr 1fr 1.25fr; gap: 14px; padding: 18px; margin-bottom: 18px; }
    label { display: grid; gap: 7px; color: var(--muted); font-size: 12px; font-weight: 650; }
    select, input {
      width: 100%;
      min-height: 42px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: var(--panel-2);
      color: var(--text);
      padding: 9px 11px;
      outline: none;
    }
    select:focus, input:focus { border-color: var(--accent-strong); }
    [hidden] { display: none !important; }
    .custom-range {
      display: grid;
      grid-template-columns: 1fr 1fr;
      grid-column: 1 / -1;
      gap: 14px;
      padding-top: 2px;
    }
    .range-hint { grid-column: 1 / -1; color: var(--muted); font-size: 12px; }
    .workspace { display: grid; grid-template-columns: 300px minmax(0, 1fr); gap: 18px; align-items: start; }
    aside { position: sticky; top: 18px; padding: 16px; }
    .aside-title { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 12px; }
    .tiny { color: var(--muted); font-size: 12px; }
    .source-list { display: grid; gap: 8px; max-height: 62vh; overflow: auto; padding-right: 3px; }
    .source-button {
      width: 100%;
      border: 1px solid transparent;
      border-radius: 10px;
      padding: 10px;
      text-align: left;
      color: var(--text);
      background: var(--panel-2);
    }
    .source-button:hover, .source-button.active { border-color: var(--accent-strong); }
    .source-button[disabled] { cursor: default; opacity: .55; }
    .source-name { display: block; font-weight: 700; overflow-wrap: anywhere; }
    .source-meta { display: block; color: var(--muted); font-size: 11px; margin-top: 3px; }
    main { min-width: 0; }
    .toolbar { display: grid; grid-template-columns: minmax(220px, 1fr) auto auto; gap: 10px; margin-bottom: 14px; }
    .secondary {
      border: 1px solid var(--line);
      border-radius: 10px;
      background: var(--panel);
      color: var(--text);
      padding: 9px 13px;
    }
    .secondary:hover { border-color: var(--accent-strong); }
    .summary { display: flex; justify-content: space-between; gap: 14px; align-items: center; margin-bottom: 14px; }
    .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 14px; }
    .card {
      border: 1px solid var(--line);
      border-radius: 14px;
      background: var(--panel);
      padding: 16px;
      min-width: 0;
    }
    .card.selected { border-color: var(--accent-strong); background: #112019; }
    .card-head { display: flex; gap: 11px; align-items: flex-start; }
    .card-head input { width: 18px; min-height: 18px; margin: 3px 0 0; accent-color: var(--accent-strong); }
    .card-title { font-weight: 750; font-size: 16px; }
    .badges { display: flex; flex-wrap: wrap; gap: 6px; margin: 12px 0; }
    .badge { padding: 4px 7px; border-radius: 7px; background: var(--panel-2); color: var(--muted); font-size: 11px; }
    .badge.format { color: var(--accent); text-transform: uppercase; font-weight: 700; }
    details { border-top: 1px solid var(--line); padding-top: 11px; }
    summary { color: var(--muted); cursor: pointer; user-select: none; }
    pre {
      margin: 10px 0 0;
      padding: 12px;
      max-height: 250px;
      overflow: auto;
      border-radius: 10px;
      background: var(--code);
      color: #c8d5e5;
      font: 11px/1.55 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .footer {
      position: sticky;
      bottom: 14px;
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
      margin-top: 18px;
      padding: 14px 16px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgba(17, 24, 33, .96);
      backdrop-filter: blur(12px);
    }
    .primary {
      border: 0;
      border-radius: 10px;
      background: var(--accent);
      color: #07110b;
      font-weight: 800;
      padding: 11px 18px;
    }
    .primary:hover { background: #6fe4a5; }
    .primary:disabled { cursor: not-allowed; opacity: .45; }
    .result { display: none; margin-top: 14px; padding: 14px 16px; }
    .result.show { display: block; }
    .result.error { border-color: var(--danger); }
    .result.success { border-color: var(--accent-strong); }
    .empty { padding: 42px; text-align: center; color: var(--muted); }
    @media (max-width: 860px) {
      .shell { padding: 18px; }
      header { display: grid; }
      .controls { grid-template-columns: 1fr; }
      .custom-range { grid-template-columns: 1fr; }
      .workspace { grid-template-columns: 1fr; }
      aside { position: static; }
      .source-list { max-height: 280px; }
      .toolbar { grid-template-columns: 1fr 1fr; }
      .toolbar input { grid-column: 1 / -1; }
      .footer { align-items: stretch; flex-direction: column; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header>
      <div>
        <div class="eyebrow">A.G.E.N.T. Smith local lab</div>
        <h1>Splunk Lab Data Studio</h1>
        <p>Select precise event families, inspect their payloads, then send time-fresh data to local Splunk.</p>
      </div>
      <div class="status"><span id="statusDot" class="dot"></span><span id="statusText">Checking HEC…</span></div>
    </header>

    <section class="panel controls" aria-label="Generation controls">
      <label>Lab layout
        <select id="layout"></select>
      </label>
      <label>Events per selection
        <input id="count" type="number" min="1" max="500" value="50">
      </label>
      <label>Timestamp range
        <select id="timeRange" aria-describedby="rangeHint">
          <option value="last_hour">Last hour</option>
          <option value="last_6_hours" selected>Last 6 hours</option>
          <option value="last_24_hours">Last 24 hours</option>
          <option value="last_7_days">Last 7 days</option>
          <option value="custom">Custom…</option>
        </select>
      </label>
      <div id="customRange" class="custom-range" hidden>
        <label>Custom start (local time)
          <input id="rangeStart" type="datetime-local" step="60">
        </label>
        <label>Custom end (local time)
          <input id="rangeEnd" type="datetime-local" step="60">
        </label>
      </div>
      <div id="rangeHint" class="range-hint" role="status" aria-live="polite"></div>
    </section>

    <div class="workspace">
      <aside class="panel">
        <div class="aside-title"><h2>Available sourcetypes</h2><span id="sourceCount" class="tiny"></span></div>
        <div id="sourceList" class="source-list"></div>
      </aside>

      <main>
        <div class="toolbar">
          <input id="search" type="search" placeholder="Filter by event, domain, index, or sourcetype">
          <button id="selectVisible" class="secondary" type="button">Select visible</button>
          <button id="clearSelection" class="secondary" type="button">Clear</button>
        </div>
        <div class="summary">
          <div>
            <h2 id="layoutTitle">Loading catalog…</h2>
            <p id="layoutDescription"></p>
          </div>
          <span id="visibleCount" class="tiny"></span>
        </div>
        <div id="cards" class="cards"></div>
        <div id="result" class="panel result" role="status" aria-live="polite"></div>
        <div class="footer">
          <div>
            <strong id="selectionSummary">0 event families selected</strong>
            <div id="eventEstimate" class="tiny" aria-live="polite">0 events will be sent across the last 6 hours</div>
          </div>
          <button id="generate" class="primary" type="button" disabled>Generate and send to Splunk</button>
        </div>
      </main>
    </div>
  </div>

  <script nonce="__CSP_NONCE__">
    "use strict";
    const CSRF = __CSRF_TOKEN__;
    const state = { catalog: null, selected: new Set(), activeSource: "", busy: false };
    const byId = (id) => document.getElementById(id);
    const RANGE_LABELS = Object.freeze({
      last_hour: "Last hour",
      last_6_hours: "Last 6 hours",
      last_24_hours: "Last 24 hours",
      last_7_days: "Last 7 days",
    });
    const MAX_RANGE_MILLISECONDS = 90 * 24 * 60 * 60 * 1000;
    const MAX_FUTURE_SKEW_MILLISECONDS = 5 * 60 * 1000;

    function node(tag, className, text) {
      const item = document.createElement(tag);
      if (className) item.className = className;
      if (text !== undefined) item.textContent = text;
      return item;
    }

    function searchText(row) {
      return [row.id, row.title, row.domain, row.index, row.sourcetype, row.source, row.benchmark_case]
        .join(" ").toLowerCase();
    }

    function visibleRows() {
      if (!state.catalog) return [];
      const query = byId("search").value.trim().toLowerCase();
      return state.catalog.event_sets.filter((row) => {
        const sourceMatch = !state.activeSource || row.sourcetype_key === state.activeSource;
        return sourceMatch && (!query || searchText(row).includes(query));
      });
    }

    function datetimeLocalValue(date) {
      const pad = (value) => String(value).padStart(2, "0");
      return [
        `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`,
        `${pad(date.getHours())}:${pad(date.getMinutes())}`,
      ].join("T");
    }

    function initializeCustomRange() {
      if (byId("rangeStart").value && byId("rangeEnd").value) return;
      const end = new Date();
      end.setSeconds(0, 0);
      const start = new Date(end.getTime() - (6 * 60 * 60 * 1000));
      byId("rangeStart").value = datetimeLocalValue(start);
      byId("rangeEnd").value = datetimeLocalValue(end);
    }

    function localDateLabel(milliseconds) {
      return new Date(milliseconds).toLocaleString([], {
        dateStyle: "medium",
        timeStyle: "short",
      });
    }

    function durationLabel(milliseconds) {
      const hours = milliseconds / (60 * 60 * 1000);
      if (hours >= 48 && Number.isInteger(hours / 24)) return `${hours / 24} days`;
      return `${Number(hours.toFixed(1))} ${hours === 1 ? "hour" : "hours"}`;
    }

    function selectedTimeRange() {
      const selection = byId("timeRange").value;
      if (selection !== "custom") {
        const label = RANGE_LABELS[selection];
        return {
          valid: Boolean(label),
          label: label || "Unknown range",
          payload: { time_range: selection },
        };
      }

      const startValue = byId("rangeStart").value;
      const endValue = byId("rangeEnd").value;
      const startMilliseconds = new Date(startValue).getTime();
      const endMilliseconds = new Date(endValue).getTime();
      if (!startValue || !endValue || !Number.isFinite(startMilliseconds) || !Number.isFinite(endMilliseconds)) {
        return { valid: false, label: "Choose a custom start and end", payload: {} };
      }
      if (startMilliseconds >= endMilliseconds) {
        return { valid: false, label: "Custom start must be before end", payload: {} };
      }
      const span = endMilliseconds - startMilliseconds;
      if (span > MAX_RANGE_MILLISECONDS) {
        return { valid: false, label: "Custom range cannot exceed 90 days", payload: {} };
      }
      if (endMilliseconds > Date.now() + MAX_FUTURE_SKEW_MILLISECONDS) {
        return { valid: false, label: "Custom end cannot be in the future", payload: {} };
      }
      return {
        valid: true,
        label: `${localDateLabel(startMilliseconds)} to ${localDateLabel(endMilliseconds)} (${durationLabel(span)})`,
        payload: {
          time_range: "custom",
          start_time: startMilliseconds / 1000,
          end_time: endMilliseconds / 1000,
        },
      };
    }

    function updateRangeControls() {
      const custom = byId("timeRange").value === "custom";
      byId("customRange").hidden = !custom;
      if (custom) initializeCustomRange();
      const range = selectedTimeRange();
      byId("rangeHint").textContent = `Synthetic timestamps: ${range.label}.`;
      updateSelectionSummary();
    }

    function updateSelectionSummary() {
      const count = Number(byId("count").value || 0);
      const families = state.selected.size;
      const range = selectedTimeRange();
      byId("selectionSummary").textContent = `${families} event ${families === 1 ? "family" : "families"} selected`;
      byId("eventEstimate").textContent = `${(families * count).toLocaleString()} events will be sent across ${range.label}`;
      byId("generate").disabled = families === 0 || state.busy || !range.valid;
    }

    function renderSources() {
      const container = byId("sourceList");
      container.replaceChildren();
      const all = node("button", `source-button${state.activeSource === "" ? " active" : ""}`);
      all.type = "button";
      all.append(node("span", "source-name", "All generatable data"));
      all.append(node("span", "source-meta", `${state.catalog.event_sets.length} event families`));
      all.addEventListener("click", () => { state.activeSource = ""; renderSources(); renderCards(); });
      container.append(all);

      state.catalog.sourcetypes.forEach((source) => {
        const button = node("button", `source-button${state.activeSource === source.key ? " active" : ""}`);
        button.type = "button";
        button.disabled = source.event_sets.length === 0;
        button.append(node("span", "source-name", source.sourcetype));
        const suffix = source.event_sets.length === 0 ? "preview unavailable" : `${source.event_sets.length} event families`;
        button.append(node("span", "source-meta", `${source.indexes.join(", ")} · ${suffix}`));
        button.addEventListener("click", () => {
          state.activeSource = source.key;
          renderSources();
          renderCards();
        });
        container.append(button);
      });
      byId("sourceCount").textContent = `${state.catalog.sourcetypes.length} mappings`;
    }

    function renderCards() {
      const container = byId("cards");
      container.replaceChildren();
      const rows = visibleRows();
      byId("visibleCount").textContent = `${rows.length} shown`;
      if (!rows.length) {
        container.append(node("div", "panel empty", "No event families match this filter."));
        return;
      }
      rows.forEach((row) => {
        const card = node("article", `card${state.selected.has(row.id) ? " selected" : ""}`);
        const head = node("div", "card-head");
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.checked = state.selected.has(row.id);
        checkbox.setAttribute("aria-label", `Select ${row.title}`);
        checkbox.addEventListener("change", () => {
          if (checkbox.checked) state.selected.add(row.id); else state.selected.delete(row.id);
          card.classList.toggle("selected", checkbox.checked);
          updateSelectionSummary();
        });
        const identity = node("div");
        identity.append(node("div", "card-title", row.title));
        identity.append(node("div", "tiny", row.benchmark_case || row.domain));
        head.append(checkbox, identity);
        card.append(head);

        const badges = node("div", "badges");
        badges.append(node("span", "badge format", row.format));
        badges.append(node("span", "badge", `index=${row.index}`));
        badges.append(node("span", "badge", `sourcetype=${row.sourcetype}`));
        card.append(badges);

        const source = node("p", "tiny", `Source: ${row.source || "catalog default"} · Domain: ${row.domain}`);
        card.append(source);
        const details = document.createElement("details");
        details.append(node("summary", "", "View sample event"));
        details.append(node("pre", "", row.sample));
        card.append(details);
        container.append(card);
      });
    }

    async function loadCatalog() {
      state.selected.clear();
      state.activeSource = "";
      const layout = byId("layout").value;
      const response = await fetch(`/api/catalog?layout=${encodeURIComponent(layout)}`);
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Catalog request failed");
      state.catalog = payload;
      byId("layoutTitle").textContent = layout.replaceAll("_", " ");
      byId("layoutDescription").textContent = payload.description;
      renderSources();
      renderCards();
      updateSelectionSummary();
    }

    function showResult(ok, title, detail) {
      const result = byId("result");
      result.className = `panel result show ${ok ? "success" : "error"}`;
      result.replaceChildren(node("strong", "", title), node("p", "", detail));
      result.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }

    function returnedRangeLabel(timeRange) {
      if (!timeRange || typeof timeRange !== "object") return "Selected timestamp range";
      const start = Number(timeRange.start_epoch);
      const end = Number(timeRange.end_epoch);
      if (Number.isFinite(start) && Number.isFinite(end)) {
        return `${timeRange.label || "Timestamp range"}: ${localDateLabel(start * 1000)} to ${localDateLabel(end * 1000)}`;
      }
      return timeRange.label || "Selected timestamp range";
    }

    async function sendGeneration() {
      if (!state.selected.size || state.busy) return;
      const range = selectedTimeRange();
      if (!range.valid) {
        showResult(false, "Choose a valid timestamp range", range.label);
        return;
      }
      state.busy = true;
      byId("generate").textContent = "Generating…";
      updateSelectionSummary();
      try {
        const response = await fetch("/api/generate", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
          body: JSON.stringify({
            layout: byId("layout").value,
            event_sets: Array.from(state.selected),
            count: Number(byId("count").value),
            ...range.payload,
          }),
        });
        const payload = await response.json();
        if (!response.ok || !payload.ok) throw new Error(payload.error || (payload.errors || []).join(", "));
        showResult(
          true,
          `${payload.sent.toLocaleString()} events sent`,
          `${payload.selected_event_sets.length} event families · ${returnedRangeLabel(payload.time_range)} · ${payload.layout} · ${payload.transport.toUpperCase()} transport`
        );
      } catch (error) {
        showResult(false, "Generation failed", error instanceof Error ? error.message : String(error));
      } finally {
        state.busy = false;
        byId("generate").textContent = "Generate and send to Splunk";
        updateSelectionSummary();
      }
    }

    async function initialize() {
      try {
        initializeCustomRange();
        updateRangeControls();
        const response = await fetch("/api/health");
        const health = await response.json();
        const layoutSelect = byId("layout");
        health.layouts.forEach((layout) => {
          const option = document.createElement("option");
          option.value = layout.name;
          option.textContent = layout.name.replaceAll("_", " ");
          option.title = layout.description;
          layoutSelect.append(option);
        });
        layoutSelect.value = health.default_layout;
        byId("statusText").textContent = health.hec_configured ? `HEC ready · ${health.target}` : "HEC is not configured";
        byId("statusDot").classList.toggle("ok", health.hec_configured);
        await loadCatalog();
      } catch (error) {
        showResult(false, "Studio failed to initialize", error instanceof Error ? error.message : String(error));
      }
    }

    byId("layout").addEventListener("change", () => loadCatalog().catch((error) => showResult(false, "Catalog failed", error.message)));
    byId("search").addEventListener("input", renderCards);
    byId("count").addEventListener("input", updateSelectionSummary);
    byId("timeRange").addEventListener("change", updateRangeControls);
    byId("rangeStart").addEventListener("input", updateRangeControls);
    byId("rangeEnd").addEventListener("input", updateRangeControls);
    byId("selectVisible").addEventListener("click", () => {
      visibleRows().forEach((row) => state.selected.add(row.id));
      renderCards();
      updateSelectionSummary();
    });
    byId("clearSelection").addEventListener("click", () => {
      state.selected.clear();
      renderCards();
      updateSelectionSummary();
    });
    byId("generate").addEventListener("click", sendGeneration);
    initialize();
  </script>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Launch the local Splunk lab-data web studio")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    if args.host not in LOOPBACK_HOSTS:
        print("ERROR: lab-data web UI only binds to 127.0.0.1, ::1, or localhost", file=sys.stderr)
        return 2
    if args.port < 1 or args.port > 65535:
        print("ERROR: port must be between 1 and 65535", file=sys.stderr)
        return 2

    server = LabDataWebServer((args.host, args.port))
    url = f"http://{args.host}:{server.server_address[1]}/"
    hec_ready = bool(
        load_ui_env().get("SPLUNK_HEC_URL")
        and load_ui_env().get("SPLUNK_HEC_TOKEN")
    )
    print(f"Splunk Lab Data Studio: {url}")
    print(f"HEC configured: {'yes' if hec_ready else 'no'}")
    print("Press Ctrl+C to stop.")
    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Lab Data Studio.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
