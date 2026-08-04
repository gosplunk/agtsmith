#!/usr/bin/env python3
"""Splunk receivers/simple ingestion (8089) when HEC is unavailable."""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ReceiversConfig:
    base_url: str
    user: str
    password: str
    timeout_sec: int = 30


class ReceiversClient:
    def __init__(self, config: ReceiversConfig) -> None:
        self.config = config

    @classmethod
    def from_env(cls, ui_env: dict[str, str]) -> ReceiversClient:
        base = str(ui_env.get("SPLUNK_BASE_URL", "https://127.0.0.1:8089")).rstrip("/")
        user = str(ui_env.get("SPLUNK_USER", ui_env.get("SOC_UI_AUTH_USERNAME", ""))).strip()
        password = str(ui_env.get("SPLUNK_PASS", ui_env.get("SPLUNK_PASSWORD", ""))).strip()
        if not user or not password:
            raise RuntimeError("receivers_auth_missing:SPLUNK_USER and SPLUNK_PASS required in config/ui.env")
        return cls(ReceiversConfig(base_url=base, user=user, password=password))

    def _context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _auth_header(self) -> str:
        cred = base64.b64encode(f"{self.config.user}:{self.config.password}".encode("utf-8")).decode("ascii")
        return f"Basic {cred}"

    def send_event(
        self,
        *,
        index: str,
        sourcetype: str,
        host: str,
        source: str,
        time_epoch: float,
        event: str | dict[str, Any],
        fields: dict[str, Any] | None = None,
    ) -> None:
        if isinstance(event, dict):
            body = dict(event)
            if fields:
                for key, value in fields.items():
                    body.setdefault(key, value)
            payload = json.dumps(body)
        else:
            payload = str(event)
            if fields:
                raise RuntimeError(
                    "receivers_string_fields_unsupported:"
                    "use HEC to attach lab metadata without changing raw events"
                )

        params = {
            "index": index,
            "sourcetype": sourcetype,
            "host": host,
            "source": source,
            "time": str(time_epoch),
        }
        url = f"{self.config.base_url}/services/receivers/simple?{urllib.parse.urlencode(params)}"
        req = urllib.request.Request(
            url,
            data=payload.encode("utf-8"),
            method="POST",
            headers={
                "Authorization": self._auth_header(),
                "Content-Type": "application/json" if isinstance(event, dict) else "text/plain",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_sec, context=self._context()) as resp:
                if resp.status >= 300:
                    raise RuntimeError(f"receivers_http_status:{resp.status}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"receivers_http_error:{exc.code}:{detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"receivers_unreachable:{exc}") from exc

    def ping(self) -> bool:
        url = f"{self.config.base_url}/services/server/info?output_mode=json"
        req = urllib.request.Request(url, method="GET", headers={"Authorization": self._auth_header()})
        try:
            with urllib.request.urlopen(req, timeout=5, context=self._context()) as resp:
                return resp.status < 300
        except Exception:
            return False
