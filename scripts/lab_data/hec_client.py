#!/usr/bin/env python3
"""HTTP Event Collector client for lab data injection."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class HecConfig:
    url: str
    token: str
    insecure: bool = True
    timeout_sec: int = 30


class HecClient:
    def __init__(self, config: HecConfig) -> None:
        self.config = config

    @classmethod
    def from_env(cls, ui_env: dict[str, str]) -> HecClient:
        url = str(ui_env.get("SPLUNK_HEC_URL", "")).strip()
        token = str(ui_env.get("SPLUNK_HEC_TOKEN", "")).strip()
        if not url or not token:
            raise RuntimeError("hec_config_missing:SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN required in config/ui.env")
        insecure = str(ui_env.get("SPLUNK_HEC_INSECURE", "1")).strip().lower() in {"1", "true", "yes", "on"}
        return cls(HecConfig(url=url, token=token, insecure=insecure))

    def _context(self) -> ssl.SSLContext | None:
        if self.config.insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return None

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
        payload: dict[str, Any] = {
            "time": time_epoch,
            "host": host,
            "index": index,
            "sourcetype": sourcetype,
            "source": source,
        }
        if isinstance(event, dict):
            # Structured events (e.g. Windows JSON) — fields land as top-level event keys.
            body_event = dict(event)
            if fields:
                for key, value in fields.items():
                    body_event.setdefault(key, value)
            payload["event"] = body_event
        else:
            # Raw log lines — HEC event must be a string so Splunk uses it as _raw and
            # applies sourcetype props (access_combined, auth.log, etc.).
            payload["event"] = str(event)
            if fields:
                payload["fields"] = dict(fields)

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.config.url,
            data=data,
            method="POST",
            headers={
                "Authorization": f"Splunk {self.config.token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_sec, context=self._context()) as resp:
                if resp.status >= 300:
                    raise RuntimeError(f"hec_http_status:{resp.status}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"hec_http_error:{exc.code}:{detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"hec_unreachable:{exc}") from exc

    def ping(self) -> bool:
        try:
            req = urllib.request.Request(
                self.config.url,
                data=b"{}",
                method="POST",
                headers={
                    "Authorization": f"Splunk {self.config.token}",
                    "Content-Type": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=5, context=self._context()) as resp:
                return resp.status < 500
        except Exception:
            return False
