#!/usr/bin/env python3
"""Remote Windows Ollama SSE log streaming adapter for the SOC lab app."""

from __future__ import annotations

import json
import os
import queue
import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

DEFAULT_REMOTE_URL = "http://192.168.169.173:8791/logs/stream"
DEFAULT_BUFFER_SIZE = 5000
ALLOWED_ROLES = {"admin", "ops"}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact_secrets(text: str) -> str:
    """Redact common secret/token patterns from log lines."""
    if not text:
        return text

    redacted = text
    patterns: list[tuple[re.Pattern[str], str]] = [
        (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)([^\s\"']+)"), r"\1[REDACTED_BEARER]"),
        (re.compile(r"(?i)(bearer\s+)([A-Za-z0-9_\-\./+=]{16,})"), r"\1[REDACTED_BEARER]"),
        (re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)([^\s\"']+)"), r"\1[REDACTED_API_KEY]"),
        (re.compile(r"(?i)(token\s*[=:]\s*)([^\s\"']+)"), r"\1[REDACTED_TOKEN]"),
        (re.compile(r"([A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})"), "[REDACTED_JWT]"),
    ]
    for pattern, repl in patterns:
        redacted = pattern.sub(repl, redacted)

    # Generic long high-entropy token-like strings.
    redacted = re.sub(r"(?<![A-Za-z0-9])[A-Za-z0-9_\-\./+=]{48,}(?![A-Za-z0-9])", "[REDACTED_SECRET]", redacted)
    return redacted


def infer_level(text: str) -> str:
    lowered = (text or "").lower()
    if any(k in lowered for k in (" fatal", "fatal", "panic", "critical")):
        return "fatal"
    if any(k in lowered for k in (" error", "[error]", "exception", "traceback")):
        return "error"
    if any(k in lowered for k in (" warn", "warning", "[warn]")):
        return "warn"
    if any(k in lowered for k in (" debug", "[debug]")):
        return "debug"
    return "info"


def line_matches_filters(entry: dict[str, Any], level: str = "", grep: str = "") -> bool:
    line = str(entry.get("line", ""))
    entry_level = str(entry.get("level", "info")).lower()
    level = (level or "").strip().lower()
    grep = (grep or "").strip().lower()

    if level and level != "all" and entry_level != level:
        return False
    if grep and grep not in line.lower():
        return False
    return True


def format_sse(event: str, payload: dict[str, Any]) -> bytes:
    data = json.dumps(payload, ensure_ascii=False)
    return f"event: {event}\ndata: {data}\n\n".encode("utf-8")


@dataclass(frozen=True)
class StreamParams:
    tail: int = 200
    level: str = ""
    grep: str = ""

    @staticmethod
    def from_values(tail: Any, level: Any, grep: Any) -> "StreamParams":
        t = 200
        try:
            if tail not in (None, ""):
                t = int(tail)
        except Exception:
            t = 200
        t = max(0, min(5000, t))
        lv = str(level or "").strip().lower()
        gp = str(grep or "").strip()
        return StreamParams(tail=t, level=lv, grep=gp)


class RemoteLogSource:
    """Single remote SSE stream with local buffer and multi-subscriber fanout."""

    def __init__(
        self,
        *,
        remote_url: str,
        remote_token: str,
        params: StreamParams,
        buffer_size: int = DEFAULT_BUFFER_SIZE,
    ) -> None:
        self.remote_url = remote_url
        self.remote_token = remote_token
        self.params = params
        self.buffer: deque[dict[str, Any]] = deque(maxlen=buffer_size)
        self.subscribers: dict[int, queue.Queue[dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._next_subscriber_id = 1
        self._started = False
        self._stop = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
            self._thread = threading.Thread(target=self._run, name="remote-ollama-log-source", daemon=True)
            self._thread.start()

    def subscribe(self) -> tuple[int, queue.Queue[dict[str, Any]]]:
        q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=2000)
        with self._lock:
            sid = self._next_subscriber_id
            self._next_subscriber_id += 1
            self.subscribers[sid] = q
        return sid, q

    def unsubscribe(self, sid: int) -> None:
        with self._lock:
            self.subscribers.pop(sid, None)

    def get_recent(self, n: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.buffer)[-max(0, n) :]

    def _emit(self, event: dict[str, Any], *, save_log: bool = False) -> None:
        if save_log:
            with self._lock:
                self.buffer.append(event)
        with self._lock:
            subscribers = list(self.subscribers.values())
        for q in subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except Exception:
                    pass

    def _emit_status(self, state: str, detail: str = "") -> None:
        self._emit(
            {
                "type": "status",
                "state": state,
                "detail": detail,
                "ts": utc_now_iso(),
            },
            save_log=False,
        )

    def _emit_error(self, code: str, message: str, *, retry_in_seconds: float | None = None) -> None:
        self._emit(
            {
                "type": "error",
                "code": code,
                "message": redact_secrets(message),
                "retry_in_seconds": retry_in_seconds,
                "ts": utc_now_iso(),
            },
            save_log=False,
        )

    def _normalize_line_event(self, raw_data: str) -> dict[str, Any]:
        line = raw_data
        payload: dict[str, Any] = {}
        try:
            maybe = json.loads(raw_data)
            if isinstance(maybe, dict):
                payload = maybe
                line = str(
                    maybe.get("line")
                    or maybe.get("message")
                    or maybe.get("msg")
                    or raw_data
                )
        except Exception:
            payload = {}

        line = redact_secrets(line)
        entry_level = str(payload.get("level") or infer_level(line)).lower()

        entry = {
            "type": "log",
            "line": line,
            "level": entry_level,
            "ts": str(payload.get("ts") or payload.get("timestamp") or utc_now_iso()),
            "ingest_ts": utc_now_iso(),
            "raw": payload,
        }
        return entry

    def _stream_once(self) -> None:
        headers = {
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
        }
        if self.remote_token:
            headers["Authorization"] = f"Bearer {self.remote_token}"

        query_params: dict[str, Any] = {
            "tail": self.params.tail,
        }
        if self.params.level:
            query_params["level"] = self.params.level
        if self.params.grep:
            query_params["grep"] = self.params.grep

        with httpx.Client(timeout=None) as client:
            with client.stream("GET", self.remote_url, headers=headers, params=query_params) as resp:
                if resp.status_code != 200:
                    try:
                        body = resp.read().decode("utf-8", errors="replace")[:500]
                    except Exception:
                        body = ""
                    raise RuntimeError(f"remote_sse_http_{resp.status_code}:{body}")

                self._emit_status("connected", detail="remote_windows_stream_connected")

                current_event = "message"
                data_lines: list[str] = []
                for raw_line in resp.iter_lines():
                    if self._stop:
                        break
                    line = raw_line if isinstance(raw_line, str) else (raw_line.decode("utf-8", errors="replace"))
                    if line.startswith(":"):
                        continue

                    # Support upstream streams that send plain newline-delimited log lines
                    # without strict SSE event/data framing.
                    if line and not line.startswith("event:") and not line.startswith("data:"):
                        entry = self._normalize_line_event(line)
                        if line_matches_filters(entry, level=self.params.level, grep=self.params.grep):
                            self._emit(entry, save_log=True)
                        continue

                    if line == "":
                        if data_lines:
                            data = "\n".join(data_lines)
                            if current_event in ("message", "log", "line"):
                                entry = self._normalize_line_event(data)
                                if line_matches_filters(entry, level=self.params.level, grep=self.params.grep):
                                    self._emit(entry, save_log=True)
                            elif current_event == "status":
                                try:
                                    parsed = json.loads(data)
                                    detail = str(parsed.get("detail", "")) if isinstance(parsed, dict) else ""
                                    state = str(parsed.get("state", "connected")) if isinstance(parsed, dict) else "connected"
                                except Exception:
                                    state = "connected"
                                    detail = str(data)
                                self._emit_status(state, detail=detail)
                            elif current_event == "error":
                                self._emit_error("remote_error", data)
                        current_event = "message"
                        data_lines = []
                        continue

                    if line.startswith("event:"):
                        current_event = line[len("event:") :].strip() or "message"
                    elif line.startswith("data:"):
                        data_piece = line[len("data:") :].lstrip()
                        if current_event in ("message", "log", "line"):
                            # Real-world forwarders sometimes emit one data frame per event
                            # without an empty separator line; emit immediately to avoid latency.
                            entry = self._normalize_line_event(data_piece)
                            if line_matches_filters(entry, level=self.params.level, grep=self.params.grep):
                                self._emit(entry, save_log=True)
                            current_event = "message"
                            data_lines = []
                        else:
                            data_lines.append(data_piece)

                # Flush final pending event if stream ended without trailing blank line.
                if data_lines:
                    data = "\n".join(data_lines)
                    if current_event in ("message", "log", "line"):
                        entry = self._normalize_line_event(data)
                        if line_matches_filters(entry, level=self.params.level, grep=self.params.grep):
                            self._emit(entry, save_log=True)

    def _run(self) -> None:
        backoff = 1.0
        max_backoff = 30.0
        while not self._stop:
            try:
                self._stream_once()
                if self._stop:
                    break
                self._emit_status("disconnected", detail="remote_stream_closed")
            except Exception as exc:
                self._emit_error("remote_stream_exception", str(exc), retry_in_seconds=backoff)
                self._emit_status("reconnecting", detail=f"retry_in={backoff:.1f}s")
                time.sleep(backoff)
                backoff = min(max_backoff, backoff * 2)
                continue
            backoff = 1.0
            self._emit_status("reconnecting", detail=f"retry_in={backoff:.1f}s")
            time.sleep(backoff)


class RemoteLogSourceRegistry:
    """Manages remote sources keyed by filter params for passthrough support."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sources: dict[tuple[int, str, str], RemoteLogSource] = {}

    def _build_source(self, params: StreamParams) -> RemoteLogSource:
        remote_url = os.getenv("OLLAMA_LOG_REMOTE_URL", DEFAULT_REMOTE_URL).strip()
        remote_token = os.getenv("OLLAMA_LOG_REMOTE_TOKEN", "").strip()
        source = RemoteLogSource(
            remote_url=remote_url,
            remote_token=remote_token,
            params=params,
            buffer_size=DEFAULT_BUFFER_SIZE,
        )
        source.start()
        return source

    def get_source(self, params: StreamParams) -> RemoteLogSource:
        key = (params.tail, params.level, params.grep)
        with self._lock:
            source = self._sources.get(key)
            if source is None:
                source = self._build_source(params)
                self._sources[key] = source
            return source


def get_remote_health_url(stream_url: str) -> str:
    parsed = urlparse(stream_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    return base + "/health"


def check_remote_health(url: str, token: str, timeout: float = 5.0) -> tuple[bool, str]:
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url, headers=headers)
        if resp.status_code == 200:
            return True, "ok"
        return False, f"http_{resp.status_code}:{resp.text[:200]}"
    except Exception as exc:
        return False, f"exception:{type(exc).__name__}:{exc}"


def role_allowed(role: str) -> bool:
    return (role or "").strip().lower() in ALLOWED_ROLES
