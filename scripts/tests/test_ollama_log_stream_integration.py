#!/usr/bin/env python3

from __future__ import annotations

import queue
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ollama_log_stream
from ollama_log_stream import RemoteLogSource, StreamParams, format_sse


class _FakeReconnectSource(RemoteLogSource):
    """Deterministic source for reconnect behavior tests."""

    def __init__(self) -> None:
        super().__init__(
            remote_url="http://fake/stream",
            remote_token="fake",
            params=StreamParams(tail=5, level="", grep=""),
            buffer_size=5000,
        )
        self.calls = 0

    def _stream_once(self) -> None:  # type: ignore[override]
        self.calls += 1
        self._emit_status("connected", detail=f"call_{self.calls}")
        self._emit(
            {
                "type": "log",
                "line": f"synthetic line {self.calls}",
                "level": "info",
                "ts": f"t{self.calls}",
            },
            save_log=True,
        )
        if self.calls == 1:
            raise RuntimeError("synthetic_disconnect")
        # Stop after second successful emit to end test quickly.
        self._stop = True


class TestOllamaLogStreamIntegration(unittest.TestCase):
    def test_sse_framing_helper(self) -> None:
        blob = format_sse("status", {"state": "connected"}).decode("utf-8")
        self.assertIn("event: status", blob)
        self.assertIn("data: {\"state\": \"connected\"}", blob)
        self.assertTrue(blob.endswith("\n\n"))

    def test_reconnect_behavior_and_buffer_growth(self) -> None:
        src = _FakeReconnectSource()
        sid, sub_q = src.subscribe()
        src.start()

        saw_connected = False
        saw_reconnecting = False
        saw_log = False
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                event = sub_q.get(timeout=0.5)
            except queue.Empty:
                continue
            et = event.get("type")
            if et == "status" and event.get("state") == "connected":
                saw_connected = True
            if et == "status" and event.get("state") == "reconnecting":
                saw_reconnecting = True
            if et == "log" and "synthetic line" in str(event.get("line", "")):
                saw_log = True
            if saw_connected and saw_reconnecting and saw_log and len(src.get_recent(10)) >= 2:
                break

        src.unsubscribe(sid)

        self.assertTrue(saw_connected)
        self.assertTrue(saw_reconnecting)
        self.assertTrue(saw_log)
        self.assertGreaterEqual(len(src.get_recent(10)), 2)

    def test_data_frames_without_blank_line_emit_immediately(self) -> None:
        class _FakeResp:
            status_code = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def iter_lines(self):
                yield "event: log"
                yield 'data: {"line":"first","level":"info","ts":"t1"}'
                yield 'data: {"line":"second","level":"info","ts":"t2"}'

        class _FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def stream(self, method, url, headers=None, params=None):
                return _FakeResp()

        original_client = ollama_log_stream.httpx.Client
        ollama_log_stream.httpx.Client = _FakeClient  # type: ignore[assignment]
        try:
            src = RemoteLogSource(
                remote_url="http://fake/stream",
                remote_token="fake",
                params=StreamParams(tail=5, level="", grep=""),
                buffer_size=5000,
            )
            sid, sub_q = src.subscribe()
            src._stream_once()

            seen = []
            while True:
                try:
                    evt = sub_q.get_nowait()
                except queue.Empty:
                    break
                if evt.get("type") == "log":
                    seen.append(str(evt.get("line", "")))
            src.unsubscribe(sid)
        finally:
            ollama_log_stream.httpx.Client = original_client  # type: ignore[assignment]

        self.assertIn("first", seen)
        self.assertIn("second", seen)
        self.assertGreaterEqual(len(seen), 2)


if __name__ == "__main__":
    unittest.main()
