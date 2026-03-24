#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ollama_log_stream import StreamParams, line_matches_filters, redact_secrets


class TestOllamaLogStreamUnit(unittest.TestCase):
    def test_redact_bearer_and_token_assignments(self) -> None:
        raw = (
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890 "
            "token=super_secret_value_1234567890 api_key=my_api_key_value"
        )
        redacted = redact_secrets(raw)
        self.assertIn("Authorization: Bearer [REDACTED_BEARER]", redacted)
        self.assertIn("token=[REDACTED_TOKEN]", redacted)
        self.assertIn("api_key=[REDACTED_API_KEY]", redacted)
        self.assertNotIn("super_secret_value_1234567890", redacted)

    def test_level_and_grep_filter(self) -> None:
        entry = {
            "line": "2026-03-09 [ERROR] remote stream disconnected",
            "level": "error",
        }
        self.assertTrue(line_matches_filters(entry, level="error", grep="disconnected"))
        self.assertFalse(line_matches_filters(entry, level="warn", grep="disconnected"))
        self.assertFalse(line_matches_filters(entry, level="error", grep="connected_ok"))

    def test_stream_params_allows_zero_tail_for_live_only_mode(self) -> None:
        params = StreamParams.from_values("0", "", "")
        self.assertEqual(params.tail, 0)


if __name__ == "__main__":
    unittest.main()
