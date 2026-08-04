#!/usr/bin/env python3
"""Tests for MCP token ensure/refresh behavior."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lab_data.refresh_mcp_token import ensure_mcp_token


class RefreshMcpTokenTests(unittest.TestCase):
    def test_reuses_valid_existing_token_without_rotate(self) -> None:
        token = "x" * 120
        with tempfile.TemporaryDirectory() as tmp:
            ui_env = Path(tmp) / "ui.env"
            ui_env.write_text(
                "\n".join(
                    [
                        "SPLUNK_USER=dev",
                        "SPLUNK_PASS=test-only-placeholder",
                        f"SPLUNK_LAB_BEARER_TOKEN={token}",
                        "SPLUNK_MCP_URL=https://127.0.0.1:8089/services/mcp",
                    ]
                ),
                encoding="utf-8",
            )
            with mock.patch("lab_data.refresh_mcp_token.verify_mcp_token") as verify:
                with mock.patch("lab_data.refresh_mcp_token.rotate_mcp_token") as rotate:
                    out, action = ensure_mcp_token(ui_env_path=ui_env, token_user="mcp")
            self.assertEqual(out, token)
            self.assertEqual(action, "reused")
            verify.assert_called_once()
            rotate.assert_not_called()

    def test_rotates_only_when_existing_token_invalid(self) -> None:
        old = "a" * 120
        new = "b" * 120
        with tempfile.TemporaryDirectory() as tmp:
            ui_env = Path(tmp) / "ui.env"
            ui_env.write_text(
                "\n".join(
                    [
                        "SPLUNK_USER=dev",
                        "SPLUNK_PASS=test-only-placeholder",
                        f"SPLUNK_LAB_BEARER_TOKEN={old}",
                        "SPLUNK_MCP_URL=https://127.0.0.1:8089/services/mcp",
                    ]
                ),
                encoding="utf-8",
            )

            def _verify(tok: str, *, ui_env: dict) -> None:
                if tok == old:
                    raise RuntimeError("invalid")

            with mock.patch("lab_data.refresh_mcp_token.verify_mcp_token", side_effect=_verify):
                with mock.patch("lab_data.refresh_mcp_token.fetch_mcp_token", side_effect=RuntimeError("fetch fail")):
                    with mock.patch("lab_data.refresh_mcp_token.rotate_mcp_token", return_value=new) as rotate:
                        out, action = ensure_mcp_token(ui_env_path=ui_env, token_user="mcp")
            self.assertEqual(out, new)
            self.assertEqual(action, "rotated")
            rotate.assert_called_once()
            saved = ui_env.read_text(encoding="utf-8")
            self.assertIn(new, saved)
            self.assertNotIn(old, saved)


if __name__ == "__main__":
    unittest.main()
