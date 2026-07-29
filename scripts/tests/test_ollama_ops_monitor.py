#!/usr/bin/env python3

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ollama_ops_monitor import (  # noqa: E402
    build_local_log_command,
    ollama_log_config_status,
    query_nvidia_smi,
    resolve_log_source_mode,
)


class TestOllamaOpsMonitor(unittest.TestCase):
    def test_resolve_log_source_mode_prefers_explicit(self) -> None:
        with patch.dict("os.environ", {"OLLAMA_LOG_SOURCE": "remote_windows"}, clear=False):
            self.assertEqual(resolve_log_source_mode(), "remote_windows")

    def test_resolve_log_source_mode_uses_local_command(self) -> None:
        with patch.dict(
            "os.environ",
            {"OLLAMA_LOG_SOURCE": "", "OLLAMA_LOG_LOCAL_CMD": "journalctl -u ollama -f"},
            clear=False,
        ):
            self.assertEqual(resolve_log_source_mode(), "local_command")

    def test_build_local_log_command_systemd(self) -> None:
        with patch.dict("os.environ", {"OLLAMA_LOG_SYSTEMD_UNIT": "ollama.service"}, clear=False):
            cmd = build_local_log_command("local_systemd")
        self.assertEqual(cmd[0], "journalctl")
        self.assertIn("ollama.service", cmd)

    def test_ollama_log_config_status_local_systemd(self) -> None:
        with patch("ollama_ops_monitor.resolve_log_source_mode", return_value="local_systemd"):
            status = ollama_log_config_status()
        self.assertEqual(status["mode"], "local_systemd")
        self.assertTrue(status["config_ok"])

    def test_query_nvidia_smi_parses_csv(self) -> None:
        fake_stdout = "0, NVIDIA RTX 1000 Ada, 512, 6141, 5629, 12, 8, 44, 15.00\n"
        with patch("ollama_ops_monitor._run_command", return_value=(0, fake_stdout, "")):
            payload = query_nvidia_smi()
        self.assertTrue(payload["available"])
        self.assertEqual(payload["gpus"][0]["name"], "NVIDIA RTX 1000 Ada")
        self.assertEqual(payload["gpus"][0]["memory_total_mib"], 6141.0)


if __name__ == "__main__":
    unittest.main()
