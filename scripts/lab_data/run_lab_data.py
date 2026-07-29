#!/usr/bin/env python3
"""Run lab-data subprocesses with config/ui.env loaded and stale env vars cleared."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_UI_ENV = PROJECT_ROOT / "config" / "ui.env"

# Parent-shell exports must not override gitignored ui.env (MCP tokens contain '=').
STRIP_ENV_KEYS = (
    "SPLUNK_LAB_BEARER_TOKEN",
    "SPLUNK_USER",
    "SPLUNK_PASS",
    "SPLUNK_PASSWORD",
    "SPLUNK_HEC_TOKEN",
    "SPLUNK_HEC_URL",
)


def _load_ui_env(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def build_env(ui_env_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    for key in STRIP_ENV_KEYS:
        env.pop(key, None)
    env.update(_load_ui_env(ui_env_path))
    env["PYTHONPATH"] = f"{PROJECT_ROOT}:{PROJECT_ROOT / 'scripts'}"
    return env


def main() -> int:
    parser = argparse.ArgumentParser(description="Run command with lab-data env hygiene")
    parser.add_argument("--ui-env", default=str(DEFAULT_UI_ENV))
    parser.add_argument("cmd", nargs=argparse.REMAINDER, help="Command after --")
    args = parser.parse_args()
    cmd = args.cmd
    if cmd[:1] == ["--"]:
        cmd = cmd[1:]
    if not cmd:
        print("ERROR: missing command", file=sys.stderr)
        return 2
    env = build_env(Path(args.ui_env))
    completed = subprocess.run(cmd, env=env, cwd=str(PROJECT_ROOT), check=False)
    return int(completed.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
