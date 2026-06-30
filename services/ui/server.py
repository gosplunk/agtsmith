#!/usr/bin/env python3
"""Thin entrypoint for the agtsmith UI service (wraps scripts/web_ui_server.py)."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

if __name__ == "__main__":
    runpy.run_path(str(SCRIPTS / "web_ui_server.py"), run_name="__main__")
