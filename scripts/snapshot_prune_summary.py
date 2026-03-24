#!/usr/bin/env python3
"""Snapshot prune_summary.json into a timestamped history file."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

SRC = Path("docs/logs/prune_summary.json")
DST_DIR = Path("docs/logs/prune_summary_history")


def main() -> int:
    if not SRC.exists():
        print(f"FAIL: source missing: {SRC}")
        return 1

    data = json.loads(SRC.read_text(encoding="utf-8"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = DST_DIR / f"prune_summary_{stamp}.json"

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "source": str(SRC),
        "summary": data,
    }

    DST_DIR.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"snapshot={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
