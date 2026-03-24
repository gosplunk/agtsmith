#!/usr/bin/env python3
"""Fail if environment profile is missing or stale."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def _parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Check environment profile freshness")
    parser.add_argument("--path", default="artifacts/environment/environment_profile_latest.json")
    parser.add_argument("--max-age-minutes", type=int, default=1440)
    args = parser.parse_args()

    p = Path(args.path)
    if not p.exists():
        print(f"FAIL: missing profile: {p}")
        return 1

    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"FAIL: profile read error: {type(exc).__name__}: {exc}")
        return 1

    ts = _parse_ts(str(payload.get("timestamp_utc", "")))
    if ts is None:
        print("FAIL: timestamp_utc missing/invalid")
        return 1

    age_min = (datetime.now(timezone.utc) - ts).total_seconds() / 60.0
    print(f"profile={p}")
    print(f"timestamp_utc={ts.isoformat()}")
    print(f"age_minutes={age_min:.2f}")
    print(f"max_age_minutes={args.max_age_minutes}")

    if age_min > args.max_age_minutes:
        print("FAIL: environment profile is stale")
        return 1

    print("PASS: environment profile freshness ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
