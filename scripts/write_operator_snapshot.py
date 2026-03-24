#!/usr/bin/env python3
"""Bundle latest operator artifacts into one snapshot directory.

This script copies current CSV/JSON status artifacts into:
- a rolling `latest` snapshot directory
- an optional timestamped history snapshot directory
"""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_FILES = [
    "docs/logs/latest_status.json",
    "docs/logs/template_regression_latest.json",
    "docs/logs/status_latest.csv",
    "docs/logs/status_meta_latest.csv",
    "docs/logs/trend_latest.csv",
    "docs/logs/trend_meta_latest.csv",
]


def copy_if_exists(src: Path, dst_dir: Path) -> bool:
    if not src.exists():
        return False
    dst_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst_dir / src.name)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Write operator snapshot bundle")
    parser.add_argument(
        "--latest-dir",
        default="docs/logs/operator_snapshot/latest",
        help="Directory for rolling latest snapshot bundle",
    )
    parser.add_argument(
        "--history-dir",
        default="docs/logs/operator_snapshot/history",
        help="Directory for timestamped snapshot bundles",
    )
    parser.add_argument(
        "--no-history",
        action="store_true",
        help="Skip timestamped history snapshot write",
    )
    args = parser.parse_args()

    latest_dir = Path(args.latest_dir)
    history_dir = Path(args.history_dir)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    history_snapshot_dir = history_dir / f"snapshot_{stamp}"

    included: list[str] = []
    missing: list[str] = []

    for rel in DEFAULT_FILES:
        src = Path(rel)
        if copy_if_exists(src, latest_dir):
            included.append(rel)
        else:
            missing.append(rel)

    if not args.no_history:
        for rel in included:
            src = Path(rel)
            copy_if_exists(src, history_snapshot_dir)

    manifest = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "included_files": included,
        "missing_files": missing,
        "latest_dir": str(latest_dir),
        "history_dir": str(history_dir),
        "history_written": not args.no_history,
        "history_snapshot_dir": str(history_snapshot_dir) if not args.no_history else None,
    }

    latest_dir.mkdir(parents=True, exist_ok=True)
    (latest_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    if not args.no_history:
        history_snapshot_dir.mkdir(parents=True, exist_ok=True)
        (history_snapshot_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )

    print("=== Operator Snapshot ===")
    print(f"latest_dir={latest_dir}")
    if not args.no_history:
        print(f"history_snapshot_dir={history_snapshot_dir}")
    print(f"included={len(included)}")
    print(f"missing={len(missing)}")
    if missing:
        print("missing_files:")
        for rel in missing:
            print(f"- {rel}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
