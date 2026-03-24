#!/usr/bin/env python3
"""Prune old lab artifacts with dry-run support.

Default behavior is dry-run (no deletions).
Use --apply to perform deletions.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import shutil


@dataclass
class PruneTarget:
    name: str
    base_dir: Path
    pattern: str
    keep: int
    kind: str  # file or dir


def collect_candidates(target: PruneTarget) -> list[Path]:
    if not target.base_dir.exists():
        return []
    items = sorted(target.base_dir.glob(target.pattern))
    if target.kind == "file":
        items = [p for p in items if p.is_file()]
    else:
        items = [p for p in items if p.is_dir()]
    if len(items) <= target.keep:
        return []
    return items[: len(items) - target.keep]


def delete_path(path: Path, kind: str) -> None:
    if kind == "file":
        path.unlink(missing_ok=True)
    else:
        shutil.rmtree(path, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Prune old artifact files/directories")
    parser.add_argument("--keep-regression", type=int, default=100, help="Keep latest N regression history files")
    parser.add_argument("--keep-snapshots", type=int, default=50, help="Keep latest N operator snapshot directories")
    parser.add_argument("--keep-langgraph", type=int, default=200, help="Keep latest N LangGraph run files")
    parser.add_argument("--apply", action="store_true", help="Apply deletions (default is dry-run)")
    args = parser.parse_args()

    targets = [
        PruneTarget(
            name="template_regression_history",
            base_dir=Path("docs/logs/template_regression_history"),
            pattern="template_regression_*.json",
            keep=args.keep_regression,
            kind="file",
        ),
        PruneTarget(
            name="operator_snapshot_history",
            base_dir=Path("docs/logs/operator_snapshot/history"),
            pattern="snapshot_*",
            keep=args.keep_snapshots,
            kind="dir",
        ),
        PruneTarget(
            name="langgraph_runs",
            base_dir=Path("docs/logs/langgraph_runs"),
            pattern="langgraph_run_*.json",
            keep=args.keep_langgraph,
            kind="file",
        ),
    ]

    mode = "APPLY" if args.apply else "DRY-RUN"
    print("=== Artifact Prune ===")
    print(f"mode={mode}")

    total_candidates = 0
    for t in targets:
        candidates = collect_candidates(t)
        total_candidates += len(candidates)
        print(f"\n[{t.name}] keep={t.keep} candidates={len(candidates)}")
        for p in candidates:
            print(f"- {p}")
        if args.apply:
            for p in candidates:
                delete_path(p, t.kind)

    print(f"\ntotal_candidates={total_candidates}")
    if not args.apply:
        print("No deletions performed (dry-run). Use --apply to delete.")
    else:
        print("Deletions applied.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
