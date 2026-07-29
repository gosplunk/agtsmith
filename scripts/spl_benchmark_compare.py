#!/usr/bin/env python3
"""Compare SPL benchmark reports against a baseline manifest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _load_report(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"invalid_report:{path}")
    return payload


def _summary(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary", {})
    if isinstance(summary, dict) and summary:
        return summary
    results = report.get("results", [])
    scores: list[int] = []
    if isinstance(results, list):
        for row in results:
            if isinstance(row, dict):
                try:
                    scores.append(int(row.get("score", 0)))
                except Exception:
                    pass
    pass_rate = round((sum(1 for s in scores if s >= 85) / len(scores)) * 100, 2) if scores else 0.0
    return {
        "case_count": len(scores),
        "avg_score": round(sum(scores) / len(scores), 2) if scores else 0.0,
        "pass_rate_pct": pass_rate,
        "failing_case_count": sum(1 for s in scores if s < 85),
    }


def compare(*, baseline: Path, current: Path, min_pass_score: int = 85) -> dict[str, Any]:
    base_report = _load_report(baseline)
    cur_report = _load_report(current)
    base_summary = _summary(base_report)
    cur_summary = _summary(cur_report)

    base_results = {
        str(row.get("id", "")): row
        for row in base_report.get("results", [])
        if isinstance(row, dict) and str(row.get("id", "")).strip()
    }
    cur_results = {
        str(row.get("id", "")): row
        for row in cur_report.get("results", [])
        if isinstance(row, dict) and str(row.get("id", "")).strip()
    }

    regressions: list[dict[str, Any]] = []
    improvements: list[dict[str, Any]] = []
    for case_id, cur_row in cur_results.items():
        base_row = base_results.get(case_id)
        if not base_row:
            continue
        try:
            base_score = int(base_row.get("score", 0))
            cur_score = int(cur_row.get("score", 0))
        except Exception:
            continue
        delta = cur_score - base_score
        entry = {
            "id": case_id,
            "baseline_score": base_score,
            "current_score": cur_score,
            "delta": delta,
        }
        if cur_score < min_pass_score and base_score >= min_pass_score:
            regressions.append(entry)
        elif delta > 0:
            improvements.append(entry)
        elif delta < 0:
            regressions.append(entry)

    return {
        "baseline_report": str(baseline),
        "current_report": str(current),
        "baseline_summary": base_summary,
        "current_summary": cur_summary,
        "pass_rate_delta": round(
            float(cur_summary.get("pass_rate_pct", 0.0)) - float(base_summary.get("pass_rate_pct", 0.0)),
            2,
        ),
        "avg_score_delta": round(
            float(cur_summary.get("avg_score", 0.0)) - float(base_summary.get("avg_score", 0.0)),
            2,
        ),
        "regressions": regressions,
        "improvements": improvements,
        "ok": not regressions and float(cur_summary.get("pass_rate_pct", 0.0)) >= float(base_summary.get("pass_rate_pct", 0.0)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare SPL benchmark JSON against baseline")
    parser.add_argument("--baseline", default="artifacts/spl_autonomy/baseline/spl_hardening_benchmark_latest.json")
    parser.add_argument("--current", required=True)
    parser.add_argument("--min-pass-score", type=int, default=85)
    args = parser.parse_args()

    outcome = compare(
        baseline=Path(args.baseline),
        current=Path(args.current),
        min_pass_score=args.min_pass_score,
    )
    print(json.dumps(outcome, indent=2))
    return 0 if outcome.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
