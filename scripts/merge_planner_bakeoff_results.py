#!/usr/bin/env python3
"""Merge planner bake-off snapshots into final ranked artifacts."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "artifacts/model_eval/planner_bakeoff"


def _ts(row_source: dict[str, Any]) -> str:
    return str(row_source.get("timestamp_utc", ""))


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _rank_key(row: dict[str, Any]) -> tuple:
    return (
        -float(row.get("avg_score", 0)),
        -float(row.get("intent_match_rate_pct", 0)),
        int(row.get("median_duration_ms", 0)),
    )


def _vram(path: Path) -> dict[str, str]:
    p = path / "vram_smoke_planner_candidates.json"
    if not p.exists():
        return {}
    try:
        rows = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out: dict[str, str] = {}
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict) and row.get("model"):
            if row.get("gpu_fit"):
                out[str(row["model"])] = str(row["gpu_fit"])
    return out


def merge(
    *,
    prior_five_path: Path,
    granite4_path: Path,
    new_run_path: Path,
    out_dir: Path,
    merged_base_path: Path | None = None,
) -> dict[str, Any]:
    by_model: dict[str, tuple[str, dict[str, Any]]] = {}

    def ingest(payload: dict[str, Any]) -> None:
        ts = _ts(payload)
        for row in payload.get("ranked", []):
            if not isinstance(row, dict):
                continue
            model = str(row.get("model", "")).strip()
            if not model:
                continue
            prev = by_model.get(model)
            if prev is None or ts > prev[0]:
                by_model[model] = (ts, row)

    if merged_base_path and merged_base_path.exists():
        ingest(_load(merged_base_path))
    else:
        ingest(_load(prior_five_path))
    g4 = _load(granite4_path)
    ts_g4 = _ts(g4)
    for row in g4.get("ranked", []):
        if str(row.get("model", "")).strip() == "granite4:3b":
            prev = by_model.get("granite4:3b")
            if prev is None or ts_g4 > prev[0]:
                by_model["granite4:3b"] = (ts_g4, row)
            break
    ingest(_load(new_run_path))

    ranked = [pair[1] for pair in sorted(by_model.values(), key=lambda p: _rank_key(p[1]))]
    vram = _vram(out_dir)
    for row in ranked:
        m = str(row.get("model", ""))
        if m in vram:
            row["gpu_fit"] = vram[m]

    # Promote threshold vs granite3-moe:3b baseline
    baseline = by_model.get("granite3-moe:3b", (None, {}))[1]
    b_avg = float(baseline.get("avg_score", 0)) if baseline else 0
    b_intent = float(baseline.get("intent_match_rate_pct", 0)) if baseline else 0

    def meets_threshold(row: dict[str, Any]) -> bool:
        return (
            float(row.get("avg_score", 0)) >= 59
            and float(row.get("intent_match_rate_pct", 0)) >= 98
            and int(row.get("median_duration_ms", 999999)) <= 15000
        )

    best = ranked[0]["model"] if ranked else ""
    best_row = ranked[0] if ranked else {}
    us_eu: list[dict[str, Any]] = []
    cn: list[dict[str, Any]] = []
    for row in ranked:
        origin = str(row.get("origin", "")).lower()
        if "cn" in origin or "alibaba" in origin or "deepseek" in origin:
            cn.append(row)
        else:
            us_eu.append(row)
    best_intent = max(float(r.get("intent_match_rate_pct", 0)) for r in ranked) if ranked else 0
    recommended = best
    for row in us_eu:
        if meets_threshold(row):
            if float(row.get("intent_match_rate_pct", 0)) >= best_intent - 5:
                recommended = str(row["model"])
                break

    if not meets_threshold(best_row) and not any(meets_threshold(r) for r in ranked):
        recommended = str(baseline.get("model", "granite3-moe:3b")) if baseline else best

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "cases_path": _load(new_run_path).get("cases_path", "benchmarks/spl_cases.json"),
        "case_count": _load(new_run_path).get("case_count", 66),
        "merge_sources": {
            "merged_base": str(merged_base_path) if merged_base_path and merged_base_path.exists() else None,
            "prior_five": str(prior_five_path),
            "granite4_3b": str(granite4_path),
            "new_run": str(new_run_path),
        },
        "promotion_threshold": {"avg_score_min": 59, "intent_match_pct_min": 98, "median_ms_max": 15000},
        "baseline_granite3_moe_3b": {
            "avg_score": b_avg,
            "intent_match_rate_pct": b_intent,
            "median_duration_ms": baseline.get("median_duration_ms") if baseline else None,
        },
        "recommended_planner": recommended,
        "ranked": ranked,
    }
    return payload


def write_md(payload: dict[str, Any], path: Path, vram: dict[str, str]) -> None:
    lines = [
        "# Planner Model Evaluation (planner_node only)",
        "",
        f"- Timestamp (UTC): `{payload['timestamp_utc']}`",
        f"- Cases: `{payload['case_count']}`",
        f"- Recommended planner: `{payload.get('recommended_planner', '')}`",
        f"- Merged bake-off ({len(payload.get('ranked', []))} models)",
        "",
        "| Rank | Model | Origin | Avg | Intent match | Median ms | GPU fit |",
        "|------|-------|--------|-----|--------------|-----------|---------|",
    ]
    for i, row in enumerate(payload.get("ranked", []), 1):
        model = str(row.get("model", ""))
        lines.append(
            f"| {i} | `{model}` | {row.get('origin', '?')} | {row.get('avg_score', 0)} | "
            f"{row.get('intent_match_rate_pct', 0)}% | {row.get('median_duration_ms', 0)} | "
            f"{vram.get(model, row.get('gpu_fit', '—'))} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    prior = OUT / "planner_eval_prior5_backup.json"
    g4 = OUT / "planner_eval_20260722T153400Z.json"
    new_run = OUT / "planner_eval_latest.json"
    for p in (prior, g4, new_run):
        if not p.exists():
            print(f"missing: {p}", file=sys.stderr)
            return 1
    merged_base = OUT / "planner_eval_merged_base.json"
    payload = merge(
        prior_five_path=prior,
        granite4_path=g4,
        new_run_path=new_run,
        out_dir=OUT,
        merged_base_path=merged_base if merged_base.exists() else None,
    )
    vram = _vram(OUT)
    (OUT / "planner_eval_latest.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    write_md(payload, OUT / "planner_eval_latest.md", vram)
    write_md(payload, OUT / "planner_comparison.md", vram)
    print(json.dumps({"recommended_planner": payload["recommended_planner"], "model_count": len(payload["ranked"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
