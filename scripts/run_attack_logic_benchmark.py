#!/usr/bin/env python3
"""Run an ATT&CK logic benchmark focused on question interpretation and MITRE mapping."""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from langgraph_multi_model_soc import planner_node, writer_node
from web_ui_server import _mitre_attack_bundle


@dataclass(frozen=True)
class AttackCase:
    id: str
    family: str
    question: str
    expected_intent: str
    expected_mitre_techniques: tuple[str, ...]
    min_mitre_pivots: int


def _load_cases(path: Path) -> list[AttackCase]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [
        AttackCase(
            id=str(row["id"]),
            family=str(row["family"]),
            question=str(row["question"]),
            expected_intent=str(row["expected_intent"]),
            expected_mitre_techniques=tuple(row.get("expected_mitre_techniques", [])),
            min_mitre_pivots=int(row.get("min_mitre_pivots", 0)),
        )
        for row in raw
    ]


def _score(case: AttackCase, actual_intent: str, mitre_bundle: dict[str, Any]) -> dict[str, Any]:
    score = 0
    findings: list[str] = []
    if actual_intent == case.expected_intent:
        score += 50
    else:
        findings.append(f"intent_mismatch:{actual_intent}->{case.expected_intent}")

    techniques = mitre_bundle.get("techniques", []) if isinstance(mitre_bundle.get("techniques"), list) else []
    technique_ids = [str(item.get("technique_id", "")).strip() for item in techniques if isinstance(item, dict)]
    if case.expected_mitre_techniques:
        hits = [item for item in case.expected_mitre_techniques if item in technique_ids]
        if hits:
            score += 35
        else:
            findings.append("mitre_mismatch:" + ",".join(case.expected_mitre_techniques))
    else:
        score += 35

    pivots = mitre_bundle.get("next_pivots", []) if isinstance(mitre_bundle.get("next_pivots"), list) else []
    if len(pivots) >= case.min_mitre_pivots:
        score += 15
    else:
        findings.append(f"mitre_pivots_below_expectation:{len(pivots)}<{case.min_mitre_pivots}")

    failure_class = "pass"
    if any(item.startswith("intent_mismatch:") for item in findings):
        failure_class = "intent_mismatch"
    elif any(item.startswith("mitre_mismatch:") for item in findings):
        failure_class = "mitre_mismatch"
    elif any(item.startswith("mitre_pivots_below_expectation:") for item in findings):
        failure_class = "mitre_pivots_gap"

    return {
        "score": max(0, min(100, score)),
        "findings": findings,
        "failure_class": failure_class,
        "mitre_techniques": technique_ids,
        "mitre_pivots": len(pivots),
    }


def _build_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ATT&CK Logic Benchmark",
        "",
        f"- Timestamp (UTC): `{report['timestamp_utc']}`",
        f"- Cases: `{report['case_count']}`",
        f"- Average score: `{report['summary']['avg_score']}`",
        f"- Pass rate (>=85): `{report['summary']['pass_rate_pct']}%`",
        "",
        "## Failure Classes",
    ]
    for key, value in report["summary"]["failure_classes"].items():
        lines.append(f"- `{key}`: `{value}`")
    lines.append("")
    lines.append("## Failing Cases")
    failing = [row for row in report["results"] if row["score"] < report["summary"]["min_pass_score"]]
    if not failing:
        lines.append("- none")
    else:
        for row in failing:
            lines.append(f"- `{row['id']}` score=`{row['score']}` findings=`{'; '.join(row['findings'])}`")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run ATT&CK logic benchmark")
    parser.add_argument("--cases", default="benchmarks/attack_logic_botsv3_pack.json")
    parser.add_argument("--out-dir", default="artifacts/benchmark_attack_logic")
    parser.add_argument("--case-limit", type=int, default=0)
    parser.add_argument("--min-pass-score", type=int, default=85)
    args = parser.parse_args()

    cases = _load_cases(Path(args.cases))
    if args.case_limit > 0:
        cases = cases[: args.case_limit]
    if not cases:
        raise SystemExit("no_cases_selected")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    history_dir = out_dir / "history"
    history_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    for idx, case in enumerate(cases, start=1):
        print(f"[attack-logic] {idx}/{len(cases)} case={case.id}")
        planner_state = planner_node({"question": case.question})
        writer_state = writer_node({"question": case.question, "planner_output": planner_state.get("planner_output", {})})
        writer_output = writer_state.get("writer_output", {}) if isinstance(writer_state.get("writer_output", {}), dict) else {}
        actual_intent = str(writer_output.get("intent", "")).strip() or "unknown"
        mitre_bundle = _mitre_attack_bundle({"intent": actual_intent, "summary": str(writer_output.get("reason", ""))})
        score = _score(case, actual_intent, mitre_bundle)
        results.append(
            {
                "id": case.id,
                "family": case.family,
                "question": case.question,
                "expected_intent": case.expected_intent,
                "actual_intent": actual_intent,
                **score,
            }
        )

    scores = [int(row["score"]) for row in results]
    failure_classes = Counter(row["failure_class"] for row in results if row["failure_class"] != "pass")
    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "case_count": len(results),
        "summary": {
            "avg_score": round(statistics.mean(scores), 2) if scores else 0.0,
            "pass_rate_pct": round((sum(1 for s in scores if s >= args.min_pass_score) / max(1, len(scores))) * 100, 2),
            "failure_classes": dict(sorted(failure_classes.items())),
            "min_pass_score": args.min_pass_score,
        },
        "results": results,
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_json = out_dir / f"attack_logic_benchmark_{stamp}.json"
    out_md = out_dir / f"attack_logic_benchmark_{stamp}.md"
    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    out_md.write_text(_build_markdown(report), encoding="utf-8")
    (out_dir / "attack_logic_benchmark_latest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out_dir / "attack_logic_benchmark_latest.md").write_text(_build_markdown(report), encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    print(f"json={out_json}")
    print(f"md={out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
