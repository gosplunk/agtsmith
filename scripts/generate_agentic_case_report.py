#!/usr/bin/env python3
"""Generate a structured case report from latest or provided agentic run artifact."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _latest_agentic_file(run_dir: Path) -> Path | None:
    files = sorted(run_dir.glob("agentic_run_*.json"))
    return files[-1] if files else None


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _recommendations_from_trajectory(trajectory: list[dict[str, Any]]) -> list[str]:
    recs: list[str] = []
    if not trajectory:
        return ["Run an initial read-only investigation question to populate evidence."]

    last = trajectory[-1]
    tool = str(last.get("tool", ""))
    if tool == "splunk_run_query":
        recs.append("Refine the final SPL query with a narrower entity/time scope and rerun.")
        recs.append("Save the final query in runbook notes for repeat investigations.")
    elif tool == "splunk_get_metadata":
        recs.append("Pivot metadata output into an SPL query on top host/sourcetype for deeper evidence.")
    elif tool == "splunk_get_indexes":
        recs.append("Drill into the highest-volume index using sourcetype metadata next.")

    if not recs:
        recs.append("Review step evidence signals and run one focused follow-up query.")
    return recs[:3]


def build_report(run_payload: dict[str, Any], source_file: Path) -> dict[str, Any]:
    result = run_payload.get("result", {}) if isinstance(run_payload, dict) else {}
    trajectory = result.get("trajectory", []) if isinstance(result, dict) else []
    if not isinstance(trajectory, list):
        trajectory = []

    steps: list[dict[str, Any]] = []
    for item in trajectory:
        if not isinstance(item, dict):
            continue
        steps.append(
            {
                "step": item.get("step"),
                "tool": item.get("tool"),
                "reason": item.get("reason"),
                "rows_returned": item.get("rows_returned"),
                "total_rows": item.get("total_rows"),
                "confidence": item.get("confidence"),
                "evidence_signals": item.get("evidence_signals", []),
                "args": item.get("args", {}),
            }
        )

    confidence_values = [float(s.get("confidence")) for s in steps if isinstance(s.get("confidence"), (int, float))]
    avg_confidence = round(sum(confidence_values) / len(confidence_values), 2) if confidence_values else None

    report = {
        "report_version": "1.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_artifact": str(source_file),
        "question": result.get("question"),
        "supported": result.get("supported"),
        "done_reason": result.get("done_reason"),
        "steps_executed": result.get("steps_executed"),
        "average_confidence": avg_confidence,
        "summary": result.get("summary"),
        "summary_quality_reason": result.get("summary_quality_reason"),
        "summary_fallback_used": result.get("summary_fallback_used"),
        "investigation_steps": steps,
        "recommended_next_actions": _recommendations_from_trajectory(steps),
    }
    return report


def write_markdown(report: dict[str, Any], path: Path) -> None:
    steps = report.get("investigation_steps", [])
    lines = [
        "# Agentic SOC Case Report",
        "",
        f"- generated_at_utc: {report.get('generated_at_utc')}",
        f"- source_artifact: {report.get('source_artifact')}",
        f"- question: {report.get('question')}",
        f"- supported: {report.get('supported')}",
        f"- done_reason: {report.get('done_reason')}",
        f"- steps_executed: {report.get('steps_executed')}",
        f"- average_confidence: {report.get('average_confidence')}",
        "",
        "## Summary",
        "",
        str(report.get("summary", "")).strip(),
        "",
        "## Steps",
        "",
    ]

    for s in steps:
        lines.append(f"### Step {s.get('step')} - {s.get('tool')}")
        lines.append(f"- reason: {s.get('reason')}")
        lines.append(f"- rows_returned: {s.get('rows_returned')} total_rows={s.get('total_rows')}")
        lines.append(f"- confidence: {s.get('confidence')}")
        evidence = s.get("evidence_signals", [])
        if isinstance(evidence, list) and evidence:
            lines.append(f"- evidence_signals: {', '.join(str(e) for e in evidence)}")
        lines.append(f"- args: `{json.dumps(s.get('args', {}), sort_keys=True)}`")
        lines.append("")

    lines.append("## Recommended Next Actions")
    lines.append("")
    for item in report.get("recommended_next_actions", []):
        lines.append(f"- {item}")

    path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate agentic case report")
    parser.add_argument("--run-file", default="", help="Optional specific agentic_run_*.json file")
    parser.add_argument("--run-dir", default="docs/logs/agentic_runs")
    parser.add_argument("--json-out", default="docs/logs/agentic_case_report_latest.json")
    parser.add_argument("--md-out", default="docs/logs/agentic_case_report_latest.md")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    if args.run_file:
        run_file = Path(args.run_file)
    else:
        latest = _latest_agentic_file(run_dir)
        if latest is None:
            print("FAIL: no agentic run artifacts found")
            return 1
        run_file = latest

    if not run_file.exists():
        print(f"FAIL: run artifact not found: {run_file}")
        return 1

    payload = _read_json(run_file)
    report = build_report(payload, run_file)

    json_out = Path(args.json_out)
    md_out = Path(args.md_out)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    md_out.parent.mkdir(parents=True, exist_ok=True)

    json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report, md_out)

    print("=== Agentic Case Report ===")
    print(f"source={run_file}")
    print(f"json={json_out}")
    print(f"markdown={md_out}")
    print("status=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
