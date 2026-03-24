#!/usr/bin/env python3
"""Regression check for lightweight session memory helpers."""

from __future__ import annotations

from pathlib import Path

from langgraph_minimal_flow import load_session_context, persist_session_context


SESSION_ID = "memory_check_tmp"
BASE_DIR = "artifacts/sessions"


def main() -> int:
    print("=== Session Memory Check ===")

    initial = load_session_context(SESSION_ID, base_dir=BASE_DIR)
    if not isinstance(initial, dict):
        print("status=FAIL")
        print("reason=initial_context_not_dict")
        return 1

    out = persist_session_context(
        SESSION_ID,
        question="Check session memory write path",
        selected_tool="splunk_get_info",
        summary="summary preview",
        rows_returned=1,
        base_dir=BASE_DIR,
    )
    if out is None:
        print("status=FAIL")
        print("reason=missing_session_output_path")
        return 1

    path = Path(out)
    if not path.exists():
        print("status=FAIL")
        print(f"reason=session_file_not_found path={path}")
        return 1

    loaded = load_session_context(SESSION_ID, base_dir=BASE_DIR)
    questions = loaded.get("recent_questions", []) if isinstance(loaded, dict) else []
    tools = loaded.get("recent_tools", []) if isinstance(loaded, dict) else []

    if "Check session memory write path" not in questions:
        print("status=FAIL")
        print("reason=question_not_persisted")
        return 1
    if "splunk_get_info" not in tools:
        print("status=FAIL")
        print("reason=tool_not_persisted")
        return 1

    print("status=PASS")
    print(f"session_file={path}")
    print(f"questions_count={len(questions)} tools_count={len(tools)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
