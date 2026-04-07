#!/usr/bin/env python3
"""Case persistence for investigations and pivots."""

from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS_ROOT = PROJECT_ROOT / "artifacts"
CASE_ROOT = ARTIFACTS_ROOT / "cases"
SQLITE_CASE_DB_PATH = CASE_ROOT / "case_store.sqlite3"
PG_MIGRATION_MARKER = CASE_ROOT / ".postgres_migration_complete"
CASE_STORE_LOCK = threading.Lock()


def _safe_json_dict(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        loaded = json.loads(str(raw))
    except Exception:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _summary_confidence(summary: str) -> float | None:
    raw = str(summary or "").strip()
    if not raw:
        return None
    match = re.search(r"Final confidence:\s*([0-9]+(?:\.[0-9]+)?)", raw, re.IGNORECASE)
    if not match:
        return None
    try:
        return float(match.group(1))
    except Exception:
        return None


def _float_or_none(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def _extract_confidence(result: dict[str, Any], graph_state: dict[str, Any], summary: str) -> float | None:
    for candidate in (
        _summary_confidence(summary),
        _float_or_none(result.get("confidence")),
        _float_or_none(result.get("final_confidence")),
        _float_or_none((((result.get("planner") or {}).get("output") or {}).get("confidence"))),
        _float_or_none((((result.get("evidence") or {}).get("quality") or {}).get("confidence"))),
        _float_or_none((((result.get("mitre_attack") or {}).get("validation") or {}).get("confidence"))),
        _float_or_none(graph_state.get("confidence")),
    ):
        if candidate is not None:
            return round(candidate, 2)
    return None


def _extract_time_range(result: dict[str, Any], graph_state: dict[str, Any]) -> dict[str, str]:
    query_args = result.get("query_args") if isinstance(result.get("query_args"), dict) else {}
    state_time = graph_state.get("time_range") if isinstance(graph_state.get("time_range"), dict) else {}
    earliest = str(query_args.get("earliest_time") or query_args.get("earliest") or state_time.get("earliest") or "").strip()
    latest = str(query_args.get("latest_time") or query_args.get("latest") or state_time.get("latest") or "").strip()
    return {"earliest": earliest, "latest": latest}


def _extract_query(result: dict[str, Any], graph_state: dict[str, Any]) -> str:
    query_args = result.get("query_args") if isinstance(result.get("query_args"), dict) else {}
    if str(query_args.get("query") or "").strip():
        return str(query_args.get("query") or "").strip()
    state_args = graph_state.get("query_args") if isinstance(graph_state.get("query_args"), dict) else {}
    if str(state_args.get("query") or "").strip():
        return str(state_args.get("query") or "").strip()
    selected = graph_state.get("selected_spl_details")
    if isinstance(selected, list):
        for item in selected:
            if isinstance(item, dict) and str(item.get("query") or "").strip():
                return str(item.get("query") or "").strip()
    return ""


def _normalize_entity_list(values: Any, limit: int = 6) -> list[str]:
    if not isinstance(values, list):
        return []
    out: list[str] = []
    for value in values:
        raw = str(value or "").strip()
        if raw and raw not in out:
            out.append(raw)
        if len(out) >= limit:
            break
    return out


def _normalize_ranked_entities(values: Any, limit: int = 4) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        return []
    out: list[dict[str, Any]] = []
    for item in values:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "").strip()
        if not value:
            continue
        out.append({"value": value, "count": int(item.get("count") or 0)})
        if len(out) >= limit:
            break
    return out


def _extract_entities(graph_state: dict[str, Any]) -> dict[str, list[str]]:
    raw = graph_state.get("evidence_entities") if isinstance(graph_state.get("evidence_entities"), dict) else {}
    return {
        "hosts": _normalize_entity_list(raw.get("hosts")),
        "users": _normalize_entity_list(raw.get("users")),
        "source_ips": _normalize_entity_list(raw.get("source_ips")),
        "client_ips": _normalize_entity_list(raw.get("client_ips")),
        "ports": _normalize_entity_list(raw.get("ports")),
        "event_names": _normalize_entity_list(raw.get("event_names")),
        "services": _normalize_entity_list(raw.get("services")),
        "uri_paths": _normalize_entity_list(raw.get("uri_paths")),
        "user_agents": _normalize_entity_list(raw.get("user_agents")),
    }


def _extract_ranked_entities(graph_state: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    raw = graph_state.get("ranked_entities") if isinstance(graph_state.get("ranked_entities"), dict) else {}
    return {
        "hosts": _normalize_ranked_entities(raw.get("hosts")),
        "users": _normalize_ranked_entities(raw.get("users")),
        "source_ips": _normalize_ranked_entities(raw.get("source_ips")),
        "client_ips": _normalize_ranked_entities(raw.get("client_ips")),
        "event_names": _normalize_ranked_entities(raw.get("event_names")),
        "services": _normalize_ranked_entities(raw.get("services")),
    }


def _extract_pivot_candidates(graph_state: dict[str, Any]) -> list[dict[str, Any]]:
    raw = graph_state.get("pivot_candidates")
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw[:4]:
        if not isinstance(item, dict):
            continue
        out.append(
            {
                "id": str(item.get("id") or "").strip(),
                "title": str(item.get("title") or item.get("next_question") or "").strip(),
                "target_type": str(item.get("target_type") or "").strip(),
                "target_label": str(item.get("target_label") or "").strip(),
                "target_values": _normalize_entity_list(item.get("target_values"), limit=4),
                "pivot_kind": str(item.get("pivot_kind") or "").strip(),
                "query_args": item.get("query_args") if isinstance(item.get("query_args"), dict) else None,
                "next_question": str(item.get("next_question") or "").strip(),
                "provenance": item.get("provenance") if isinstance(item.get("provenance"), dict) else {},
            }
        )
    return out


def _extract_pivot_source(result: dict[str, Any]) -> dict[str, Any]:
    raw = result.get("pivot_source") if isinstance(result.get("pivot_source"), dict) else {}
    candidate = raw.get("candidate") if isinstance(raw.get("candidate"), dict) else {}
    if not candidate:
        return {}
    return {
        "kind": str(raw.get("kind") or "").strip(),
        "title": str(candidate.get("title") or "").strip(),
        "target_type": str(candidate.get("target_type") or "").strip(),
        "target_label": str(candidate.get("target_label") or "").strip(),
        "target_values": _normalize_entity_list(candidate.get("target_values"), limit=4),
        "next_question": str(candidate.get("next_question") or "").strip(),
        "provenance": candidate.get("provenance") if isinstance(candidate.get("provenance"), dict) else {},
    }


def _extract_mitre_preview(result: dict[str, Any]) -> list[str]:
    raw = (result.get("mitre_attack") or {}).get("techniques")
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw[:3]:
        if not isinstance(item, dict):
            continue
        tid = str(item.get("technique_id") or "").strip()
        tech = str(item.get("technique") or "").strip()
        tactic = str(item.get("tactic") or "").strip()
        label = " / ".join(part for part in (tactic, tech, tid) if part)
        if label:
            out.append(label)
    return out


def _extract_state_preview(graph_state: dict[str, Any]) -> dict[str, Any]:
    return {
        "matching_active_spl_assets": len(graph_state.get("matching_active_spl_assets") or []) if isinstance(graph_state.get("matching_active_spl_assets"), list) else 0,
        "pivot_candidate_count": len(graph_state.get("pivot_candidates") or []) if isinstance(graph_state.get("pivot_candidates"), list) else 0,
        "rows_returned": int(graph_state.get("rows_returned") or 0),
    }


def case_store_backend() -> str:
    if str(os.getenv("AGTSMITH_CASE_DB_DSN", "")).strip() or str(os.getenv("AGTSMITH_CASE_DB_HOST", "")).strip():
        return "postgres"
    return "sqlite"


def _postgres_dsn() -> str:
    explicit = str(os.getenv("AGTSMITH_CASE_DB_DSN", "")).strip()
    if explicit:
        return explicit
    host = str(os.getenv("AGTSMITH_CASE_DB_HOST", "localhost")).strip()
    port = str(os.getenv("AGTSMITH_CASE_DB_PORT", "5432")).strip()
    name = str(os.getenv("AGTSMITH_CASE_DB_NAME", "agtsmith")).strip()
    user = str(os.getenv("AGTSMITH_CASE_DB_USER", "agtsmith")).strip()
    password = str(os.getenv("AGTSMITH_CASE_DB_PASSWORD", "")).strip()
    return f"host={host} port={port} dbname={name} user={user} password={password}"


def _sqlite_connect() -> sqlite3.Connection:
    CASE_ROOT.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(SQLITE_CASE_DB_PATH))
    conn.row_factory = sqlite3.Row
    _ensure_sqlite_schema(conn)
    return conn


def _ensure_sqlite_schema(conn: sqlite3.Connection) -> None:
    with CASE_STORE_LOCK:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                session_id TEXT,
                root_question TEXT,
                status TEXT,
                created_at INTEGER,
                updated_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS case_nodes (
                node_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                parent_node_id TEXT,
                node_type TEXT,
                question TEXT,
                title TEXT,
                intent TEXT,
                supported INTEGER,
                row_count INTEGER,
                created_at INTEGER,
                summary TEXT,
                result_json TEXT NOT NULL,
                graph_state_json TEXT,
                FOREIGN KEY(case_id) REFERENCES cases(case_id)
            );
            CREATE INDEX IF NOT EXISTS idx_case_nodes_case_created ON case_nodes(case_id, created_at);
            """
        )
        try:
            conn.execute("ALTER TABLE case_nodes ADD COLUMN graph_state_json TEXT")
        except Exception:
            pass
        conn.commit()


def _postgres_connect():
    import psycopg  # lazy import so local py_compile/tests don't require the driver

    CASE_ROOT.mkdir(parents=True, exist_ok=True)
    conn = psycopg.connect(_postgres_dsn())
    _ensure_postgres_schema(conn)
    _migrate_sqlite_to_postgres_if_needed(conn)
    return conn


def _ensure_postgres_schema(conn) -> None:
    with CASE_STORE_LOCK:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    session_id TEXT,
                    root_question TEXT,
                    status TEXT,
                    created_at BIGINT,
                    updated_at BIGINT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS case_nodes (
                    node_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    parent_node_id TEXT,
                    node_type TEXT,
                    question TEXT,
                    title TEXT,
                    intent TEXT,
                    supported BOOLEAN,
                    row_count INTEGER,
                    created_at BIGINT,
                    summary TEXT,
                    result_json TEXT NOT NULL,
                    graph_state_json TEXT
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_case_nodes_case_created ON case_nodes(case_id, created_at)")
        conn.commit()


def _migrate_sqlite_to_postgres_if_needed(conn) -> None:
    if PG_MIGRATION_MARKER.exists():
        return
    if not SQLITE_CASE_DB_PATH.exists():
        PG_MIGRATION_MARKER.write_text("no_sqlite_source\n", encoding="utf-8")
        return
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM cases")
        count = int(cur.fetchone()[0] or 0)
    if count > 0:
        PG_MIGRATION_MARKER.write_text("postgres_not_empty\n", encoding="utf-8")
        return
    sqlite_conn = _sqlite_connect()
    try:
        case_rows = sqlite_conn.execute("SELECT case_id, session_id, root_question, status, created_at, updated_at FROM cases").fetchall()
        node_rows = sqlite_conn.execute(
            """
            SELECT node_id, case_id, parent_node_id, node_type, question, title, intent, supported, row_count, created_at, summary, result_json,
                   COALESCE(graph_state_json, NULL) AS graph_state_json
            FROM case_nodes
            """
        ).fetchall()
    finally:
        sqlite_conn.close()
    with CASE_STORE_LOCK:
        with conn.cursor() as cur:
            for row in case_rows:
                cur.execute(
                    """
                    INSERT INTO cases(case_id, session_id, root_question, status, created_at, updated_at)
                    VALUES(%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (case_id) DO NOTHING
                    """,
                    (
                        row["case_id"],
                        row["session_id"],
                        row["root_question"],
                        row["status"],
                        row["created_at"],
                        row["updated_at"],
                    ),
                )
            for row in node_rows:
                cur.execute(
                    """
                    INSERT INTO case_nodes(
                        node_id, case_id, parent_node_id, node_type, question, title, intent, supported, row_count, created_at, summary, result_json, graph_state_json
                    ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (node_id) DO NOTHING
                    """,
                    (
                        row["node_id"],
                        row["case_id"],
                        row["parent_node_id"],
                        row["node_type"],
                        row["question"],
                        row["title"],
                        row["intent"],
                        bool(row["supported"]),
                        row["row_count"],
                        row["created_at"],
                        row["summary"],
                        row["result_json"],
                        row["graph_state_json"],
                    ),
                )
        conn.commit()
    PG_MIGRATION_MARKER.write_text("sqlite_imported\n", encoding="utf-8")


def _connect():
    return _postgres_connect() if case_store_backend() == "postgres" else _sqlite_connect()


def new_case_id() -> str:
    return f"case_{int(time.time())}_{secrets.token_hex(4)}"


def new_node_id() -> str:
    return f"node_{int(time.time())}_{secrets.token_hex(4)}"


def _build_case_timeline_from_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    children: dict[str, list[dict[str, Any]]] = defaultdict(list)
    roots: list[dict[str, Any]] = []
    for row in rows:
        parent = str(row.get("parent_node_id", "") or "").strip()
        if parent:
            children[parent].append(row)
        else:
            roots.append(row)
    ordered: list[dict[str, Any]] = []

    def walk(row: dict[str, Any], depth: int) -> None:
        result = _safe_json_dict(row.get("result_json"))
        graph_state = _safe_json_dict(row.get("graph_state_json"))
        summary = row.get("summary", "") or ""
        ordered.append(
            {
                "node_id": row.get("node_id", ""),
                "parent_node_id": row.get("parent_node_id", "") or "",
                "node_type": row.get("node_type", "investigation") or "investigation",
                "question": row.get("question", "") or "",
                "title": row.get("title", "") or row.get("question", "") or "Investigation",
                "intent": row.get("intent", "") or "",
                "supported": bool(row.get("supported", False)),
                "row_count": int(row.get("row_count") or 0),
                "created_at": int(row.get("created_at") or 0),
                "depth": depth,
                "summary": summary,
                "saved_summary": str(result.get("summary") or summary or "").strip(),
                "active_question": str(result.get("active_question") or row.get("title") or row.get("question") or "").strip(),
                "selected_tool": str(result.get("selected_tool") or graph_state.get("selected_tool") or "").strip(),
                "time_range": _extract_time_range(result, graph_state),
                "confidence": _extract_confidence(result, graph_state, summary),
                "query": _extract_query(result, graph_state),
                "evidence_entities": _extract_entities(graph_state),
                "ranked_entities": _extract_ranked_entities(graph_state),
                "pivot_candidates": _extract_pivot_candidates(graph_state),
                "pivot_source": _extract_pivot_source(result),
                "state_preview": _extract_state_preview(graph_state),
                "search_strategy_summary": str(result.get("search_strategy_summary") or "").strip(),
                "mitre_preview": _extract_mitre_preview(result),
                "supported_explanation": str(result.get("search_strategy_summary") or result.get("summary") or "").strip(),
            }
        )
        for child in children.get(str(row.get("node_id", "")), []):
            walk(child, depth + 1)

    for root in roots:
        walk(root, 0)
    return ordered


def build_case_timeline(case_id: str) -> list[dict[str, Any]]:
    conn = _connect()
    try:
        if case_store_backend() == "postgres":
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT node_id, case_id, parent_node_id, node_type, question, title, intent, supported, row_count, created_at, summary, result_json, graph_state_json
                    FROM case_nodes
                    WHERE case_id = %s
                    ORDER BY created_at ASC, node_id ASC
                    """,
                    (case_id,),
                )
                rows = [
                    {
                        "node_id": row[0],
                        "case_id": row[1],
                        "parent_node_id": row[2],
                        "node_type": row[3],
                        "question": row[4],
                        "title": row[5],
                        "intent": row[6],
                        "supported": row[7],
                        "row_count": row[8],
                        "created_at": row[9],
                        "summary": row[10],
                        "result_json": row[11],
                        "graph_state_json": row[12],
                    }
                    for row in cur.fetchall()
                ]
        else:
            rows = [dict(row) for row in conn.execute(
                """
                SELECT node_id, case_id, parent_node_id, node_type, question, title, intent, supported, row_count, created_at, summary, result_json, graph_state_json
                FROM case_nodes
                WHERE case_id = ?
                ORDER BY created_at ASC, rowid ASC
                """,
                (case_id,),
            ).fetchall()]
    finally:
        conn.close()
    return _build_case_timeline_from_rows(rows)


def load_case_node(case_id: str, node_id: str) -> dict[str, Any] | None:
    conn = _connect()
    try:
        if case_store_backend() == "postgres":
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT result_json FROM case_nodes WHERE case_id = %s AND node_id = %s LIMIT 1",
                    (case_id, node_id),
                )
                row = cur.fetchone()
                raw = row[0] if row else None
        else:
            row = conn.execute(
                "SELECT result_json FROM case_nodes WHERE case_id = ? AND node_id = ? LIMIT 1",
                (case_id, node_id),
            ).fetchone()
            raw = row["result_json"] if row else None
    finally:
        conn.close()
    if not raw:
        return None
    try:
        result = json.loads(str(raw))
    except Exception:
        return None
    if not isinstance(result, dict):
        return None
    case_context = result.get("case_context")
    if not isinstance(case_context, dict):
        case_context = {
            "case_id": case_id,
            "node_id": node_id,
        }
        result["case_context"] = case_context
    graph_state = result.get("graph_case_state")
    if isinstance(graph_state, dict):
        graph_state["case_id"] = str(case_context.get("case_id") or case_id or "").strip()
        graph_state["current_node_id"] = str(case_context.get("node_id") or node_id or "").strip()
        graph_state["parent_node_id"] = str(case_context.get("parent_node_id") or graph_state.get("parent_node_id") or "").strip()
    pivot_context = result.get("pivot_context")
    if isinstance(pivot_context, dict):
        if not str(pivot_context.get("case_id") or "").strip():
            pivot_context["case_id"] = str(case_context.get("case_id") or case_id or "").strip()
        if not str(pivot_context.get("current_node_id") or "").strip():
            pivot_context["current_node_id"] = str(case_context.get("node_id") or node_id or "").strip()
        if not str(pivot_context.get("parent_node_id") or "").strip():
            pivot_context["parent_node_id"] = str(case_context.get("parent_node_id") or "").strip()
        if isinstance(graph_state, dict) and not isinstance(pivot_context.get("graph_case_state"), dict):
            pivot_context["graph_case_state"] = graph_state
    return result


def list_recent_cases(limit: int = 30) -> list[dict[str, Any]]:
    conn = _connect()
    try:
        if case_store_backend() == "postgres":
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT c.case_id, c.root_question, c.status, c.created_at, c.updated_at,
                           COUNT(n.node_id) AS node_count,
                           COALESCE(MAX(n.row_count), 0) AS latest_rows
                    FROM cases c
                    LEFT JOIN case_nodes n ON n.case_id = c.case_id
                    GROUP BY c.case_id, c.root_question, c.status, c.created_at, c.updated_at
                    ORDER BY c.updated_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = cur.fetchall()
                return [
                    {
                        "case_id": row[0],
                        "root_question": row[1],
                        "status": row[2],
                        "created_at": int(row[3] or 0),
                        "updated_at": int(row[4] or 0),
                        "node_count": int(row[5] or 0),
                        "latest_rows": int(row[6] or 0),
                    }
                    for row in rows
                ]
        rows = conn.execute(
            """
            SELECT c.case_id, c.root_question, c.status, c.created_at, c.updated_at,
                   COUNT(n.node_id) AS node_count,
                   COALESCE(MAX(n.row_count), 0) AS latest_rows
            FROM cases c
            LEFT JOIN case_nodes n ON n.case_id = c.case_id
            GROUP BY c.case_id, c.root_question, c.status, c.created_at, c.updated_at
            ORDER BY c.updated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [
            {
                "case_id": row["case_id"],
                "root_question": row["root_question"],
                "status": row["status"],
                "created_at": int(row["created_at"] or 0),
                "updated_at": int(row["updated_at"] or 0),
                "node_count": int(row["node_count"] or 0),
                "latest_rows": int(row["latest_rows"] or 0),
            }
            for row in rows
        ]
    finally:
        conn.close()


def load_case(case_id: str) -> dict[str, Any] | None:
    if not case_id:
        return None
    conn = _connect()
    try:
        if case_store_backend() == "postgres":
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT case_id, session_id, root_question, status, created_at, updated_at FROM cases WHERE case_id = %s LIMIT 1",
                    (case_id,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                payload = {
                    "case_id": row[0],
                    "session_id": row[1] or "",
                    "root_question": row[2] or "",
                    "status": row[3] or "",
                    "created_at": int(row[4] or 0),
                    "updated_at": int(row[5] or 0),
                }
        else:
            row = conn.execute(
                "SELECT case_id, session_id, root_question, status, created_at, updated_at FROM cases WHERE case_id = ? LIMIT 1",
                (case_id,),
            ).fetchone()
            if not row:
                return None
            payload = {
                "case_id": row["case_id"],
                "session_id": row["session_id"] or "",
                "root_question": row["root_question"] or "",
                "status": row["status"] or "",
                "created_at": int(row["created_at"] or 0),
                "updated_at": int(row["updated_at"] or 0),
            }
    finally:
        conn.close()
    payload["timeline"] = build_case_timeline(case_id)
    return payload


def persist_case_result(
    *,
    session_id: str,
    question: str,
    result_body: dict[str, Any],
    graph_case_state: dict[str, Any],
    case_id: str | None,
    parent_node_id: str | None,
    node_type: str,
) -> dict[str, Any]:
    case_id_final = str(case_id or "").strip() or new_case_id()
    node_id = new_node_id()
    now_ts = int(time.time())
    root_question = str(result_body.get("root_question") or question or "").strip() or question
    title = str(result_body.get("active_question") or result_body.get("question") or question).strip() or question
    summary = str(result_body.get("summary") or "").strip()
    row_count = int(result_body.get("rows_returned") or result_body.get("total_rows") or 0)
    supported = bool(result_body.get("supported", True))
    conn = _connect()
    try:
        with CASE_STORE_LOCK:
            if case_store_backend() == "postgres":
                with conn.cursor() as cur:
                    cur.execute("SELECT case_id FROM cases WHERE case_id = %s LIMIT 1", (case_id_final,))
                    existing = cur.fetchone()
                    if existing:
                        cur.execute(
                            "UPDATE cases SET status = %s, updated_at = %s WHERE case_id = %s",
                            ("complete" if supported else "blocked", now_ts, case_id_final),
                        )
                    else:
                        cur.execute(
                            "INSERT INTO cases(case_id, session_id, root_question, status, created_at, updated_at) VALUES(%s,%s,%s,%s,%s,%s)",
                            (case_id_final, session_id, root_question, "complete" if supported else "blocked", now_ts, now_ts),
                        )
                    cur.execute(
                        """
                        INSERT INTO case_nodes(
                            node_id, case_id, parent_node_id, node_type, question, title, intent, supported, row_count, created_at, summary, result_json, graph_state_json
                        ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        """,
                        (
                            node_id,
                            case_id_final,
                            str(parent_node_id or "").strip() or None,
                            node_type,
                            question,
                            title,
                            str(result_body.get("intent") or "").strip(),
                            supported,
                            row_count,
                            now_ts,
                            summary,
                            json.dumps(result_body),
                            json.dumps(graph_case_state or {}),
                        ),
                    )
                conn.commit()
            else:
                existing = conn.execute("SELECT case_id FROM cases WHERE case_id = ? LIMIT 1", (case_id_final,)).fetchone()
                if existing:
                    conn.execute(
                        "UPDATE cases SET status = ?, updated_at = ? WHERE case_id = ?",
                        ("complete" if supported else "blocked", now_ts, case_id_final),
                    )
                else:
                    conn.execute(
                        "INSERT INTO cases(case_id, session_id, root_question, status, created_at, updated_at) VALUES(?,?,?,?,?,?)",
                        (case_id_final, session_id, root_question, "complete" if supported else "blocked", now_ts, now_ts),
                    )
                conn.execute(
                    """
                    INSERT INTO case_nodes(
                        node_id, case_id, parent_node_id, node_type, question, title, intent, supported, row_count, created_at, summary, result_json, graph_state_json
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        node_id,
                        case_id_final,
                        str(parent_node_id or "").strip() or None,
                        node_type,
                        question,
                        title,
                        str(result_body.get("intent") or "").strip(),
                        1 if supported else 0,
                        row_count,
                        now_ts,
                        summary,
                        json.dumps(result_body),
                        json.dumps(graph_case_state or {}),
                    ),
                )
                conn.commit()
    finally:
        conn.close()
    timeline = build_case_timeline(case_id_final)
    case_context = {
        "case_id": case_id_final,
        "node_id": node_id,
        "parent_node_id": str(parent_node_id or "").strip() or "",
        "node_type": node_type,
        "timeline": timeline,
        "backend": case_store_backend(),
    }
    result_body["case_context"] = case_context
    graph_state = dict(graph_case_state or {})
    graph_state["case_id"] = case_id_final
    graph_state["current_node_id"] = node_id
    graph_state["parent_node_id"] = str(parent_node_id or "").strip() or ""
    pivot_context = result_body.get("pivot_context")
    if isinstance(pivot_context, dict):
        pivot_context["case_id"] = case_id_final
        pivot_context["current_node_id"] = node_id
        pivot_context["parent_node_id"] = str(parent_node_id or "").strip() or ""
        pivot_context["graph_case_state"] = graph_state
    conn = _connect()
    try:
        with CASE_STORE_LOCK:
            if case_store_backend() == "postgres":
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE case_nodes SET result_json = %s, graph_state_json = %s WHERE node_id = %s",
                        (json.dumps(result_body), json.dumps(graph_state), node_id),
                    )
                conn.commit()
            else:
                conn.execute(
                    "UPDATE case_nodes SET result_json = ?, graph_state_json = ? WHERE node_id = ?",
                    (json.dumps(result_body), json.dumps(graph_state), node_id),
                )
                conn.commit()
    finally:
        conn.close()
    return case_context
