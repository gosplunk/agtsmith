#!/usr/bin/env python3
"""Splunk KV Store (or local mirror) case persistence for Splunk app deployments."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CASE_MIRROR_ROOT = PROJECT_ROOT / "artifacts" / "cases" / "kvstore_mirror"
CASES_FILE = CASE_MIRROR_ROOT / "cases.json"
NODES_FILE = CASE_MIRROR_ROOT / "case_nodes.json"


def _splunk_kv_enabled() -> bool:
    return str(os.getenv("AGTSMITH_KVSTORE_SYNC", "0")).strip() in {"1", "true", "yes"}


def _splunk_base() -> str:
    return str(os.getenv("SPLUNK_BASE_URL", "https://127.0.0.1:8089")).rstrip("/")


def _bearer() -> str:
    return str(os.getenv("SPLUNK_LAB_BEARER_TOKEN", "")).strip()


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _save_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


class KvStoreCaseBackend:
    """File-backed case store with optional Splunk KV Store sync."""

    def __init__(self) -> None:
        self.cases = _load_json(CASES_FILE)
        self.nodes = _load_json(NODES_FILE)

    def _persist_mirror(self) -> None:
        _save_json(CASES_FILE, self.cases)
        _save_json(NODES_FILE, self.nodes)
        if _splunk_kv_enabled() and _bearer():
            self._sync_collection("agent_smith_cases", self.cases)
            self._sync_collection("agent_smith_case_nodes", self.nodes)

    def _sync_collection(self, collection: str, payload: dict[str, Any]) -> None:
        url = f"{_splunk_base()}/servicesNS/nobody/agent_smith/storage/collections/data/{collection}/batch_save"
        body = json.dumps([{"_key": k, **(v if isinstance(v, dict) else {"value": v})} for k, v in payload.items()]).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {_bearer()}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, context=_ssl_context(), timeout=15) as resp:
                resp.read()
        except urllib.error.HTTPError:
            # Collection may not exist yet — mirror still holds data locally.
            pass

    def upsert_case(self, case_id: str, record: dict[str, Any]) -> None:
        self.cases[case_id] = record
        self._persist_mirror()

    def upsert_node(self, node_id: str, record: dict[str, Any]) -> None:
        self.nodes[node_id] = record
        self._persist_mirror()

    def list_cases(self, limit: int = 30) -> list[dict[str, Any]]:
        node_counts: dict[str, int] = {}
        latest_rows: dict[str, int] = {}
        for node in self.nodes.values():
            if not isinstance(node, dict):
                continue
            cid = str(node.get("case_id") or "")
            if not cid:
                continue
            node_counts[cid] = node_counts.get(cid, 0) + 1
            latest_rows[cid] = max(latest_rows.get(cid, 0), int(node.get("row_count") or 0))
        rows = []
        for case_id, record in self.cases.items():
            if not isinstance(record, dict):
                continue
            rows.append(
                {
                    **record,
                    "case_id": case_id,
                    "node_count": node_counts.get(case_id, 0),
                    "latest_rows": latest_rows.get(case_id, 0),
                }
            )
        rows.sort(key=lambda r: int(r.get("updated_at") or 0), reverse=True)
        return rows[:limit]

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        row = self.cases.get(case_id)
        return row if isinstance(row, dict) else None

    def get_node(self, case_id: str, node_id: str) -> dict[str, Any] | None:
        row = self.nodes.get(node_id)
        if not isinstance(row, dict):
            return None
        if str(row.get("case_id") or "") != case_id:
            return None
        return row

    def nodes_for_case(self, case_id: str) -> list[dict[str, Any]]:
        rows = [
            row
            for row in self.nodes.values()
            if isinstance(row, dict) and str(row.get("case_id") or "") == case_id
        ]
        rows.sort(key=lambda r: int(r.get("created_at") or 0))
        return rows


def _ssl_context():
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
