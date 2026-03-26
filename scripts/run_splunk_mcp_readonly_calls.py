#!/usr/bin/env python3
"""Run first read-only Splunk MCP tool calls.

Flow:
1) initialize
2) tools/call -> splunk_get_user_info
3) tools/call -> splunk_get_indexes

This script is educational and focused on response-shape discovery.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Any

import httpx
from runtime_config import get_splunk_mcp_url

SPLUNK_MCP_URL = get_splunk_mcp_url()

# LAB-ONLY / TEMPORARY / NOT PRODUCTION SAFE
LAB_BEARER_TOKEN_FALLBACK = "REPLACE_WITH_SPLUNK_MCP_BEARER_TOKEN"


@dataclass
class RpcResponse:
    status_code: int
    body: dict[str, Any] | list[Any] | str


def rpc_call(client: httpx.Client, headers: dict[str, str], payload: dict[str, Any]) -> RpcResponse:
    resp = client.post(SPLUNK_MCP_URL, headers=headers, json=payload)
    text = (resp.text or "").strip()
    try:
        body: dict[str, Any] | list[Any] | str = resp.json()
    except Exception:
        body = text
    return RpcResponse(status_code=resp.status_code, body=body)


def compact(obj: Any) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=True)


def main() -> int:
    token = os.getenv("SPLUNK_LAB_BEARER_TOKEN", LAB_BEARER_TOKEN_FALLBACK)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
    }

    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "agtsmith-lab", "version": "0.1.0"},
        },
    }

    get_user_info_payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "splunk_get_user_info",
            "arguments": {},
        },
    }

    get_indexes_payload = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "splunk_get_indexes",
            "arguments": {
                "row_limit": 20,
            },
        },
    }

    with httpx.Client(timeout=60.0, verify=False, follow_redirects=True) as client:
        init_resp = rpc_call(client, headers, init_payload)
        user_resp = rpc_call(client, headers, get_user_info_payload)
        indexes_resp = rpc_call(client, headers, get_indexes_payload)

    print("=== initialize ===")
    print(compact({"status": init_resp.status_code, "body": init_resp.body}))

    print("\n=== tools/call: splunk_get_user_info ===")
    print(compact({"status": user_resp.status_code, "body": user_resp.body}))

    print("\n=== tools/call: splunk_get_indexes ===")
    print(compact({"status": indexes_resp.status_code, "body": indexes_resp.body}))

    if init_resp.status_code != 200:
        print("\nFAIL: initialize did not return HTTP 200.")
        return 1

    for label, resp in (("splunk_get_user_info", user_resp), ("splunk_get_indexes", indexes_resp)):
        if resp.status_code != 200:
            print(f"\nFAIL: {label} HTTP status {resp.status_code}.")
            return 1
        if not isinstance(resp.body, dict):
            print(f"\nFAIL: {label} response was not JSON object.")
            return 1
        if "error" in resp.body:
            print(f"\nFAIL: {label} returned JSON-RPC error: {resp.body['error']}")
            return 1
        if "result" not in resp.body:
            print(f"\nFAIL: {label} missing JSON-RPC result.")
            return 1

    # Minimal shape summary for docs.
    user_result = user_resp.body.get("result", {}) if isinstance(user_resp.body, dict) else {}
    indexes_result = indexes_resp.body.get("result", {}) if isinstance(indexes_resp.body, dict) else {}

    user_content = user_result.get("content", []) if isinstance(user_result, dict) else []
    indexes_content = indexes_result.get("content", []) if isinstance(indexes_result, dict) else []

    print("\n=== Summary ===")
    print(f"user_info.content_items={len(user_content) if isinstance(user_content, list) else 'n/a'}")
    print(f"indexes.content_items={len(indexes_content) if isinstance(indexes_content, list) else 'n/a'}")

    print("\nPASS: First read-only tool calls succeeded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
