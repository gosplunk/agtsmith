#!/usr/bin/env python3
"""Lab smoke checks for Splunk SOC Analyst sandbox.

Checks in one run:
1) Ollama tags endpoint reachability
2) Ollama generate behavior with expected token response
3) Splunk 8089 API responsiveness/auth signal

This script is intentionally simple and educational.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, asdict

import httpx
from runtime_config import get_ollama_host, get_splunk_base_url

OLLAMA_HOST = get_ollama_host()
DEFAULT_MODEL_NAME = "hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
MODEL_NAME = os.getenv("OLLAMA_MODEL_PRIMARY", DEFAULT_MODEL_NAME)
SPLUNK_BASE = get_splunk_base_url()

EXPECTED_TOKEN = "OLLAMA_HTTP_THINK_OFF_OK"


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str


def check_ollama_tags(timeout: float = 30.0) -> CheckResult:
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"{OLLAMA_HOST}/api/tags")
        resp.raise_for_status()
        body = resp.json()
        models = body.get("models", [])
        model_names = [m.get("name", "") for m in models if isinstance(m, dict)]

        if MODEL_NAME in model_names:
            return CheckResult(
                name="ollama_tags",
                passed=True,
                detail=f"Tags reachable. Found model '{MODEL_NAME}'.",
            )

        return CheckResult(
            name="ollama_tags",
            passed=False,
            detail=(
                "Tags reachable but target model missing. "
                f"Found {len(model_names)} models."
            ),
        )
    except Exception as exc:
        return CheckResult(
            name="ollama_tags",
            passed=False,
            detail=f"Request failed: {exc}",
        )


def check_ollama_generate(timeout: float = 120.0) -> CheckResult:
    payload = {
        "model": MODEL_NAME,
        "prompt": f"Reply with exactly: {EXPECTED_TOKEN}",
        "stream": False,
        "think": False,
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(f"{OLLAMA_HOST}/api/generate", json=payload)
        resp.raise_for_status()
        data = resp.json()
        text = (data.get("response") or "").strip()

        if text == EXPECTED_TOKEN:
            return CheckResult(
                name="ollama_generate",
                passed=True,
                detail=f"Generate returned expected token '{EXPECTED_TOKEN}'.",
            )

        if text:
            return CheckResult(
                name="ollama_generate",
                passed=False,
                detail=(
                    "Generate returned non-empty but unexpected text. "
                    f"Observed: {text!r}"
                ),
            )

        return CheckResult(
            name="ollama_generate",
            passed=False,
            detail=(
                "Generate returned empty text. "
                f"done={data.get('done')} done_reason={data.get('done_reason')} "
                f"eval_count={data.get('eval_count')}"
            ),
        )
    except Exception as exc:
        return CheckResult(
            name="ollama_generate",
            passed=False,
            detail=f"Request failed: {exc}",
        )


def check_splunk_auth_signal(timeout: float = 30.0) -> CheckResult:
    # We intentionally call without auth to validate network path and API response behavior.
    url = f"{SPLUNK_BASE}/services/mcp"

    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
            get_resp = client.get(url)
            post_resp = client.post(url, json={})

        get_body = (get_resp.text or "").strip().lower()
        post_body = (post_resp.text or "").strip().lower()

        auth_signal = any(
            [
                "not properly authenticated" in get_body,
                "not properly authenticated" in post_body,
                get_resp.status_code in {401, 403},
                post_resp.status_code in {401, 403},
            ]
        )

        if auth_signal:
            return CheckResult(
                name="splunk_auth_signal",
                passed=True,
                detail=(
                    "Splunk responded with expected unauth/auth-processing signal. "
                    f"get_status={get_resp.status_code} post_status={post_resp.status_code}"
                ),
            )

        if (
            200 <= get_resp.status_code < 500
            and 200 <= post_resp.status_code < 500
        ):
            return CheckResult(
                name="splunk_auth_signal",
                passed=True,
                detail=(
                    "Splunk endpoint responded on both methods, but auth signal text differed. "
                    f"get_status={get_resp.status_code} post_status={post_resp.status_code}"
                ),
            )

        return CheckResult(
            name="splunk_auth_signal",
            passed=False,
            detail=(
                "Unexpected Splunk response status. "
                f"get_status={get_resp.status_code} post_status={post_resp.status_code}"
            ),
        )
    except Exception as exc:
        return CheckResult(
            name="splunk_auth_signal",
            passed=False,
            detail=f"Request failed: {exc}",
        )


def main() -> int:
    checks = [
        check_ollama_tags(),
        check_ollama_generate(),
        check_splunk_auth_signal(),
    ]

    print("=== Lab Smoke Check Results ===")
    for c in checks:
        status = "PASS" if c.passed else "FAIL"
        print(f"[{status}] {c.name}: {c.detail}")

    summary = {
        "all_passed": all(c.passed for c in checks),
        "checks": [asdict(c) for c in checks],
    }

    print("\n=== JSON Summary ===")
    print(json.dumps(summary, indent=2))

    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
