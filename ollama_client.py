"""Shared Ollama helpers for A.G.E.N.T. Smith."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from scripts.runtime_config import get_ollama_host

OLLAMA_HOST = get_ollama_host()
DEFAULT_MODEL = "granite4:3b"


def extract_json_object(text: str) -> dict[str, Any]:
    if not text:
        raise ValueError("empty_model_text")

    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)

    try:
        obj = json.loads(cleaned)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", cleaned):
        start = match.start()
        try:
            obj, _end = decoder.raw_decode(cleaned[start:])
        except Exception:
            continue
        if isinstance(obj, dict):
            return obj
    raise ValueError("json_object_not_found")


def call_ollama_json(
    *,
    model: str,
    system_prompt: str,
    user_payload: dict[str, Any],
    timeout: float = 180.0,
    host: str | None = None,
) -> dict[str, Any]:
    """Call Ollama /api/chat with JSON response format (planner/writer structured output)."""
    ollama_host = str(host or get_ollama_host()).strip().rstrip("/")
    user_text = f"Return strict JSON only. No prose.\n\nINPUT:\n{json.dumps(user_payload, indent=2)}"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_text},
        ],
        "stream": False,
        "format": "json",
    }
    timeout_config = httpx.Timeout(
        timeout,
        connect=min(8.0, timeout),
        read=timeout,
        write=min(30.0, timeout),
        pool=min(30.0, timeout),
    )
    with httpx.Client(timeout=timeout_config) as client:
        resp = client.post(f"{ollama_host}/api/chat", json=payload)
        resp.raise_for_status()
        body = resp.json()

    if body.get("error"):
        raise RuntimeError(str(body["error"]))

    raw = str((body.get("message") or {}).get("content") or "").strip()
    parsed = extract_json_object(raw)
    parsed["_raw_text_preview"] = raw[:1200]
    parsed["_ollama_model"] = model
    return parsed


def generate(prompt: str, model: str = DEFAULT_MODEL, timeout: float = 120.0) -> str:
    """Run a non-streaming Ollama generation request and return text."""
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "think": False,
    }

    with httpx.Client(timeout=timeout) as client:
        response = client.post(f"{OLLAMA_HOST}/api/generate", json=payload)
        response.raise_for_status()
        data = response.json()

    text = data.get("response", "").strip()
    if not text:
        raise RuntimeError(
            "Ollama returned an empty response body. "
            f"done={data.get('done')} done_reason={data.get('done_reason')} "
            f"eval_count={data.get('eval_count')}"
        )

    return text


if __name__ == "__main__":
    reply = generate("Reply with exactly: CUSTOM_OLLAMA_WRAPPER_OK")
    print(reply)
