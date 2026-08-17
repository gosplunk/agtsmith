"""Shared Ollama helpers for A.G.E.N.T. Smith."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

import httpx

from scripts.runtime_config import (
    get_ollama_host,
    get_ollama_keep_alive,
    get_ollama_request_timeout_sec,
    get_ollama_warm_keep_alive,
    ollama_warm_model_names,
)

OLLAMA_HOST = get_ollama_host()
DEFAULT_MODEL = "granite4:3b"
OLLAMA_TIMEOUT_EVENTS: list[dict[str, Any]] = []


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


def reset_ollama_timeout_events() -> None:
    OLLAMA_TIMEOUT_EVENTS.clear()


def get_ollama_timeout_events() -> list[dict[str, Any]]:
    return [dict(item) for item in OLLAMA_TIMEOUT_EVENTS]


def list_loaded_ollama_models(*, host: str | None = None) -> list[str]:
    """Return model names currently loaded in Ollama VRAM."""
    ollama_host = str(host or get_ollama_host()).strip().rstrip("/")
    if not ollama_host:
        return []
    try:
        with httpx.Client(timeout=8.0) as client:
            resp = client.get(f"{ollama_host}/api/ps")
            resp.raise_for_status()
            body = resp.json()
    except Exception:
        return []
    models = body.get("models", []) if isinstance(body, dict) else []
    names: list[str] = []
    for item in models:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if name and name not in names:
            names.append(name)
    return names


def warm_ollama_models(
    models: Iterable[str] | None = None,
    *,
    host: str | None = None,
    keep_alive: str | int | None = None,
) -> dict[str, Any]:
    """Best-effort preload of planner/writer models into Ollama memory."""
    ollama_host = str(host or get_ollama_host()).strip().rstrip("/")
    if not ollama_host:
        return {"warmed": [], "errors": ["missing_ollama_host"]}
    targets = [str(item).strip() for item in (models or ollama_warm_model_names()) if str(item).strip()]
    if not targets:
        return {"warmed": [], "errors": ["no_warm_models_configured"]}
    retention = get_ollama_warm_keep_alive() if keep_alive is None else keep_alive
    warmed: list[str] = []
    errors: list[str] = []
    with httpx.Client(timeout=120.0) as client:
        for model in targets:
            try:
                resp = client.post(
                    f"{ollama_host}/api/generate",
                    json={
                        "model": model,
                        "prompt": "Reply with exactly: WARM_OK",
                        "stream": False,
                        "keep_alive": retention,
                    },
                )
                resp.raise_for_status()
                warmed.append(model)
            except Exception as exc:
                errors.append(f"{model}:{type(exc).__name__}:{exc}")
    return {"warmed": warmed, "errors": errors}


def release_ollama_vram(models: Iterable[str] | None = None, *, host: str | None = None) -> None:
    """Best-effort unload of Ollama models from GPU/CPU memory."""
    ollama_host = str(host or get_ollama_host()).strip().rstrip("/")
    if not ollama_host:
        return
    targets = [str(item).strip() for item in (models or []) if str(item).strip()]
    if not targets:
        targets = list_loaded_ollama_models(host=ollama_host)
    if not targets:
        return
    with httpx.Client(timeout=10.0) as client:
        for model in targets:
            try:
                client.post(
                    f"{ollama_host}/api/generate",
                    json={"model": model, "keep_alive": 0},
                )
            except Exception:
                continue


def call_ollama_json(
    *,
    model: str,
    system_prompt: str,
    user_payload: dict[str, Any],
    timeout: float | None = None,
    host: str | None = None,
    keep_alive: str | int | None = None,
) -> dict[str, Any]:
    """Call Ollama /api/chat with JSON response format (planner/writer structured output)."""
    ollama_host = str(host or get_ollama_host()).strip().rstrip("/")
    user_text = f"Return strict JSON only. No prose.\n\nINPUT:\n{json.dumps(user_payload, indent=2)}"
    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_text},
        ],
        "stream": False,
        "format": "json",
        "keep_alive": get_ollama_keep_alive() if keep_alive is None else keep_alive,
    }
    request_timeout = (
        get_ollama_request_timeout_sec() if timeout is None else max(0.1, float(timeout))
    )
    timeout_config = httpx.Timeout(
        request_timeout,
        connect=min(8.0, request_timeout),
        read=request_timeout,
        write=min(30.0, request_timeout),
        pool=min(30.0, request_timeout),
    )
    try:
        with httpx.Client(timeout=timeout_config) as client:
            resp = client.post(f"{ollama_host}/api/chat", json=payload)
            resp.raise_for_status()
            body = resp.json()
    except httpx.TimeoutException:
        OLLAMA_TIMEOUT_EVENTS.append(
            {
                "model": model,
                "timeout_seconds": round(request_timeout, 3),
            }
        )
        raise

    if body.get("error"):
        raise RuntimeError(str(body["error"]))

    raw = str((body.get("message") or {}).get("content") or "").strip()
    parsed = extract_json_object(raw)
    parsed["_raw_text_preview"] = raw[:1200]
    parsed["_ollama_model"] = model
    return parsed


def generate(
    prompt: str,
    model: str = DEFAULT_MODEL,
    timeout: float = 120.0,
    *,
    think: bool = False,
    keep_alive: str | int | None = None,
) -> str:
    """Run a non-streaming Ollama generation request and return text."""
    payload: dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "think": think,
        "keep_alive": get_ollama_keep_alive() if keep_alive is None else keep_alive,
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
