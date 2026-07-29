#!/usr/bin/env python3
"""VRAM smoke for planner candidate Ollama tags."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import httpx

OLLAMA = "http://127.0.0.1:11434"
DEFAULT_MODELS = [
    "granite4:3b",
    "gemma3:4b",
    "granite3-moe:1b",
    "granite3-moe:3b",
    "mistral:7b",
    "mistral-nemo:12b",
    "devstral:24b",
    "qwen3:4b",
    "qwen3:8b",
    "qwen2.5:7b",
    "llama3.2:3b",
    "phi4-mini",
    "qwen3:30b-a3b",
    # HF discovery P0 (artifacts/model_eval/planner_bakeoff/hf_exhaustive_research.md)
    "ibm/granite4.1:8b",
    "phi4-mini-reasoning",
    "ministral-3:3b",
    "allenporter/xlam:1b",
    "nemotron-mini:4b-instruct-q4_K_M",
    "hf.co/bartowski/functionary-small-v3.2-GGUF:Q4_K_M",
    "hf.co/bartowski/AgentFlow_agentflow-planner-7b-GGUF:Q4_K_M",
]


def _resolve_installed_tag(requested: str, installed: set[str]) -> str | None:
    if requested in installed:
        return requested
    latest = f"{requested}:latest"
    if latest in installed:
        return latest
    for tag in installed:
        if tag.split(":", 1)[0] == requested:
            return tag
    return None


def main() -> int:
    out_path = Path("artifacts/model_eval/planner_bakeoff/vram_smoke_planner_candidates.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tags = {m["name"] for m in httpx.get(f"{OLLAMA}/api/tags", timeout=30).json().get("models", [])}
    client = httpx.Client(timeout=300)
    rows: list[dict] = []
    for model in DEFAULT_MODELS:
        resolved = _resolve_installed_tag(model, tags)
        if not resolved:
            rows.append({"model": model, "status": "not_installed"})
            continue
        try:
            client.post(
                f"{OLLAMA}/api/generate",
                json={"model": resolved, "prompt": "ok", "stream": False, "options": {"num_predict": 8}},
            )
            ps = client.get(f"{OLLAMA}/api/ps").json()
            row = ps["models"][0] if ps.get("models") else {}
            size = int(row.get("size", 0) or 0)
            vram = int(row.get("size_vram", 0) or 0)
            ratio = (vram / size) if size else 0.0
            rows.append(
                {
                    "model": model,
                    "resolved_tag": resolved,
                    "size_gib": round(size / 1024**3, 2),
                    "vram_mib": round(vram / 1024**2),
                    "gpu_fit": "full_gpu" if ratio >= 0.92 else f"partial_{round(ratio * 100)}pct_gpu",
                }
            )
            client.post(f"{OLLAMA}/api/generate", json={"model": resolved, "keep_alive": 0})
        except Exception as exc:
            rows.append({"model": model, "error": str(exc)[:120]})
        time.sleep(0.3)
    out_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
