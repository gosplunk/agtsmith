# v1.5.1 Release Highlights

This document summarizes operator-facing changes in `v1.5.1` compared with `v1.5.0`.

## Why This Release Matters

`v1.5.1` completes the **split-role model stack**: a dedicated **Ministral-3B-Reasoning planner** plus the existing **`granite4:3b` SPL writer**. The planner was chosen from a 24-model isolated `planner_node` bake-off on the RTX 1000 Ada lab while preserving the writer bake-off winner from `v1.5.0`.

## Headline Changes

### 1. Dedicated planner model

What changed:
- `OLLAMA_MODEL_QUERY_PLANNER` defaults to **`TechyShishy/ministral-3:3b-reasoning-2512-q4_K_M`**
- `OLLAMA_MODEL_QUERY_PLANNER_FALLBACK` defaults to **`ministral-3:3b`**
- bake-off artifact winner: **`hf.co/EnlistedGhost/Ministral-3-3B-Reasoning-2512-GGUF:Q5_K_M`** (`PLANNER_BAKEOFF_WINNER_ARTIFACT` in `scripts/runtime_config.py`; eval winner, not production tag — EnlistedGhost GGUF crashes Ollama on the lab host)

Why it matters:
- separates planning from SPL writing instead of reusing `granite4:3b` for both roles
- planner bake-off: **59.68 avg**, **100% intent**, **~2.7 s median** on 66 cases
- LangGraph falls back to `ministral-3:3b`, then deterministic templates, if the primary tag fails

### 2. Writer unchanged

- `OLLAMA_MODEL_QUERY_WRITER` and `OLLAMA_MODEL_QUERY_REPAIR` remain **`granite4:3b`**
- MCP hardening stays at **94.83 / 100%** on the lab harness

### 3. Structured Ollama JSON via chat API

- planner/writer structured calls use **`/api/chat`** with `format: json`
- shared helper: `ollama_client.call_ollama_json()`

## Upgrade Notes

Pull the new default models:

```bash
ollama pull TechyShishy/ministral-3:3b-reasoning-2512-q4_K_M
ollama pull ministral-3:3b
ollama pull granite4:3b
ollama pull gemma3:4b
ollama pull hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest
```

Update `config/ui.env`:

```bash
OLLAMA_MODEL_QUERY_PLANNER=TechyShishy/ministral-3:3b-reasoning-2512-q4_K_M
OLLAMA_MODEL_QUERY_PLANNER_FALLBACK=ministral-3:3b
OLLAMA_MODEL_QUERY_WRITER=granite4:3b
OLLAMA_MODEL_QUERY_REPAIR=granite4:3b
OLLAMA_MODEL_PEER_REVIEWER=gemma3:4b
OLLAMA_MODEL_PEER_REVIEWER_2=gemma3:4b
```

After changing models, restart the controller and run:

```bash
make env-profile-refresh
make spl-hardening-benchmark
```

Benchmark artifacts: `docs/runbooks/laptop_model_profile.md`, `artifacts/model_eval/planner_bakeoff/planner_eval_latest.md`.
