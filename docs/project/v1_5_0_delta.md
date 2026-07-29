# v1.5.0 Release Highlights

This document summarizes operator-facing changes in `v1.5.0` compared with `v1.4.2`.

> **Historical note:** `v1.5.1` superseded the `v1.5.0` planner default. In `v1.5.0`, planner and writer both defaulted to **`granite4:3b`**. Current production (`v1.5.1`) uses a dedicated **Ministral-3B-Reasoning planner** plus **`granite4:3b` writer**. See [v1.5.1 Release Highlights](v1_5_1_delta.md).

## Why This Release Matters

`v1.5.0` promotes a **US-primary Ollama model stack** for SPL writing and peer review. The stack was chosen from a 20-model bake-off on the RTX 1000 Ada lab: **no MCP hardening regression** (94.83 / 100% pass) while improving offline SPL quality and GPU efficiency versus the prior `deepseek-coder-v2:lite` writer.

## Headline Changes

### 1. New default SPL writer and repair model

What changed:
- `OLLAMA_MODEL_QUERY_WRITER` and `OLLAMA_MODEL_QUERY_REPAIR` default to **`granite4:3b`** (US / IBM)
- replaces **`deepseek-coder-v2:lite`** (CN / DeepSeek)

Why it matters:
- offline RAG SPL score **94.4 vs 75.8** on the lab harness
- **full GPU** load (~2.4 GiB) vs DeepSeek **~47% GPU / CPU spill**
- ~**1 s** SPL generation vs ~**6 s** on the same prompt

### 2. US-primary planner and peer reviewers (superseded in v1.5.1)

What changed in `v1.5.0`:
- `OLLAMA_MODEL_QUERY_PLANNER` defaulted to **`granite4:3b`** (same tag as writer)
- `OLLAMA_MODEL_PEER_REVIEWER` and `_2` default to **`gemma3:4b`** (US / Google)
- replaced Qwen-class planner/peer defaults from `v1.4.x`

What changed in `v1.5.1`:
- planner moved to **`TechyShishy/ministral-3:3b-reasoning-2512-q4_K_M`** with **`ministral-3:3b`** fallback
- writer, peers, and review roles unchanged from `v1.5.0`

Why it matters:
- `v1.5.0` validated granite + gemma + Foundation-Sec at **94.83 MCP**
- `v1.5.1` split planner from writer after the dedicated 24-model planner bake-off

### 3. Centralized defaults in `scripts/runtime_config.py`

What changed:
- all LangGraph role defaults flow from `runtime_config.py`
- `LEGACY_V14_*` constants document the prior Qwen + DeepSeek profile for rollback

Why it matters:
- UI config panel, Makefile `model-show`, and pipeline code stay aligned

## Upgrade Notes

Pull the new default models (current `v1.5.1` stack):

```bash
ollama pull TechyShishy/ministral-3:3b-reasoning-2512-q4_K_M
ollama pull ministral-3:3b
ollama pull granite4:3b
ollama pull gemma3:4b
ollama pull hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest
```

Update `config/ui.env` (or rely on code defaults if unset):

```bash
OLLAMA_MODEL_QUERY_PLANNER=TechyShishy/ministral-3:3b-reasoning-2512-q4_K_M
OLLAMA_MODEL_QUERY_PLANNER_FALLBACK=ministral-3:3b
OLLAMA_MODEL_QUERY_WRITER=granite4:3b
OLLAMA_MODEL_QUERY_REPAIR=granite4:3b
OLLAMA_MODEL_PEER_REVIEWER=gemma3:4b
OLLAMA_MODEL_PEER_REVIEWER_2=gemma3:4b
```

Rollback to `v1.4.x` models:

```bash
OLLAMA_MODEL_QUERY_PLANNER=hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M
OLLAMA_MODEL_QUERY_WRITER=deepseek-coder-v2:lite
OLLAMA_MODEL_QUERY_REPAIR=deepseek-coder-v2:lite
OLLAMA_MODEL_PEER_REVIEWER=hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M
OLLAMA_MODEL_PEER_REVIEWER_2=hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M
```

After changing models, restart the controller and run:

```bash
make env-profile-refresh
make spl-hardening-benchmark
```

Benchmark artifacts and rationale: `docs/runbooks/laptop_model_profile.md`.
