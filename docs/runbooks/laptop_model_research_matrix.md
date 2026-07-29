# Laptop Model Research Matrix (RTX 1000 Ada — 6141 MiB VRAM)

Generated during model bake-off Phase 0. **Origin is disclosure only** — not a scoring filter.

**Current production defaults (`v1.5.1`):** Ministral-3B-Reasoning planner, `granite4:3b` writer/repair, `gemma3:4b` peers, Foundation-Sec-8B review/summary. See `docs/model_strategy.md`.

## VRAM budget

| Item | Value |
|------|-------|
| Total VRAM | 6141 MiB |
| Safe single-model load | ≤ ~5.0–5.5 GiB (+ KV headroom) |
| Ranking track | RAG-on (production parity) + vanilla baseline |

## Already pulled (VRAM smoke verified)

| tag | quant | params | disk | origin | peak_vram_mib | fits_6gb | pull? | roles |
|-----|-------|--------|------|--------|---------------|----------|-------|-------|
| `deepseek-coder-v2:lite` | Q4_0 | 15.7B MoE | 8.9 GB | CN / DeepSeek | **4586** (`size_vram`) | yes | done | writer/repair baseline |
| `qwen2.5:7b` | Q4_K_M | 7.6B | 4.7 GB | CN / Alibaba | **4637** (`size_vram`) | yes | done | planner/peer/writer |
| `hf.co/fdtn-ai/Foundation-Sec-8B-...-Q8_0-GGUF:latest` | Q8_0 | 8B | 8.5 GB | US / Foundation | likely CPU offload | marginal | done | review/summary |

## Candidates pulled for bake-off

| tag | quant (expected) | est. VRAM | origin | fits_6gb | pull? | roles |
|-----|------------------|-----------|--------|----------|-------|-------|
| `qwen2.5-coder:7b` | Q4_K_M | ~5 GiB | CN / Alibaba | yes | **yes** | writer/repair |
| `gemma3:4b` | Q4_K_M | ~3.3 GiB | US / Google | yes | **yes** | writer/planner |
| `codegemma:7b` | Q4_K_M | ~5–5.5 GiB | US / Google | yes | **yes** | writer |
| `codegemma:2b` | Q4_K_M | ~2 GiB | US / Google | yes | **yes** | writer fallback |
| `llama3.2:3b` | Q4_K_M | ~2 GiB | US / Meta | yes | **yes** | planner |
| `granite4:3b` | Q4_K_M | ~2 GiB | US / IBM | yes | **yes** | writer (v1.5.x default); planner in v1.5.0 only |

## Additional pulls (2026-07-21 — optional / light tier)

| tag | quant | params | peak_vram_mib | origin | fits_6gb | roles |
|-----|-------|--------|---------------|--------|----------|-------|
| `qwen2.5:3b` | Q4_K_M | 3.1B | 2059 | CN / Alibaba | yes | planner fallback |
| `qwen2.5-coder:3b` | Q4_K_M | 3.1B | 2059 | CN / Alibaba | yes | writer fallback |
| `qwen2.5-coder:1.5b` | Q4_K_M | 1.5B | 1112 | CN / Alibaba | yes | ultra-light writer |
| `mistral:7b` | Q4_K_M | 7.2B | 4586 | FR / Mistral AI | yes | planner (v0.3 tag N/A on Ollama) |
| `phi4-mini` | Q4_K_M | 3.8B | 2945 | US / Microsoft | yes | planner/writer experiment |
| `phi3:mini` | Q4_0 | 3.8B | 3622 | US / Microsoft | yes | planner experiment |
| `phi3.5:3.8b` | Q4_0 | 3.8B | 3622 | US / Microsoft | yes | planner experiment |
| `llama3.2:1b` | Q8_0 | 1.2B | 1444 | US / Meta | yes | ultra-light planner |
| `gemma3:1b` | Q4_K_M | ~1B | 837 | US / Google | yes | ultra-light planner |

**Not available:** `mistral:7b-instruct-v0.3` (manifest missing on Ollama library — use `mistral:7b` instead).

## Skip (wrong tier for 6GB)

| tag | reason | origin |
|-----|--------|--------|
| `gemma3:12b` | ~7.3 GiB Q4 minimum | US / Google |
| `llama3.1:8b` | marginal + KV | US / Meta |
| `qwen3-coder:30b` | upstream default; OOM | CN / Alibaba |
| `llama3.3:70b` | OOM | US / Meta |

## VRAM smoke procedure (per tag)

```bash
ollama run <tag> "reply OK" --verbose
curl -s http://127.0.0.1:11434/api/ps
nvidia-smi --query-gpu=memory.used --format=csv,noheader
```

## RAG bake-off notes

- Production default: `OLLAMA_RAG_ENABLED=1` via `build_spl_rag_context()` (includes `spl_gold_standard_queries.md`).
- Phase 1 ranking: **RAG-on** primary; vanilla + `model-rag-ab` lift for top finalists.
- Before RAG eval: `make env-profile-refresh`.
