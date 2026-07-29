# Final Model Bake-off Results (RTX 1000 Ada — 6141 MiB)

Completed 2026-07-22. **Origin is disclosure only.**

## Standard test queries (5 prompts, RAG on + off)

| ID | Prompt |
|----|--------|
| failed_login | Write a read-only Splunk SPL query for failed login activity in the last 24 hours. |
| linux_auth | Write a read-only Splunk SPL query for Linux authentication failures in index=linux over last 24 hours. |
| linux_priv_esc | Write a read-only Splunk SPL query for failed sudo or su activity in Linux logs over last 24 hours. |
| apache_top_ips | Write a read-only Splunk SPL query for top client IPs in index=linux sourcetype=access_combined over last 24 hours. |
| apache_404 | Write a read-only Splunk SPL query for 404 spikes in index=linux sourcetype=access_combined over last 24 hours. |

Scoring: rule-based 0–100 (search prefix, required terms, time bounds, row_limit, no forbidden ops).  
RAG-on uses full `build_spl_rag_context()` (gold SPL, env profile, skillpack, playbook).

## Final offline rankings (RAG avg — primary sort)

| Rank | Model | Origin | RAG | Vanilla | Lift | VRAM MiB | MCP hardening |
|------|-------|--------|-----|---------|------|----------|---------------|
| 1 | `granite4:3b` | US / IBM | **94.4** | 85.8 | +8.6 | ~2510 | 94.83 / 100% |
| 2 | `qwen2.5:7b` | CN / Alibaba | 84.0 | 87.8 | -3.8 | ~4637 | 94.83 / 100% |
| 3 | `qwen2.5:3b` | CN / Alibaba | 79.8 | 75.2 | +4.6 | ~2059 | — |
| 4 | `gemma3:4b` | US / Google | 79.8 | 83.2 | -3.4 | ~3756 | — |
| 5 | `deepseek-coder-v2:lite` | CN / DeepSeek | 75.8 | 67.8 | +8.0 | ~4586 | 94.83 / 100% |
| 6 | `qwen3:8b` | CN / Alibaba | 72.0 | 88.8 | -16.8 | ~4530 | — |
| 7 | `llama3.2:3b` | US / Meta | 66.4 | 67.0 | -0.6 | ~2560 | — |
| 8 | `codegemma:7b` | US / Google | 66.4 | 84.2 | -17.8 | ~4570 | — |
| 9 | `qwen2.5-coder:3b` | CN / Alibaba | 66.0 | 70.4 | -4.4 | ~2059 | — |
| 10 | `phi4-mini` | US / Microsoft | 62.4 | 59.2 | +3.2 | ~2945 | — |
| 11 | `qwen2.5-coder:7b` | CN / Alibaba | 61.4 | 77.4 | -16.0 | ~4637 | 94.83 / 100% |
| 12 | `mistral:7b` | FR / Mistral AI | 54.4 | 30.0 | +24.4 | ~4586 | — |
| 13 | `qwen2.5-coder:1.5b` | CN / Alibaba | 52.4 | 78.8 | -26.4 | ~1112 | — |
| 14–20 | smaller / phi / gemma1b / codegemma2b | various | ≤51 | — | — | — | — |
| — | `qwen3:30b-a3b` | CN / Alibaba | **0.0** | 24.0 | -24.0 | ~4519 | **94.83 / 100%** |

**Note:** `qwen3:30b-a3b` (MoE, ~3B active) fails isolated JSON writer eval but passes full LangGraph MCP hardening — use as **planner**, not writer.

## Not tested locally

| Model | Reason |
|-------|--------|
| Kimi K2 / K2.5 / K2.6 | No local Ollama tags (`kimi-k2`, `moonshotai/kimi`, `kimi-vl` → manifest not found); `:cloud` only on this lab |
| `qwen3-coder:480b-cloud` | Cloud-only |
| `gpt-oss:20b` | Pulled successfully; 14 GB weights, ~67% CPU / ~33% GPU on 6 GB VRAM — too slow for bake-off tier |

Artifact: `artifacts/model_eval/bakeoff_final/spl_writer_eval_latest.json`

## Planner bake-off (planner_node only — 66 cases)

Completed 2026-07-23 (13/14 new models; `qwen3:30b` skipped at case 1/66 after user pause).  
Scoring: rule-based avg 0–100 on planner JSON output; intent-match rate; median latency.  
Promotion threshold vs `granite3-moe:3b` baseline (56.2 avg, 100% intent, 7073 ms): avg ≥59, intent ≥98%, median ≤15 s.  
Artifacts: `artifacts/model_eval/planner_bakeoff/planner_eval_latest.json`, `planner_eval_latest.md`, `run_full.log`.

| Rank | Model | Origin | Avg | Intent % | Median ms |
|------|-------|--------|-----|----------|-----------|
| 1 | `qwen3:30b-a3b` | CN / Alibaba | 60.21 | 98.48 | 180243 |
| 2 | `hf.co/EnlistedGhost/Ministral-3-3B-Reasoning-2512-GGUF:Q5_K_M` | FR / Mistral AI | 59.68 | 100.0 | 2699 |
| 3 | `phi4-mini-reasoning` | US / Microsoft | 59.68 | 100.0 | 10947 |
| 4 | `qwen3:4b` | CN / Alibaba | 58.17 | 100.0 | 90263 |
| 5 | `hf.co/bartowski/functionary-small-v3.2-GGUF:Q4_K_M` | unknown | 57.82 | 96.97 | 16792 |
| 6 | `granite3-moe:3b` | US / IBM | 56.2 | 100.0 | 7073 |
| 7 | `alibayram/smollm3` | unknown | 55.79 | 98.48 | 4687 |
| 8 | `phi4-mini` | US / Microsoft | 55.76 | 100.0 | 5670 |
| 9 | `ministral-3:3b` | FR / Mistral AI | 55.36 | 100.0 | 8288 |
| 10 | `gemma3:4b` | US / Google | 55.14 | 100.0 | 9755 |
| 11 | `nemotron-mini:4b-instruct-q4_K_M` | US / NVIDIA | 54.67 | 93.94 | 5008 |
| 12 | `devstral:24b` | FR / Mistral AI | 53.5 | 100.0 | 98203 |
| 13 | `phi4-mini:3.8b-q4_K_M` | US / Microsoft | 53.47 | 100.0 | 6050 |
| 14 | `gemma4:e2b-it-qat` | US / Google | 53.15 | 95.45 | 6978 |
| 15 | `granite3-moe:1b` | US / IBM | 52.77 | 90.91 | 2793 |
| 16 | `qwen2.5:7b` | CN / Alibaba | 51.71 | 95.45 | 8263 |
| 17 | `mistral-nemo:12b` | FR / Mistral AI | 51.7 | 93.94 | 28432 |
| 18 | `mistral:7b` | FR / Mistral AI | 51.05 | 89.39 | 11752 |
| 19 | `ibm/granite4.1:3b-q6_K` | US / IBM | 49.98 | 90.91 | 5792 |
| 20 | `allenporter/xlam:1b` | unknown | 49.48 | 77.27 | 1159 |
| 21 | `granite4:3b` | US / IBM | 49.36 | 87.88 | 5065 |
| 22 | `qwen3:8b` | CN / Alibaba | 47.8 | 86.36 | 20603 |
| 23 | `ibm/granite4.1:8b` | US / IBM | 47.58 | 90.91 | 21803 |
| 24 | `llama3.2:3b` | US / Meta | 43.32 | 86.36 | 3637 |

**Bake-off artifact winner:** `hf.co/EnlistedGhost/Ministral-3-3B-Reasoning-2512-GGUF:Q5_K_M` — first US/EU model meeting promotion threshold (59.68 avg, 100% intent, 2.7 s median). Top scorer `qwen3:30b-a3b` fails latency gate (180 s median).

**Production default (v1.5.1):** `TechyShishy/ministral-3:3b-reasoning-2512-q4_K_M` — same Ministral-3B-Reasoning family; the EnlistedGhost HF GGUF tag crashes Ollama on the lab host. Fallback: `ministral-3:3b`.

## Promoted LangGraph stack (`config/ui.env` — v1.5.1 US-primary)

| Role | Model | Origin | Why |
|------|-------|--------|-----|
| **Planner** | `TechyShishy/ministral-3:3b-reasoning-2512-q4_K_M` | FR / Mistral AI | Bake-off winner class (Ministral-3B-Reasoning); fallback `ministral-3:3b` |
| **Writer + Repair** | `granite4:3b` | US / IBM | Best RAG (94.4), beats `deepseek-coder-v2:lite`, ~1 s gen |
| **Peer reviewers** | `gemma3:4b` | US / Google | US peer diversity; 79.8 offline RAG |
| **Review / Summary** | Foundation-Sec-8B Q8 | US / Foundation | Unchanged |

**Legacy v1.4.x rollback:** planner/peers `Qwen3-30B-A3B` + writer `deepseek-coder-v2:lite` (see `LEGACY_V14_*` in `scripts/runtime_config.py`).
