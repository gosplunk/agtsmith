# Model Strategy

## v1.5.x US-Primary Stack

The default profile shifts from Qwen + DeepSeek (`v1.4.x`) to US-origin Ollama tags validated on the RTX 1000 Ada bake-off while holding **94.83 / 100%** MCP hardening.

### Planner Model
- Default: `TechyShishy/ministral-3:3b-reasoning-2512-q4_K_M` (FR / Mistral AI — Ministral-3B-Reasoning)
- Fallback: `ministral-3:3b` via `OLLAMA_MODEL_QUERY_PLANNER_FALLBACK`
- Bake-off artifact winner: `hf.co/EnlistedGhost/Ministral-3-3B-Reasoning-2512-GGUF:Q5_K_M` (EnlistedGhost GGUF crashes Ollama on the lab host)

### SPL Writer and Repair
- Default: `granite4:3b` (US / IBM)
- Responsibilities: primary SPL writer, query repair fallback writer
- Replaces `deepseek-coder-v2:lite` (offline RAG **94.4 vs 75.8**, full GPU, ~1 s gen vs ~6 s)

### Peer Reviewers
- Default: `gemma3:4b` (US / Google) for both peer slots
- Responsibilities: adjudicate writer vs security reviewer when queries are not cleanly approved

### Security Review and Summary Model
- Default: `hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest` (US / Foundation)
- Responsibilities: security reviewer, evidence reviewer, final summary, agentic summary, continuation reviewer

### Optional Edge Router Model
- Example fit: a small on-device classifier (optional)
- Configuration keys: `EDGE_LLM_ENABLED`, `EDGE_LLM_HOST`, `EDGE_LLM_MODEL`, `EDGE_LLM_ROLE`, `EDGE_LLM_TIMEOUT_SEC`

## Role Mapping
- Planner: `OLLAMA_MODEL_QUERY_PLANNER`
- SPL Writer: `OLLAMA_MODEL_QUERY_WRITER`
- Security Reviewer: `OLLAMA_MODEL_SECURITY_REVIEWER`
- Evidence Reviewer: `OLLAMA_MODEL_EVIDENCE_REVIEWER`
- Peer Reviewer 1: `OLLAMA_MODEL_PEER_REVIEWER`
- Peer Reviewer 2: `OLLAMA_MODEL_PEER_REVIEWER_2`
- Final Summary: `OLLAMA_MODEL_FINAL_SUMMARY`
- Query Repair: `OLLAMA_MODEL_QUERY_REPAIR`

## Runtime Flow
1. Optional edge router can classify or split the question before main planning.
2. Planner interprets the analyst question and emits a structured search plan.
3. SPL Writer converts that plan into bounded read-only SPL.
4. Security Reviewer critiques the generated SPL against the plan.
5. Peer reviewers adjudicate writer vs reviewer candidate only when needed.
6. Deterministic validation enforces read-only safety and environment binding.
7. Splunk executes only approved plans.
8. Evidence review, continuation review, and final summary convert execution results into analyst-facing output.

## Recommended Current Profile (v1.5.1)
```bash
export OLLAMA_MODEL_QUERY_PLANNER="TechyShishy/ministral-3:3b-reasoning-2512-q4_K_M"
export OLLAMA_MODEL_QUERY_PLANNER_FALLBACK="ministral-3:3b"
export OLLAMA_MODEL_QUERY_WRITER="granite4:3b"
export OLLAMA_MODEL_QUERY_REPAIR="granite4:3b"
export OLLAMA_MODEL_SECURITY_REVIEWER="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
export OLLAMA_MODEL_EVIDENCE_REVIEWER="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
export OLLAMA_MODEL_PEER_REVIEWER="gemma3:4b"
export OLLAMA_MODEL_PEER_REVIEWER_2="gemma3:4b"
export OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
export OLLAMA_MODEL_FINAL_SUMMARY="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
export EDGE_LLM_ENABLED="0"
```

Pull defaults:
```bash
ollama pull TechyShishy/ministral-3:3b-reasoning-2512-q4_K_M
ollama pull ministral-3:3b
ollama pull granite4:3b
ollama pull gemma3:4b
ollama pull hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest
```

## Legacy v1.4.x Profile (rollback)
```bash
export OLLAMA_MODEL_QUERY_PLANNER="hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
export OLLAMA_MODEL_QUERY_WRITER="deepseek-coder-v2:lite"
export OLLAMA_MODEL_QUERY_REPAIR="deepseek-coder-v2:lite"
export OLLAMA_MODEL_PEER_REVIEWER="hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
export OLLAMA_MODEL_PEER_REVIEWER_2="hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
```

See `scripts/runtime_config.py` (`LEGACY_V14_*` constants).

## Offline Optimization Flow
1. Build a gold corpus from seed questions using the current workflow.
2. Generate prompt variants from those gold cases.
3. Run topology permutations against the eval prompt set.
4. Score support rate, intent match, result quality, and latency.
5. Keep only topology changes that hold up empirically.

Bake-off artifacts: `docs/runbooks/laptop_model_profile.md`, `artifacts/model_eval/bakeoff_final/`.

## Operational Notes
- Keep `OLLAMA_RAG_ENABLED=1` (default) so writers see environment profile + gold SPL context.
- Run `make env-profile-refresh` before benchmarks or after Splunk index layout changes.
- The writer remains bounded by deterministic policy and environment validation.
- BOTSv3 can improve writer habits and gold SPL examples, but it must not define production defaults.
