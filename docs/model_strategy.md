# Model Strategy

## Active Split-Role SPL Workflow

### Planner Model
- Default:
  - `hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M`
- Responsibilities:
  - planner
  - peer reviewer 1 when needed
  - peer reviewer 2 when needed

This model is used for higher-context reasoning where the system needs intent interpretation, search-strategy explanation, and adjudication between competing candidate plans.

### Security Review and Summary Model
- Default:
  - `hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest`
- Responsibilities:
  - security reviewer / critic
  - evidence reviewer
  - final summary
  - agentic summary
  - continuation reviewer

This model is used for security-oriented critique, evidence assessment, continuation judgment, and concise analyst-facing output.

### SPL Writer Model
- Default:
  - `deepseek-coder-v2:lite`
- Responsibilities:
  - primary SPL writer
  - query repair fallback writer

This model is used for code-like SPL composition. It should focus on:
- command ordering
- field handling
- `stats` / `eval` composition
- bounded, syntactically clean read-only SPL

### Optional Edge Router Model
- Example fit:
  - a small Qwen-class model on an edge device
- Responsibilities:
  - cheap intent pre-classification
  - cross-platform split-query hints
  - low-cost escalation or confidence hints

This role is optional and should stay narrow. It is not the primary SPL writer or final reviewer.
Configuration keys:
- `EDGE_LLM_ENABLED`
- `EDGE_LLM_HOST`
- `EDGE_LLM_MODEL`
- `EDGE_LLM_ROLE`
- `EDGE_LLM_TIMEOUT_SEC`

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
5. Peer reviewers adjudicate writer vs reviewer candidate only when the reviewer does not cleanly approve the query or materially changes it.
6. Deterministic validation enforces read-only safety and environment binding.
7. Splunk executes only approved plans.
8. Evidence review, continuation review, and final summary convert execution results into analyst-facing output.

## Offline Optimization Flow
The same runtime now has an offline eval harness used to improve the LangGraph layout without changing the live default path blindly:

1. Build a gold corpus from seed questions using the current workflow.
2. Generate prompt variants from those gold cases.
3. Run topology permutations against the eval prompt set.
4. Score support rate, intent match, result quality, and latency.
5. Keep only topology changes that hold up empirically.

This is where experimental decisions about reviewer, peer review, summary, and repair stages should be tested first.

## Recommended Current Profile
```bash
export OLLAMA_MODEL_QUERY_PLANNER="hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
export OLLAMA_MODEL_QUERY_WRITER="deepseek-coder-v2:lite"
export OLLAMA_MODEL_SECURITY_REVIEWER="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
export OLLAMA_MODEL_EVIDENCE_REVIEWER="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
export OLLAMA_MODEL_PEER_REVIEWER="hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
export OLLAMA_MODEL_PEER_REVIEWER_2="hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
export OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
export OLLAMA_MODEL_FINAL_SUMMARY="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
export OLLAMA_MODEL_QUERY_REPAIR="deepseek-coder-v2:lite"
export EDGE_LLM_ENABLED="0"
export EDGE_LLM_HOST=""
export EDGE_LLM_MODEL=""
export EDGE_LLM_ROLE="edge_router_splitter"
export EDGE_LLM_TIMEOUT_SEC="60"
```

## Local Commands
Pull the default writer:
```bash
ollama pull deepseek-coder-v2:lite
```

If you want a custom imported writer later, assign that imported model name to:
- `OLLAMA_MODEL_QUERY_WRITER`
- optionally `OLLAMA_MODEL_QUERY_REPAIR`

## Operational Notes
- Qwen should not be the primary final SPL generator unless the writer fails and the deterministic/template fallback takes over.
- The writer remains bounded by deterministic policy and environment validation.
- BOTSv3 can improve writer habits and gold SPL examples, but it must not define production defaults.
- The edge helper is an optional accelerator and classifier. If it is disabled, the primary inference host remains the full source of planning, writing, and review.
