# A.G.E.N.T. Smith

A.G.E.N.T. Smith (Autonomous Guardrail-Enforced Networked Tasker) is a Splunk-centric agentic SOC analyst augment for TDI today and TDIR over time. It accepts a natural-language investigation question, routes it through guarded multi-agent reasoning, validates the selected Splunk MCP action deterministically, retrieves evidence read-only, and returns an analyst-facing result with visible query, evidence, and decision trace.

This project is intentionally built as analyst augmentation, not blind autonomy. The controller enforces bounded execution, fail-closed guardrails, evidence-driven reasoning, and validation before any tool can touch Splunk.

This repository is prepared to publish as a first-run blank deployment baseline: the public tree should ship with example configuration only, no committed live runtime secrets, and no committed environment-specific artifacts.

## Two-Model SPL Pipeline
A.G.E.N.T. Smith now supports an explicit two-model SPL path:

1. `Planner`
   - default: `hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M`
   - interprets analyst intent and builds a structured search plan
2. `SPL Writer`
   - default: `deepseek-coder-v2:lite`
   - converts the structured plan into bounded read-only SPL
3. `Security Reviewer`
   - default: Qwen
   - critiques the writer output before deterministic validation

Deterministic policy and environment validation still decide what can touch Splunk.
When the reviewer cleanly approves the writer output, the controller can skip peer-review adjudication and proceed directly to deterministic validation.

An optional small-model helper on an edge device can be enabled in Configuration for:
- low-cost question routing
- cross-platform split-query detection
- confidence or escalation hints

That edge helper should not replace the primary planner/writer/reviewer path on the main inference host.
When left disabled, the primary inference host continues to handle the full pipeline alone.

## What Is In Scope
- Detect, Triage, and Investigate workflows
- Splunk MCP-backed read-only retrieval
- Multi-model reviewer pipeline
- Bounded agentic continuation with one automatic follow-up and analyst approval for anything deeper
- Environment-aware SPL guidance using indexes, sourcetypes, known fields, and curated local RAG
- Host runtime and Docker deployment runtime

## What Is Not In Scope Yet
- Autonomous response or recovery
- SOAR execution
- Enterprise IAM or production secret management
- HA / SLA hardening

## Runtime Modes
1. Host runtime
```bash
make dev
```

2. Docker wrapper
This runs the app from the local working tree.
```bash
make docker-build
make docker-up
```

3. Docker deployment image
This is the portable runtime path.
```bash
make docker-deploy-build
make docker-deploy-up
```
If the host user is not UID/GID `1000`, set:
```bash
export AGENTCHAIN_UID=$(id -u)
export AGENTCHAIN_GID=$(id -g)
```

## First-Time Setup
The primary operator path is now Docker-first:

1. Launch the deployment container.
2. Open `http://<host-ip>:8787/login`.
3. Complete the first-run login bootstrap if prompted.
4. Open `Control Center`.
5. Follow the Initial Setup Guide from the Configuration page.
6. Open `LangGraph Graph` if you want the live workflow view for the current controller topology.
7. Validate Ollama, Splunk Base, and Splunk MCP.
8. Pull and assign any missing models.
9. Open `Users` if you want to add more operators after first-run setup.
10. Run `Refresh Data Domains` once and let the UI complete the initial environment-aware build automatically.
11. Run the first investigation.

Docker deployment note:
- the deploy image starts with its own clean artifact volume
- the deploy image also starts with its own isolated config volume
- it does not read the host `config/ui.env` unless you explicitly change the compose file
- it does not inherit host-built Data Domains or personalization artifacts
- environment awareness is created inside the deploy runtime after MCP validation and the explicit refresh step

## Key Paths
- Investigation UI: `/investigation`
- MCP Chat: `/mcp`
- Configuration: `/configure`
- Architecture: `/architecture`
- Documentation: `/docs`
- Data Domains: `/environment`
  - host runtime: always available when the environment profile exists
  - Docker runtime: hidden until the initial environment profile has been built after MCP validation

## Configuration
Tracked example config:
- `config/ui.env.example`

Local operator config:
- `config/ui.env`

Public repository note:
- the repository should publish without a committed live `config/ui.env`
- a clean deployment should enter first-run setup and be configured through the web UI or a local copied example file

Runtime query audit:
- `artifacts/audit/query_runs.jsonl`

Role note:
- first-run setup now defaults the initial operator to `admin`
- `analyst` can investigate but cannot change runtime settings
- `ops` can manage runtime configuration, models, validation, and Data Domains
- `admin` includes all `ops` access plus user management and query audit visibility

Two-model role note:
- set `OLLAMA_MODEL_QUERY_PLANNER` to the reasoning / planning model
- set `OLLAMA_MODEL_QUERY_WRITER` to the coding-focused SPL writer
- the writer remains read-only and guarded by deterministic validation
- use `EDGE_LLM_ENABLED=1` only if you want to add an optional edge router / splitter
- if enabled, also set:
  - `EDGE_LLM_HOST`
  - `EDGE_LLM_MODEL`
  - `EDGE_LLM_ROLE=edge_router_splitter`
  - `EDGE_LLM_TIMEOUT_SEC`

Copy the example and edit for the active environment:
```bash
cp config/ui.env.example config/ui.env
```

## SPL Hardening Loop
Use the current environment to harden SPL behavior before sharing the project.

Run:
```bash
make spl-hardening-benchmark
```

Target a specific family or case when iterating:
```bash
python3 scripts/run_spl_hardening_benchmark.py --family linux_auth_failures
python3 scripts/run_spl_hardening_benchmark.py --case-id windows_failed_logons_24h
```

This executes a benchmark corpus through the current routing/query-generation path,
runs the resulting searches through Splunk MCP, and writes:
- `artifacts/benchmark/spl_hardening_benchmark_latest.json`
- `artifacts/benchmark/spl_hardening_benchmark_latest.md`
- `artifacts/benchmark/spl_hardening_failures_latest.jsonl`

Those artifacts are intended for iterative tuning of templates, validators, and RAG
against real data instead of generic assumptions.

Filtered runs also write scoped latest artifacts such as:
- `artifacts/benchmark/spl_hardening_benchmark_latest_family_linux_auth_failures.json`
- `artifacts/benchmark/spl_hardening_benchmark_latest_case_windows_failed_logons_24h.json`

## Artifacts
Generated runtime outputs are written under:
- `artifacts/`

These are intentionally runtime-only and should not be treated as source documentation.

## Docs Reading Order
1. `docs/whitepapers/project_one_page_white_paper.md`
2. `docs/whitepapers/technical_deep_dive.md`
3. `docs/architecture/two_model_spl_pipeline.md`
4. `docs/architecture/system_design.md`
5. `docs/runbooks/initial_setup.md`
6. `docs/runbooks/health_check.md`

## Two-Model Configuration
Default local role assignments for the two-model path:

```bash
export OLLAMA_MODEL_QUERY_PLANNER="hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
export OLLAMA_MODEL_QUERY_WRITER="deepseek-coder-v2:lite"
export OLLAMA_MODEL_SECURITY_REVIEWER="hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
export OLLAMA_MODEL_EVIDENCE_REVIEWER="hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
export OLLAMA_MODEL_QUERY_REPAIR="deepseek-coder-v2:lite"
```

Pull the default writer locally:

```bash
ollama pull deepseek-coder-v2:lite
```

## BOTSv3 Benchmark Track
BOTSv3 is treated as a separate benchmark environment, not as the default runtime
behavior for SPL generation. Because the BOTSv3 timestamps are from August 2018,
the benchmark cases in `benchmarks/spl_cases_botsv3.json` use explicit all-time
queries (`earliest_time=0`) only when the question explicitly says `all time` or
`full BOTSv3 dataset`.

Run it with:

```bash
make spl-hardening-benchmark-botsv3
```

This keeps the normal writer grounded in present-day/default time windows while
still letting the project validate against a public historical Splunk dataset.

For wider planner-backed coverage across the full observed BOTSv3 sourcetype
inventory, run:

```bash
make spl-hardening-benchmark-botsv3-inventory
```

LangGraph eval and topology optimization:

```bash
make langgraph-gold-build
make langgraph-eval-prompts
make langgraph-topology-eval
make langgraph-topology-optimize
```

That inventory pass uses explicit BOTSv3 sourcetype questions such as
`show an overview of sourcetype stream:smb by host and source` to verify that
the live planner can preserve exact sourcetype names and generate a safe
overview query even for families that are not yet hand-tuned with richer logic.


## License
This project is licensed under the Apache License 2.0. See `LICENSE`.
