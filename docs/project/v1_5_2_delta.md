# v1.5.2 Release Highlights

This document summarizes operator-facing and engineering changes in `v1.5.2` compared with `v1.5.1`.

## Why This Release Matters

`v1.5.2` adds a **repeatable SPL quality program** for Splunk platform and data-domain workloads, hardens the **multi-model writer path**, improves **Docker deploy reliability**, and ships **lab-data-backed benchmarks** so teams can measure SPL accuracy per domain—not just on a single pilot corpus.

## Headline Changes

### 1. Internal & Linux SPL benchmark programs

New oracle harnesses with discover → cards → offline gate → live template → live multimodel flows:

| Program | Oracle corpus | Makefile entry points |
|---------|---------------|------------------------|
| Internal indexes | `benchmarks/internal_spl_oracles.json` (10 cases) | `make internal-spl-accuracy`, `make internal-spl-accuracy-multimodel` |
| Linux data domain | `benchmarks/linux_spl_oracles.json` (10 cases) | `make linux-spl-accuracy`, `make linux-spl-accuracy-multimodel` |

Both are wired into `make check` (offline gates). Docs: [`internal_spl_benchmark.md`](internal_spl_benchmark.md), [`linux_spl_benchmark.md`](linux_spl_benchmark.md).

**Lab results (Aug 2026):** internal and linux oracle programs at **10/10 template** and **10/10 multimodel** on the local lab.

### 2. Ten-domain SPL learning loop

Long-horizon autonomous benchmark runner for **10 data domains** (internal, linux, operational, linux_auth, web_access, windows_auth, windows_sysmon, stream_dns, aws_cloudtrail, o365_management):

```bash
make ten-domain-learning-loop MAX_HOURS=12 SKIP_BOOTSTRAP=1
```

- Bootstraps **production-shaped lab ingest** (`make lab-data-expanded-bootstrap`) when needed
- Iterates benchmark → lab-data refresh → multimodel → fix dispatch
- State: `artifacts/spl_autonomy/ten_domain_loop/final_summary.json`

**Latest run:** **7/10 domains ≥90%** (internal, linux, operational, linux_auth, stream_dns, aws, o365 green; Windows/web clusters still open).

### 3. SPL engine fixes (writer path + grounding)

- **Template bypass ordering** in `langgraph_multi_model_soc.py` — deterministic/template intents run before analytical LLM plans that could emit invalid `stats | table` shapes
- **Intent field contracts** reject stats+table combinations for table-evidence intents; require `| table` for Linux table intents
- **Domain oracle short-circuit** for internal/Linux platform intents (`spl_domain_knowledge.py`)
- **Operational harness fairness** — skip inconclusive profile checks when canonical rows are empty; suppress count drift when entity recall is full
- **Environment profile** — `PYTHON_BIN` fallback in Makefile so Docker sidecar and host `.venv` both run benchmark targets

### 4. MCP chat pipeline router

Deterministic vs LLM-assisted MCP chat routing with compare tooling:

- `scripts/mcp_pipeline_router.py`, `scripts/mcp_deterministic_routing.py`
- `make` targets and tests under `scripts/tests/test_mcp_pipeline_router.py`

### 5. Docker deploy contract

- `scripts/docker_deploy.py` + `make docker-deploy-*` contract tests
- Skill: `.cursor/skills/agtsmith-docker-build/` — rebuild/restart sidecar on `:8787` with verified build id
- `docker-compose.deploy.nvidia.yml` optional GPU metrics overlay
- Host `.venv` for CI/benchmarks; **Docker for runtime UI** (not `make ui-dev`)

### 6. Saved query library & domain embedding RAG

- Saved investigation queries API and library (`scripts/saved_query_library.py`)
- Domain/sourcetype embedding index (`scripts/domain_embedding_retrieval.py`, `scripts/build_domain_embedding_index.py`)

### 7. Splunk app wrapper (fork)

Native Splunk app packaging under `splunk_app/agent_smith/` for Splunk Web embedding (parallel to Docker sidecar). Install: `make splunk-app-install-local`.

### 8. Operational SPL accuracy gate

- `benchmarks/operational_spl_accuracy.json` expanded to **10 cases**
- `make operational-spl-accuracy-offline` as standalone target (also in `make check`)
- Latest lab multimodel: **9–10/10** depending on profile scoring edge cases

## Benchmark & quality artifacts

| Artifact | Path |
|----------|------|
| Internal latest | `artifacts/spl_autonomy/internal_benchmark/latest.json` |
| Linux latest | `artifacts/spl_autonomy/linux_benchmark/latest.json` |
| Operational latest | `artifacts/benchmark/operational_spl_accuracy/latest.json` |
| Live domain | `artifacts/spl_autonomy/live_benchmark/*/report.json` |
| Ten-domain loop | `artifacts/spl_autonomy/ten_domain_loop/final_summary.json` |
| Improvement logs | `artifacts/spl_autonomy/*/improvement_log.json` |

Phase 3 expansion (deferred): [`internal_spl_phase3.md`](internal_spl_phase3.md).

## Dependencies

No new pip packages required beyond existing `requirements-docker.txt`. Notable runtime expectations:

- **Python 3.12** (Docker sidecar and recommended host `.venv`)
- **Docker Compose** for `:8787` deploy stack
- **Ollama** with v1.5.1 model stack (Ministral planner, Granite writer, Gemma peers, Foundation-Sec review)
- **Splunk 9.x** with MCP enabled for live benchmarks
- **Playwright + Chromium** for `make screenshots SCREENSHOT_VERSION=v1.5.2`

## Upgrade notes

1. Pull `main` at tag **`v1.5.2`**
2. Rebuild sidecar: `.cursor/skills/agtsmith-docker-build/scripts/deploy.sh`
3. Refresh profile: `make env-profile-refresh`
4. Optional quality sign-off: `make phase2-automation` or `make ten-domain-learning-loop`
5. Splunk app (if used): `make splunk-app-install-local` and hard-refresh Splunk Web

## Known gaps (v1.5.2)

- **Windows auth / web paraphrase** live-domain clusters remain below 90% in ten-domain loop—needs targeted writer/grounding fixes, not more lab ingest alone
- **`env-profile-check`** Makefile may need `ENV_PROFILE_MAX_AGE_MINUTES` exported when invoked from automation scripts
- SPL Quality Tracker is **host-side only** (`make spl-quality-tracker` on `:8791`), not bundled in the Docker sidecar

## Related docs

- [CHANGELOG.md](../../CHANGELOG.md)
- [Initial Setup Guide](../runbooks/initial_setup.md)
- [Local Splunk Dev](../runbooks/local_splunk_dev.md)
- [Screenshot capture](../runbooks/screenshot_capture.md)
