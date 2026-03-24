# SPL Quality Pass Runbook

## Purpose
- Validate SPL-writing quality against your live Splunk dataset.
- Compare SOC analyst baseline SPL vs model-written SPL.
- Detect and remediate index/sourcetype drift before demo use.

## Command
```bash
cd ~/agtsmith
make model-spl-quality-deep
```

## Output Artifacts
- `artifacts/model_eval/deep_spl_quality_pass_latest.json`
- `artifacts/model_eval/deep_spl_quality_pass_latest.md`

## What It Tests
- Domains:
  - Windows authentication failures
  - Linux (`host=rpi5`) failed auth and failed sudo/su
  - Apache `access_combined` top clients and 404 spikes
  - Cross-domain failed-login coverage excluding internal indexes
- Modes:
  - vanilla model SPL
  - RAG-augmented model SPL
- Checks:
  - textual intent alignment
  - deterministic intent field-contract alignment
  - query policy compliance
  - environment profile validation
  - live Splunk execution and row return

## Intent Field-Contract Gate (New)
- The multi-model execution path now enforces a deterministic intent contract before running SPL.
- If a query is policy-safe but misses required intent fields (for example Apache top-IP query without `clientip`), it is auto-repaired once, then re-validated.
- If contract still fails after repair, execution is blocked fail-closed.

Contract implementation:
- `scripts/intent_field_contracts.py`

## Current Recommendation (Latest Pass)
- Query-writer model:
  - `hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M`
- Rationale:
  - Highest RAG score on live cases
  - Lowest index/sourcetype hallucination rate after environment-binding hardening

## Recent Performance Snapshot (Post-Contract)
- Sample size: 3 representative investigations
- Average end-to-end wall runtime: ~48.6s
- Average validation stage runtime: ~2.7s
- Supported rate: 100%
- Auto-repair activation rate: 33% (Linux failed-login case in this sample)

## Troubleshooting
- If all rows are zero for Linux auth-failure cases:
  - This can be a true-negative (no failed auth in time window).
  - Run a volume pivot check:
  ```spl
  search index=linux host="rpi5" (sourcetype=auth.log OR sourcetype=auth-4 OR sourcetype=linux_secure)
  | stats count by sourcetype
  | sort - count
  ```
- If model picks wrong index for `access_combined`:
  - Refresh profile + skillpack:
  ```bash
  make env-profile-refresh
  ```
  - Re-run deep pass:
  ```bash
  make model-spl-quality-deep
  ```

## Operator Notes
- Lab-only workflow.
- Read-only SPL only in this phase.
- SOAR integration is intentionally out of scope for now.
