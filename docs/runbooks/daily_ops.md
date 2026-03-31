# Daily Ops Checklist (Lab)

Use this checklist for routine daily operation in the sandbox.

For runtime/operator checks in the web UI, also review:
- `Control Center -> Users`
- `artifacts/audit/query_runs.jsonl`

## 1) Fast Status Check (No Live Queries)
```bash
make status
```

Expected:
- latest artifact status is `PASS`
- no unexpected per-intent drift

## 2) Full Validation + Packaging
```bash
make all
```

This runs:
1. `make check`
2. `make status`
3. `make snapshot`

`make check` now validates:
- wrapper argument parsing behavior
- query template safety rules
- query policy pass/fail regression cases
- deterministic core-TDIR enrichment logic (`tdir_case`)

Expected:
- all stages complete without errors
- new timestamped snapshot appears in `docs/logs/operator_snapshot/history/`

## 3) Wrapper Quick Mode (When You Need Fast Confirmation)
```bash
./scripts/run_lab_checks.sh --quick --refresh-status --no-snapshot
```

Expected:
- artifact-only status output
- `latest_status.json` refreshed

## 4) Wrapper Full Mode (When You Need Fresh Live Validation)
```bash
./scripts/run_lab_checks.sh --max-abs-delta 0 --snapshot --refresh-status
```

Expected:
- preflight/regression/trend checks run live
- optional snapshot bundle written

## 5) Review Output Artifacts
- `docs/logs/latest_status.json`
- `docs/logs/template_regression_latest.json`
- `docs/logs/template_regression_history/`
- `docs/logs/operator_snapshot/latest/`
- `docs/logs/operator_snapshot/history/`
- `docs/logs/langgraph_runs/`

LangGraph run index command:
```bash
python scripts/summarize_langgraph_runs.py --limit 10
```
LangGraph run index CSV export:
```bash
python scripts/summarize_langgraph_runs.py --limit 10 --csv-out docs/logs/langgraph_runs/latest_index.csv
```
Make target shortcut:
```bash
make langgraph-status
```
`latest_index.csv` includes `selected_tool` so tool-routing outcomes are visible per run.

LangGraph policy status summary:
```bash
make langgraph-policy-status
```
Generated outputs:
- `docs/logs/langgraph_runs/latest_policy_summary.json`
- `docs/logs/langgraph_runs/latest_policy_rows.csv`

LangGraph policy summary freshness check:
```bash
make langgraph-policy-freshness
make langgraph-policy-freshness POLICY_SUMMARY_MAX_AGE_MINUTES=60
```

LangGraph policy trend freshness check:
```bash
make langgraph-policy-trend-freshness
make langgraph-policy-trend-freshness POLICY_TREND_MAX_AGE_MINUTES=1440
```

LangGraph policy trend anomaly check:
```bash
make langgraph-policy-trend-anomaly
make langgraph-policy-trend-anomaly POLICY_MAX_ABS_DELTA=2
```

LangGraph policy/status ops meta-target (includes docs consistency check):
```bash
make langgraph-ops
make langgraph-ops POLICY_MAX_ABS_DELTA=2
make langgraph-ops POLICY_MAX_ABS_DELTA=2 POLICY_SUMMARY_MAX_AGE_MINUTES=60 POLICY_TREND_MAX_AGE_MINUTES=1440
```
Optional docs consistency check:
```bash
make langgraph-docs-check
```
Optional artifact presence check:
```bash
make langgraph-artifacts-check
```
Threshold visibility:
```bash
make langgraph-thresholds
```
Strict preset:
```bash
make langgraph-ops-strict
```

LangGraph policy telemetry quick reference (recommended order):
```bash
# 1) Refresh policy summary from recent runs
make langgraph-policy-status
# 2) Snapshot the summary into history
make langgraph-policy-snapshot
# 3) Rebuild trend CSV from history snapshots
make langgraph-policy-trend
# 4) Check freshness gates
make langgraph-policy-freshness
make langgraph-policy-freshness POLICY_SUMMARY_MAX_AGE_MINUTES=60
make langgraph-policy-trend-freshness
# 5) Check for abnormal counter jumps
make langgraph-policy-trend-anomaly POLICY_MAX_ABS_DELTA=2
# 6) One-command equivalent
make langgraph-ops POLICY_MAX_ABS_DELTA=2
```

If `make langgraph-policy-trend-anomaly` fails:
1. Rebuild policy artifacts to ensure current inputs:
```bash
make langgraph-policy-status
make langgraph-policy-snapshot
make langgraph-policy-trend
```
2. Inspect latest trend rows:
```bash
sed -n '1,40p' docs/logs/langgraph_policy_summary_history/latest_trend.csv
```
3. Confirm whether deltas are expected (for example from intentional policy demos).
4. If expected and temporary, rerun with a tuned threshold:
```bash
make langgraph-policy-trend-anomaly POLICY_MAX_ABS_DELTA=8
```
5. If unexpected, keep default threshold and record findings in `docs/build_log.md`.

LangGraph run target:
```bash
make langgraph-run
make langgraph-run QUESTION="Show failed login activity in the last 24 hours" WRITE_ARTIFACT=1
```

LangGraph demo target (supported + blocked):
```bash
make langgraph-demo
```

LangGraph policy demo target (policy pass + policy fail):
```bash
make langgraph-policy-demo
```

LangGraph tool-routing regression/demo:
```bash
make langgraph-tool-routing-check
make langgraph-session-check
make langgraph-tool-demo
make langgraph-metadata-demo
make langgraph-chain-demo
make langgraph-session-demo
make langgraph-demo-ready
```
`langgraph-tool-demo` now exercises:
- `splunk_run_query`
- `splunk_get_indexes`
- `splunk_get_metadata`
- `splunk_get_info`
`langgraph-chain-demo` exercises:
- `splunk_get_indexes` -> `splunk_get_metadata` two-step chain
`langgraph-session-demo` exercises:
- shared `--session-id` memory across two sequential questions
`langgraph-demo-ready` runs:
- strict telemetry checks plus the full presentation demo chain
Summary robustness:
- occasional model summary issues are auto-handled by deterministic fallback summaries.

Manual session memory example:
```bash
python scripts/langgraph_minimal_flow.py --session-id analyst_shift_a "Show failed login activity in the last 24 hours"
python scripts/langgraph_minimal_flow.py --session-id analyst_shift_a "Investigate top index with metadata drilldown"
```

LangGraph full workflow target:
```bash
make langgraph-all
make langgraph-all POLICY_MAX_ABS_DELTA=2 POLICY_SUMMARY_MAX_AGE_MINUTES=60 POLICY_TREND_MAX_AGE_MINUTES=1440
```
This runs the full demo + telemetry validation chain, including trend, freshness, anomaly, and docs checks.
Presentation runbook:
- `docs/runbooks/demo_walkthrough.md`

LangGraph quick workflow target (telemetry/docs only):
```bash
make langgraph-all-quick
make langgraph-all-quick POLICY_MAX_ABS_DELTA=2 POLICY_SUMMARY_MAX_AGE_MINUTES=60 POLICY_TREND_MAX_AGE_MINUTES=1440
```

Agentic investigation loop commands:
```bash
make agentic-check
make agentic-run QUESTION="Show failed login activity in the last 24 hours" AGENTIC_MAX_STEPS=3
make agentic-demo
make agentic-session-demo
make agentic-status
make agentic-case-report
make agentic-demo-ready
make model-show
make model-smoke
make dev
make tdir-core-tests
make multi-model-check
make multi-model-demo-ready
```
Artifacts:
- `artifacts/runs/agentic/`
- `docs/logs/agentic_runs/latest_index.csv`
- `docs/logs/agentic_case_report_latest.json`
- `docs/logs/agentic_case_report_latest.md`
- `docs/logs/multi_model_runs/`
- `docs/logs/multi_model_runs/latest_index.csv`

Model profile env vars (optional):
```bash
export OLLAMA_MODEL_QUERY_PLANNER="hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
export OLLAMA_MODEL_QUERY_WRITER="deepseek-coder-v2:lite"
export OLLAMA_MODEL_EVIDENCE_REVIEWER="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
export OLLAMA_MODEL_SECURITY_REVIEWER="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
export OLLAMA_MODEL_PEER_REVIEWER="hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
export OLLAMA_MODEL_PEER_REVIEWER_2="hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M"
export OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
export OLLAMA_MODEL_FINAL_SUMMARY="hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest"
make model-show
```
Deterministic SPL-writer model benchmark:
```bash
make model-spl-eval
```
RAG-vs-vanilla SPL benchmark:
```bash
make model-rag-ab MODEL='hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M' RUNS=2
```
Latest benchmark artifacts:
- `docs/logs/model_eval/spl_writer_eval_latest.json`
- `docs/logs/model_eval/spl_writer_eval_latest.md`
- `docs/logs/model_eval/rag_vs_vanilla_spl_latest.json`
- `docs/logs/model_eval/rag_vs_vanilla_spl_latest.md`

Local web UI:
```bash
make dev
# compatibility alias
make ui-dev
```
Open:
- `http://<server-ip>:8787`
- `http://<server-ip>:8787/docs` (documentation portal)
- `http://<server-ip>:8787/architecture` (standalone architecture graph + text summary)
- local fallback: `http://127.0.0.1:8787`
LAN auth:
- `http://<server-ip>:8787/login`
- credentials are loaded from `config/ui.env` (`SOC_UI_AUTH_*` variables)
Startup note:
- allow a few seconds for server startup before first request.
- `make dev` auto-kills existing listeners on `:8787` before launching to prevent bind conflicts.
- UI pipeline selector options:
  - `Two-Model SPL Flow` (planner -> SPL writer -> security reviewer -> optional peer review -> deterministic gate -> tool execution)
  - `Agentic Loop` (bounded iterative drilldown with one automatic deeper pass, then analyst approval for anything further)
  - `Ops -> Ollama Logs` (remote Windows SSE stream via local proxy endpoint)
- Documentation maintenance note:
  - the web docs portal reads directly from `docs/`; any doc updates automatically appear without extra UI work.

LangGraph optimization loop:
```bash
make langgraph-gold-build
make langgraph-eval-prompts
make langgraph-topology-eval
make langgraph-topology-optimize
```
Use this offline loop when you want to compare workflow layouts before changing the live default path.

RAG planner controls (optional):
```bash
export OLLAMA_RAG_ENABLED=1
export OLLAMA_RAG_MAX_CHARS=1600
```
Persistent runtime location used by `make dev`:
```bash
cat config/ui.env
```
Restart command:
```bash
pkill -f "scripts/web_ui_server.py .*--port 8787" || true
make dev
```
Validation tests:
```bash
make tdir-core-tests
```
Architecture reference:
- `docs/architecture/tdir_core_blueprint.md`

Starter cross-platform SOC questions:
- `Show failed login activity in the last 24 hours`
- `Show linux failed login activity in the last 24 hours`
- `Show failed sudo activity on linux in the last 24 hours`
- `Show top client IPs in apache access logs (access_combined) in the last 24 hours`
- `Show 404 spike behavior in apache access_combined logs in the last 24 hours`
- `Show suspicious user agents in apache access_combined logs in the last 24 hours`

Interpretation note:
- `rows_returned=0` means query execution succeeded but no events matched current data/time window.

Consolidated report target:
```bash
make docs-index
```
Generated outputs:
- `docs/logs/status_report.md`
- `docs/logs/status_report.json`

Freshness check target:
```bash
make report-freshness
```
Recommended refresh before freshness:
```bash
make refresh-reports
```

Daily operator meta-target:
```bash
make ops
```

## 6) If Something Fails
1. Check `README.md` troubleshooting section.
2. Check `docs/runbooks/health_check.md` failure-recovery commands.
3. Re-run failing command directly to isolate issue.

## 7) Weekly Hygiene
- Run once per week:
  - `docs/runbooks/weekly_maintenance.md`
