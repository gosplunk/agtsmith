.PHONY: help check status snapshot all langgraph-status langgraph-policy-status langgraph-policy-snapshot langgraph-policy-trend langgraph-policy-freshness langgraph-policy-trend-freshness langgraph-policy-trend-anomaly langgraph-docs-check langgraph-artifacts-check langgraph-tool-routing-check langgraph-session-check langgraph-thresholds langgraph-ops langgraph-ops-strict langgraph-run langgraph-demo langgraph-policy-demo langgraph-tool-demo langgraph-metadata-demo langgraph-chain-demo langgraph-session-demo langgraph-demo-ready langgraph-all langgraph-all-quick langgraph-gold-build langgraph-eval-prompts langgraph-topology-eval langgraph-topology-optimize agentic-check agentic-run agentic-demo agentic-session-demo agentic-status agentic-case-report agentic-demo-ready multi-model-run multi-model-check multi-model-demo multi-model-status multi-model-demo-ready model-show model-smoke model-spl-eval model-rag-ab model-spl-quality-deep spl-hardening-benchmark spl-hardening-benchmark-botsv3 spl-hardening-benchmark-botsv3-inventory env-profile-build env-profile-check env-profile-refresh env-profile-tests env-profile-schedule-install env-profile-schedule-show sourcetype-research spl-skillpack-refresh dev ui-dev docker-build docker-up docker-down docker-logs docker-deploy-build docker-deploy-up docker-deploy-down docker-deploy-logs ollama-log-tests tdir-core-tests docs-index report-freshness refresh-reports ops prune-summary prune-snapshot prune-trend prune-freshness prune-dry-run prune-apply prune-ops

QUESTION ?= Show failed login activity in the last 24 hours
WRITE_ARTIFACT ?= 1
KEEP_REGRESSION ?= 100
KEEP_SNAPSHOTS ?= 50
KEEP_LANGGRAPH ?= 200
POLICY_MAX_ABS_DELTA ?= 5
POLICY_TREND_MAX_AGE_MINUTES ?= 10080
POLICY_SUMMARY_MAX_AGE_MINUTES ?= 180
AGENTIC_MAX_STEPS ?= 3
FOCUS_HOST ?=

help:
	@echo "Available targets:"
	@echo "  make check   # run wrapper parsing + template safety + query policy checks"
	@echo "  make status  # show artifact-only status + trend summary"
	@echo "  make snapshot # write operator snapshot bundle"
	@echo "  make all     # run check + status + snapshot"
	@echo "  make langgraph-status # summarize LangGraph runs + CSV export"
	@echo "  make langgraph-policy-status # summarize LangGraph policy outcomes + JSON/CSV export"
	@echo "  make langgraph-policy-snapshot # snapshot latest LangGraph policy summary into history"
	@echo "  make langgraph-policy-trend # summarize LangGraph policy history snapshots + CSV export"
	@echo "  make langgraph-policy-freshness # fail if LangGraph policy summary artifacts are stale"
	@echo "  make langgraph-policy-trend-freshness # fail if LangGraph policy trend CSV is stale"
	@echo "  make langgraph-policy-trend-anomaly # fail if LangGraph policy trend deltas exceed threshold"
	@echo "  make langgraph-docs-check # verify README and daily LangGraph telemetry docs stay aligned"
	@echo "  make langgraph-artifacts-check # verify required LangGraph telemetry artifacts exist"
	@echo "  make langgraph-tool-routing-check # verify tool selection rules"
	@echo "  make langgraph-session-check # verify session memory read/write helpers"
	@echo "  make langgraph-thresholds # print active LangGraph threshold values"
	@echo "  make langgraph-ops # refresh LangGraph status/policy summaries + trend + freshness + anomaly + tool/docs checks"
	@echo "  make langgraph-ops-strict # run langgraph-ops with stricter recommended thresholds"
	@echo "  make langgraph-run [QUESTION='...'] [WRITE_ARTIFACT=0|1]  # run minimal LangGraph flow"
	@echo "  make langgraph-demo # run supported + blocked LangGraph questions"
	@echo "  make langgraph-policy-demo # run policy-pass + policy-fail LangGraph questions"
	@echo "  make langgraph-tool-demo # run query/index/metadata/info tool demo questions"
	@echo "  make langgraph-metadata-demo # run metadata and splunk-info demo questions"
	@echo "  make langgraph-chain-demo # run two-step index->metadata drilldown chain demo"
	@echo "  make langgraph-session-demo # run two related questions with shared session context"
	@echo "  make langgraph-demo-ready # run full presentation-grade demo sequence + telemetry checks"
	@echo "  make langgraph-all # run langgraph-run + demos + status + policy trend/freshness/anomaly + docs checks"
	@echo "  make langgraph-all-quick # telemetry/docs-only variant of langgraph-all (no model-backed demos)"
	@echo "  make langgraph-gold-build # build reference gold corpus from seed questions via the live LangGraph pipeline"
	@echo "  make langgraph-eval-prompts # derive eval prompt variants from the latest gold corpus"
	@echo "  make langgraph-topology-eval # run topology experiments against the eval prompt set"
	@echo "  make langgraph-topology-optimize # print the current best topology experiment from the latest eval run"
	@echo "  make agentic-check # deterministic checks for agentic planner pivots"
	@echo "  make agentic-run [QUESTION='...'] [AGENTIC_MAX_STEPS=3] # run iterative agentic investigation loop"
	@echo "  make agentic-demo # run agentic failed-login + index-drilldown examples"
	@echo "  make agentic-session-demo # run two-step session continuity demo for agentic loop"
	@echo "  make agentic-status # summarize recent agentic run artifacts"
	@echo "  make agentic-case-report # build latest structured case report from agentic run artifact"
	@echo "  make agentic-demo-ready # run agentic checks + demos + status"
	@echo "  make multi-model-run [QUESTION='...'] # run planner->security-reviewer->peer-reviewer workflow"
	@echo "  make multi-model-check # automated regression check for multi-model workflow"
	@echo "  make multi-model-demo # run supported and blocked multi-model examples"
	@echo "  make multi-model-status # summarize multi-model run artifacts"
	@echo "  make multi-model-demo-ready # full multi-model regression + demo + status"
	@echo "  make model-show # print active primary/reasoning model env configuration"
	@echo "  make model-smoke # run connectivity smoke checks with active model env configuration"
	@echo "  make model-spl-eval # deterministic benchmark to choose best query-writer model for SPL"
	@echo "  make model-rag-ab [MODEL='...'] [RUNS=1] # A/B benchmark: vanilla vs RAG-augmented SPL writing"
	@echo "  make model-spl-quality-deep # deep live-dataset SPL quality pass (Windows/Linux/Apache)"
	@echo "  make spl-hardening-benchmark # MCP-backed benchmark suite against the current environment"
	@echo "  make spl-hardening-benchmark-botsv3 # separate BOTSv3 all-time benchmark suite"
	@echo "  make spl-hardening-benchmark-botsv3-inventory # planner-backed overview benchmark across the full BOTSv3 sourcetype inventory"
	@echo "  make env-profile-build [FOCUS_HOST=<linux-host>] # rebuild append-only environment profile from Splunk MCP (+ optional host focus)"
	@echo "  make env-profile-check # fail if environment profile is missing/stale"
	@echo "  make env-profile-refresh # build + freshness-check environment profile (full first-time field enrichment, then incremental maintenance)"
	@echo "  make env-profile-tests # run unit tests for environment profile parsing/validation"
	@echo "  make env-profile-schedule-install [INTERVAL_MIN=45] # install/update cron refresh every 30-60 min"
	@echo "  make env-profile-schedule-show # show current cron entry for profile refresh"
	@echo "  make sourcetype-research # regenerate docs/reference/sourcetype_research.md from latest profile"
	@echo "  make spl-skillpack-refresh # build artifacts/knowledge/spl_skillpack_latest.json"
	@echo "  make dev # canonical app launcher (same behavior as ui-dev)"
	@echo "  make ui-dev # run browser UI on all interfaces at http://<server-ip>:8787"
	@echo "  make docker-build # build portable Docker image around the current repo"
	@echo "  make docker-up [AGTSMITH_UI_PORT=8787] # run Dockerized UI with host repo mounted into /app"
	@echo "  make docker-down # stop/remove Dockerized UI container"
	@echo "  make docker-logs # tail Dockerized UI logs"
	@echo "  make docker-deploy-build # build self-contained deployment image with code/docs/artifacts baked in"
	@echo "  make docker-deploy-up [AGTSMITH_DEPLOY_PORT=8787] # run deployment image without host repo bind mount"
	@echo "  make docker-deploy-down # stop/remove deployment container"
	@echo "  make docker-deploy-logs # tail deployment container logs"
	@echo "  make ollama-log-tests # run unit+integration tests for remote Ollama log streaming adapter"
	@echo "  make tdir-core-tests # run deterministic core-TDIR enrichment unit tests"
	@echo "  make docs-index # generate consolidated docs/logs status report"
	@echo "  make report-freshness # fail if key reports are older than threshold"
	@echo "  make refresh-reports # refresh regression/status/docs index artifacts"
	@echo "  make ops # daily operator meta-target (refresh + freshness + docs index)"
	@echo "  make prune-summary # show current counts and keep thresholds before pruning"
	@echo "  make prune-snapshot # snapshot prune_summary.json into history"
	@echo "  make prune-trend # summarize prune history snapshots and deltas"
	@echo "  make prune-freshness # fail if prune summary artifacts are stale"
	@echo "  make prune-ops # run prune summary + snapshot + trend + freshness"
	@echo "  make prune-dry-run # show artifact prune candidates with default retention"
	@echo "  make prune-apply # apply artifact pruning with default retention"
	@echo "  (override keeps: KEEP_REGRESSION, KEEP_SNAPSHOTS, KEEP_LANGGRAPH)"
	@echo "  (override policy anomaly threshold: POLICY_MAX_ABS_DELTA)"
	@echo "  (override policy trend freshness threshold: POLICY_TREND_MAX_AGE_MINUTES)"
	@echo "  (override policy summary freshness threshold: POLICY_SUMMARY_MAX_AGE_MINUTES)"

check:
	@echo "[check] wrapper parsing regression"
	@./scripts/test_run_lab_checks.sh
	@echo "[check] template safety"
	@.venv/bin/python scripts/check_query_templates.py
	@echo "[check] query policy regression"
	@.venv/bin/python scripts/check_query_policy.py
	@echo "[check] environment profile helper tests"
	@$(MAKE) --no-print-directory env-profile-tests
	@echo "[check] core tdir enrichment tests"
	@$(MAKE) --no-print-directory tdir-core-tests
	@echo "[check] complete"

status:
	@echo "[status] artifact-only dashboard"
	@.venv/bin/python scripts/show_lab_status.py
	@echo "[status] trend summary"
	@.venv/bin/python scripts/summarize_regression_trends.py
	@echo "[status] complete"

snapshot:
	@echo "[snapshot] writing operator bundle"
	@.venv/bin/python scripts/write_operator_snapshot.py
	@echo "[snapshot] complete"

all: check status snapshot
	@echo "[all] complete"

langgraph-status:
	@echo "[langgraph-status] run index"
	@.venv/bin/python scripts/summarize_langgraph_runs.py --limit 10 --csv-out artifacts/runs/langgraph/latest_index.csv
	@echo "[langgraph-status] complete"

langgraph-policy-status:
	@echo "[langgraph-policy-status] policy summary"
	@.venv/bin/python scripts/summarize_langgraph_policy.py --limit 20 --csv-out artifacts/runs/langgraph/latest_policy_rows.csv --json-out artifacts/runs/langgraph/latest_policy_summary.json
	@echo "[langgraph-policy-status] complete"

langgraph-policy-snapshot:
	@echo "[langgraph-policy-snapshot] writing policy summary history snapshot"
	@.venv/bin/python scripts/snapshot_langgraph_policy_summary.py
	@echo "[langgraph-policy-snapshot] complete"

langgraph-policy-trend:
	@echo "[langgraph-policy-trend] summarize policy history"
	@.venv/bin/python scripts/summarize_langgraph_policy_history.py --limit 20 --csv-out docs/logs/langgraph_policy_summary_history/latest_trend.csv
	@echo "[langgraph-policy-trend] complete"

langgraph-policy-freshness:
	@echo "[langgraph-policy-freshness] checking policy summary artifact recency"
	@echo "[langgraph-policy-freshness] max_age_minutes=$(POLICY_SUMMARY_MAX_AGE_MINUTES)"
	@.venv/bin/python scripts/check_langgraph_policy_freshness.py --max-age-minutes $(POLICY_SUMMARY_MAX_AGE_MINUTES)
	@echo "[langgraph-policy-freshness] complete"

langgraph-policy-trend-freshness:
	@echo "[langgraph-policy-trend-freshness] checking policy trend artifact recency"
	@echo "[langgraph-policy-trend-freshness] max_age_minutes=$(POLICY_TREND_MAX_AGE_MINUTES)"
	@.venv/bin/python scripts/check_langgraph_policy_trend_freshness.py --max-age-minutes $(POLICY_TREND_MAX_AGE_MINUTES)
	@echo "[langgraph-policy-trend-freshness] complete"

langgraph-policy-trend-anomaly:
	@echo "[langgraph-policy-trend-anomaly] checking policy trend deltas"
	@echo "[langgraph-policy-trend-anomaly] max_abs_delta=$(POLICY_MAX_ABS_DELTA)"
	@.venv/bin/python scripts/check_langgraph_policy_trend_anomalies.py --max-abs-delta $(POLICY_MAX_ABS_DELTA)
	@echo "[langgraph-policy-trend-anomaly] complete"

langgraph-docs-check:
	@echo "[langgraph-docs-check] verifying README/daily consistency"
	@.venv/bin/python scripts/check_langgraph_docs_consistency.py
	@echo "[langgraph-docs-check] complete"

langgraph-artifacts-check:
	@echo "[langgraph-artifacts-check] verifying required artifacts"
	@.venv/bin/python scripts/check_langgraph_telemetry_artifacts.py
	@echo "[langgraph-artifacts-check] complete"

langgraph-tool-routing-check:
	@echo "[langgraph-tool-routing-check] verifying tool selection rules"
	@.venv/bin/python scripts/check_langgraph_tool_selection.py
	@echo "[langgraph-tool-routing-check] complete"

langgraph-session-check:
	@echo "[langgraph-session-check] verifying session memory helper behavior"
	@.venv/bin/python scripts/check_session_memory.py
	@echo "[langgraph-session-check] complete"

langgraph-thresholds:
	@echo "=== LangGraph Thresholds ==="
	@echo "POLICY_MAX_ABS_DELTA=$(POLICY_MAX_ABS_DELTA)"
	@echo "POLICY_SUMMARY_MAX_AGE_MINUTES=$(POLICY_SUMMARY_MAX_AGE_MINUTES)"
	@echo "POLICY_TREND_MAX_AGE_MINUTES=$(POLICY_TREND_MAX_AGE_MINUTES)"

langgraph-ops: langgraph-status langgraph-policy-status langgraph-policy-trend langgraph-policy-freshness langgraph-policy-trend-freshness langgraph-policy-trend-anomaly langgraph-tool-routing-check langgraph-session-check langgraph-docs-check langgraph-artifacts-check
	@echo "[langgraph-ops] complete"

langgraph-ops-strict:
	@$(MAKE) langgraph-ops POLICY_MAX_ABS_DELTA=2 POLICY_SUMMARY_MAX_AGE_MINUTES=60 POLICY_TREND_MAX_AGE_MINUTES=1440
	@echo "[langgraph-ops-strict] complete"

langgraph-gold-build:
	@echo "[langgraph-gold-build] building reference gold corpus"
	@.venv/bin/python scripts/build_langgraph_gold_corpus.py
	@echo "[langgraph-gold-build] complete"

langgraph-eval-prompts:
	@echo "[langgraph-eval-prompts] generating prompt variants"
	@.venv/bin/python scripts/generate_langgraph_eval_prompts.py
	@echo "[langgraph-eval-prompts] complete"

langgraph-topology-eval:
	@echo "[langgraph-topology-eval] running topology experiments"
	@.venv/bin/python scripts/run_langgraph_topology_eval.py
	@echo "[langgraph-topology-eval] complete"

langgraph-topology-optimize:
	@echo "[langgraph-topology-optimize] choosing current best topology"
	@.venv/bin/python scripts/optimize_langgraph_topology.py
	@echo "[langgraph-topology-optimize] complete"

langgraph-run:
	@echo "[langgraph-run] question=$(QUESTION)"
	@if [ "$(WRITE_ARTIFACT)" = "1" ]; then \
		.venv/bin/python scripts/langgraph_minimal_flow.py --write-artifact "$(QUESTION)"; \
	else \
		.venv/bin/python scripts/langgraph_minimal_flow.py "$(QUESTION)"; \
	fi
	@echo "[langgraph-run] complete"

langgraph-demo:
	@echo "[langgraph-demo] supported question"
	@.venv/bin/python scripts/langgraph_minimal_flow.py --write-artifact "Show failed login activity in the last 24 hours"
	@echo "[langgraph-demo] blocked question"
	@.venv/bin/python scripts/langgraph_minimal_flow.py --write-artifact "Delete old indexes and restart Splunk"
	@echo "[langgraph-demo] complete"

langgraph-policy-demo:
	@echo "[langgraph-policy-demo] policy pass case"
	@.venv/bin/python scripts/langgraph_minimal_flow.py --write-artifact "Show failed login activity in the last 24 hours"
	@echo "[langgraph-policy-demo] policy fail case (row_limit override)"
	@.venv/bin/python scripts/langgraph_minimal_flow.py --write-artifact --row-limit-override 500 "Show failed login activity in the last 24 hours"
	@echo "[langgraph-policy-demo] complete"

langgraph-tool-demo:
	@echo "[langgraph-tool-demo] query tool path"
	@.venv/bin/python scripts/langgraph_minimal_flow.py --write-artifact "Show failed login activity in the last 24 hours"
	@echo "[langgraph-tool-demo] index inventory tool path"
	@.venv/bin/python scripts/langgraph_minimal_flow.py --write-artifact "List indexes I can access"
	@echo "[langgraph-tool-demo] metadata inventory tool path"
	@.venv/bin/python scripts/langgraph_minimal_flow.py --write-artifact "List hosts metadata for the last 24 hours"
	@echo "[langgraph-tool-demo] splunk info tool path"
	@.venv/bin/python scripts/langgraph_minimal_flow.py --write-artifact "Show Splunk version details"
	@echo "[langgraph-tool-demo] complete"

langgraph-metadata-demo:
	@echo "[langgraph-metadata-demo] metadata inventory path"
	@.venv/bin/python scripts/langgraph_minimal_flow.py --write-artifact "List hosts metadata for the last 24 hours"
	@echo "[langgraph-metadata-demo] splunk info path"
	@.venv/bin/python scripts/langgraph_minimal_flow.py --write-artifact "Show Splunk version details"
	@echo "[langgraph-metadata-demo] complete"

langgraph-chain-demo:
	@echo "[langgraph-chain-demo] index->metadata drilldown path"
	@.venv/bin/python scripts/langgraph_minimal_flow.py --write-artifact "Investigate top index with metadata drilldown"
	@echo "[langgraph-chain-demo] complete"

langgraph-session-demo:
	@echo "[langgraph-session-demo] first run in demo session"
	@.venv/bin/python scripts/langgraph_minimal_flow.py --write-artifact --session-id demo_night_shift "Show failed login activity in the last 24 hours"
	@echo "[langgraph-session-demo] second run in same session"
	@.venv/bin/python scripts/langgraph_minimal_flow.py --write-artifact --session-id demo_night_shift "Investigate top index with metadata drilldown"
	@echo "[langgraph-session-demo] complete"

langgraph-demo-ready: langgraph-ops-strict langgraph-tool-demo langgraph-chain-demo langgraph-session-demo langgraph-demo langgraph-policy-demo langgraph-status langgraph-policy-status
	@echo "[langgraph-demo-ready] complete"

langgraph-all: langgraph-run langgraph-demo langgraph-policy-demo langgraph-tool-demo langgraph-chain-demo langgraph-session-demo langgraph-status langgraph-policy-status langgraph-policy-trend langgraph-policy-freshness langgraph-policy-trend-freshness langgraph-policy-trend-anomaly langgraph-tool-routing-check langgraph-docs-check
	@echo "[langgraph-all] complete"

langgraph-all-quick: langgraph-ops
	@echo "[langgraph-all-quick] complete"

agentic-check:
	@echo "[agentic-check] deterministic planner/pivot checks"
	@.venv/bin/python scripts/check_agentic_soc.py
	@echo "[agentic-check] complete"

agentic-run:
	@echo "[agentic-run] question=$(QUESTION) max_steps=$(AGENTIC_MAX_STEPS)"
	@.venv/bin/python scripts/langgraph_agentic_soc.py --write-artifact --max-steps $(AGENTIC_MAX_STEPS) "$(QUESTION)"
	@echo "[agentic-run] complete"

agentic-demo:
	@echo "[agentic-demo] failed-login investigation"
	@.venv/bin/python scripts/langgraph_agentic_soc.py --write-artifact --max-steps $(AGENTIC_MAX_STEPS) "Show failed login activity in the last 24 hours"
	@echo "[agentic-demo] top-index drilldown investigation"
	@.venv/bin/python scripts/langgraph_agentic_soc.py --write-artifact --max-steps $(AGENTIC_MAX_STEPS) "Investigate top index with metadata drilldown"
	@echo "[agentic-demo] complete"

agentic-session-demo:
	@echo "[agentic-session-demo] first question in shared session"
	@.venv/bin/python scripts/langgraph_agentic_soc.py --write-artifact --session-id agentic_demo_shift --max-steps $(AGENTIC_MAX_STEPS) "Show failed login activity in the last 24 hours"
	@echo "[agentic-session-demo] second question in shared session"
	@.venv/bin/python scripts/langgraph_agentic_soc.py --write-artifact --session-id agentic_demo_shift --max-steps $(AGENTIC_MAX_STEPS) "Investigate top index with metadata drilldown"
	@echo "[agentic-session-demo] complete"

agentic-status:
	@echo "[agentic-status] agentic run index"
	@.venv/bin/python scripts/summarize_agentic_runs.py --limit 10 --csv-out artifacts/runs/agentic/latest_index.csv
	@echo "[agentic-status] complete"

agentic-case-report:
	@echo "[agentic-case-report] generating latest case report"
	@.venv/bin/python scripts/generate_agentic_case_report.py
	@echo "[agentic-case-report] complete"

agentic-demo-ready: agentic-check agentic-demo agentic-session-demo agentic-status agentic-case-report
	@echo "[agentic-demo-ready] complete"

model-show:
	@echo "=== Model Configuration ==="
	@echo "OLLAMA_MODEL_PRIMARY=$${OLLAMA_MODEL_PRIMARY:-hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M}"
	@echo "OLLAMA_MODEL_REASONING=$${OLLAMA_MODEL_REASONING:-hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest}"
	@echo "OLLAMA_MODEL_AGENTIC_SUMMARY=$${OLLAMA_MODEL_AGENTIC_SUMMARY:-$${OLLAMA_MODEL_REASONING:-hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest}}"
	@echo "OLLAMA_MODEL_QUERY_PLANNER=$${OLLAMA_MODEL_QUERY_PLANNER:-$${OLLAMA_MODEL_PRIMARY:-hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M}}"
	@echo "OLLAMA_MODEL_QUERY_WRITER=$${OLLAMA_MODEL_QUERY_WRITER:-deepseek-coder-v2:lite}"
	@echo "OLLAMA_MODEL_SECURITY_REVIEWER=$${OLLAMA_MODEL_SECURITY_REVIEWER:-$${OLLAMA_MODEL_REASONING:-hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest}}"
	@echo "OLLAMA_MODEL_PEER_REVIEWER=$${OLLAMA_MODEL_PEER_REVIEWER:-$${OLLAMA_MODEL_REASONING:-hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest}}"
	@echo "OLLAMA_MODEL_PEER_REVIEWER_2=$${OLLAMA_MODEL_PEER_REVIEWER_2:-$${OLLAMA_MODEL_REASONING:-hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest}}"
	@echo "OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER=$${OLLAMA_MODEL_AGENTIC_CONTINUATION_REVIEWER:-$${OLLAMA_MODEL_REASONING:-hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest}}"
	@echo "OLLAMA_MODEL_FINAL_SUMMARY=$${OLLAMA_MODEL_FINAL_SUMMARY:-$${OLLAMA_MODEL_REASONING:-hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest}}"

model-smoke:
	@echo "[model-smoke] running connectivity and model generation checks"
	@.venv/bin/python scripts/smoke_lab_connectivity.py
	@echo "[model-smoke] complete"

model-spl-eval:
	@echo "[model-spl-eval] deterministic benchmark for query-writer SPL model"
	@.venv/bin/python scripts/evaluate_spl_writer_models.py
	@echo "[model-spl-eval] complete"

model-rag-ab:
	@echo "[model-rag-ab] A/B benchmark: vanilla vs RAG-augmented SPL writing"
	@.venv/bin/python scripts/evaluate_rag_vs_vanilla_spl.py --model "$${MODEL:-$${OLLAMA_MODEL_QUERY_WRITER:-$${OLLAMA_MODEL_PRIMARY:-hf.co/MaziyarPanahi/Qwen3-30B-A3B-Instruct-2507-GGUF:Q4_K_M}}}" --runs "$${RUNS:-1}"
	@echo "[model-rag-ab] complete"

model-spl-quality-deep:
	@echo "[model-spl-quality-deep] deep live-dataset SPL quality pass"
	@.venv/bin/python scripts/deep_spl_quality_pass.py
	@echo "[model-spl-quality-deep] complete"

spl-hardening-benchmark:
	@echo "[spl-hardening-benchmark] running MCP-backed hardening benchmark"
	@.venv/bin/python scripts/run_spl_hardening_benchmark.py
	@echo "[spl-hardening-benchmark] complete"

spl-hardening-benchmark-botsv3:
	@echo "[spl-hardening-benchmark-botsv3] running BOTSv3 all-time benchmark"
	@.venv/bin/python scripts/run_spl_hardening_benchmark.py --cases benchmarks/spl_cases_botsv3.json --out-dir artifacts/benchmark/botsv3
	@echo "[spl-hardening-benchmark-botsv3] complete"

spl-hardening-benchmark-botsv3-inventory:
	@echo "[spl-hardening-benchmark-botsv3-inventory] running planner-backed BOTSv3 sourcetype inventory benchmark"
	@.venv/bin/python scripts/run_spl_hardening_benchmark.py --cases AUTO_BOTSV3_INVENTORY --use-planner --out-dir artifacts/benchmark/botsv3_inventory
	@echo "[spl-hardening-benchmark-botsv3-inventory] complete"

env-profile-build:
	@echo "[env-profile-build] rebuilding append-only environment profile from Splunk MCP"
	@echo "[env-profile-build] focus_host=$(FOCUS_HOST)"
	@.venv/bin/python scripts/build_environment_profile.py --snapshot --focus-host "$(FOCUS_HOST)"
	@echo "[env-profile-build] complete"

env-profile-check:
	@echo "[env-profile-check] checking profile freshness"
	@.venv/bin/python scripts/check_environment_profile_freshness.py --max-age-minutes 11520
	@echo "[env-profile-check] complete"

spl-skillpack-refresh:
	@echo "[spl-skillpack-refresh] building SPL skillpack"
	@.venv/bin/python scripts/build_spl_skillpack.py
	@echo "[spl-skillpack-refresh] complete"

env-profile-refresh: env-profile-build env-profile-check spl-skillpack-refresh
	@echo "[env-profile-refresh] complete"

env-profile-tests:
	@echo "[env-profile-tests] running parser/validation unit tests"
	@.venv/bin/python -m unittest scripts.tests.test_environment_profile scripts.tests.test_spl_query_repair scripts.tests.test_intent_field_contracts
	@echo "[env-profile-tests] complete"

env-profile-schedule-install:
	@echo "[env-profile-schedule-install] installing cron scheduler"
	@bash scripts/install_env_profile_scheduler.sh "$${DAY_OF_WEEK:-0}" "$${HOUR:-4}" "$${MINUTE:-0}"
	@echo "[env-profile-schedule-install] complete"

env-profile-schedule-show:
	@echo "[env-profile-schedule-show] current entry"
	@crontab -l 2>/dev/null | grep 'SOC_ENV_PROFILE_REFRESH' || echo "(no scheduler entry found)"
	@echo "[env-profile-schedule-show] complete"

sourcetype-research:
	@echo "[sourcetype-research] regenerating sourcetype research report"
	@.venv/bin/python scripts/generate_sourcetype_research_report.py
	@echo "[sourcetype-research] complete"

dev:
	@$(MAKE) --no-print-directory ui-dev

ui-dev:
	@echo "[ui-dev] starting web UI on all interfaces at http://0.0.0.0:8787"
	@pids=$$(ss -ltnp | awk '/:8787 / {print $$NF}' | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u); \
	if [ -n "$$pids" ]; then \
		echo "[ui-dev] detected existing listener(s) on :8787; stopping: $$pids"; \
		kill $$pids || true; \
		sleep 1; \
	fi
	@if [ -f config/ui.env ]; then \
		echo "[ui-dev] loading runtime env from config/ui.env"; \
		set -a; . ./config/ui.env; set +a; \
		.venv/bin/python scripts/web_ui_server.py --host 0.0.0.0 --port 8787; \
	else \
		echo "[ui-dev] config/ui.env not found; starting with current shell env"; \
		.venv/bin/python scripts/web_ui_server.py --host 0.0.0.0 --port 8787; \
	fi

docker-build:
	@echo "[docker-build] building agtsmith-ui image"
	@docker compose build
	@echo "[docker-build] complete"

docker-up:
	@echo "[docker-up] starting Dockerized A.G.E.N.T. Smith UI on host port $${AGTSMITH_UI_PORT:-8787}"
	@AGTSMITH_UI_PORT=$${AGTSMITH_UI_PORT:-8787} docker compose up -d
	@echo "[docker-up] complete"

docker-down:
	@echo "[docker-down] stopping Dockerized A.G.E.N.T. Smith UI"
	@docker compose down
	@echo "[docker-down] complete"

docker-logs:
	@docker compose logs --tail=200 -f

docker-deploy-build:
	@echo "[docker-deploy-build] building self-contained deployment image"
	@docker compose -f docker-compose.deploy.yml build
	@echo "[docker-deploy-build] complete"

docker-deploy-up:
	@echo "[docker-deploy-up] starting deployment image on host port $${AGTSMITH_DEPLOY_PORT:-8787}"
	@AGTSMITH_DEPLOY_PORT=$${AGTSMITH_DEPLOY_PORT:-8787} docker compose -f docker-compose.deploy.yml up -d
	@echo "[docker-deploy-up] complete"

docker-deploy-down:
	@echo "[docker-deploy-down] stopping deployment container"
	@docker compose -f docker-compose.deploy.yml down
	@echo "[docker-deploy-down] complete"

docker-deploy-logs:
	@docker compose -f docker-compose.deploy.yml logs --tail=200 -f

ollama-log-tests:
	@echo "[ollama-log-tests] running remote log stream tests"
	@.venv/bin/python -m unittest scripts.tests.test_ollama_log_stream_unit scripts.tests.test_ollama_log_stream_integration
	@echo "[ollama-log-tests] complete"

tdir-core-tests:
	@echo "[tdir-core-tests] running deterministic tdir-core unit tests"
	@.venv/bin/python -m unittest scripts.tests.test_tdir_core
	@echo "[tdir-core-tests] complete"

multi-model-run:
	@echo "[multi-model-run] question=$(QUESTION)"
	@.venv/bin/python scripts/langgraph_multi_model_soc.py --write-artifact "$(QUESTION)"
	@echo "[multi-model-run] complete"

multi-model-check:
	@echo "[multi-model-check] running automated regression checks"
	@.venv/bin/python scripts/check_multi_model_soc.py --write-artifacts
	@echo "[multi-model-check] complete"

multi-model-demo:
	@echo "[multi-model-demo] supported case"
	@.venv/bin/python scripts/langgraph_multi_model_soc.py --write-artifact "Show failed login activity in the last 24 hours"
	@echo "[multi-model-demo] inventory case"
	@.venv/bin/python scripts/langgraph_multi_model_soc.py --write-artifact "List indexes I can access"
	@echo "[multi-model-demo] blocked case"
	@.venv/bin/python scripts/langgraph_multi_model_soc.py --write-artifact "Delete old indexes and restart Splunk"
	@echo "[multi-model-demo] complete"

multi-model-status:
	@echo "[multi-model-status] run index"
	@.venv/bin/python scripts/summarize_multi_model_runs.py --limit 10 --csv-out artifacts/runs/multi_model/latest_index.csv
	@echo "[multi-model-status] complete"

multi-model-demo-ready: multi-model-check multi-model-demo multi-model-status
	@echo "[multi-model-demo-ready] complete"

docs-index:
	@echo "[docs-index] generating status report"
	@.venv/bin/python scripts/generate_docs_index.py
	@echo "[docs-index] complete"

report-freshness:
	@echo "[report-freshness] checking key report ages"
	@.venv/bin/python scripts/check_report_freshness.py --max-age-minutes 180
	@echo "[report-freshness] complete"

refresh-reports:
	@echo "[refresh-reports] running regression"
	@.venv/bin/python scripts/run_template_regression.py
	@echo "[refresh-reports] refreshing latest status json"
	@.venv/bin/python scripts/show_lab_status.py --json-out docs/logs/latest_status.json
	@echo "[refresh-reports] rebuilding docs index reports"
	@.venv/bin/python scripts/generate_docs_index.py
	@echo "[refresh-reports] complete"

ops: refresh-reports report-freshness docs-index
	@echo "[ops] complete"

prune-summary:
	@echo "[prune-summary] current counts vs keep thresholds"
	@.venv/bin/python scripts/show_prune_summary.py --keep-regression $(KEEP_REGRESSION) --keep-snapshots $(KEEP_SNAPSHOTS) --keep-langgraph $(KEEP_LANGGRAPH) --json-out docs/logs/prune_summary.json
	@echo "[prune-summary] complete"

prune-snapshot:
	@echo "[prune-snapshot] writing prune summary history snapshot"
	@.venv/bin/python scripts/snapshot_prune_summary.py
	@echo "[prune-snapshot] complete"

prune-trend:
	@echo "[prune-trend] summarize history"
	@.venv/bin/python scripts/summarize_prune_history.py --limit 20 --csv-out docs/logs/prune_summary_history/latest_trend.csv
	@echo "[prune-trend] complete"

prune-freshness:
	@echo "[prune-freshness] checking prune artifact recency"
	@.venv/bin/python scripts/check_prune_freshness.py --max-age-minutes 10080
	@echo "[prune-freshness] complete"

prune-ops: prune-summary prune-snapshot prune-trend prune-freshness
	@echo "[prune-ops] complete"

prune-dry-run:
	@echo "[prune-dry-run] evaluating candidates"
	@echo "[prune-dry-run] keep_regression=$(KEEP_REGRESSION) keep_snapshots=$(KEEP_SNAPSHOTS) keep_langgraph=$(KEEP_LANGGRAPH)"
	@.venv/bin/python scripts/prune_artifacts.py --keep-regression $(KEEP_REGRESSION) --keep-snapshots $(KEEP_SNAPSHOTS) --keep-langgraph $(KEEP_LANGGRAPH)
	@echo "[prune-dry-run] complete"

prune-apply:
	@echo "[prune-apply] deleting old artifacts"
	@echo "[prune-apply] keep_regression=$(KEEP_REGRESSION) keep_snapshots=$(KEEP_SNAPSHOTS) keep_langgraph=$(KEEP_LANGGRAPH)"
	@.venv/bin/python scripts/prune_artifacts.py --keep-regression $(KEEP_REGRESSION) --keep-snapshots $(KEEP_SNAPSHOTS) --keep-langgraph $(KEEP_LANGGRAPH) --apply
	@echo "[prune-apply] complete"
