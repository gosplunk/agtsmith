.PHONY: help check status snapshot all langgraph-status langgraph-policy-status langgraph-policy-snapshot langgraph-policy-trend langgraph-policy-freshness langgraph-policy-trend-freshness langgraph-policy-trend-anomaly langgraph-docs-check langgraph-artifacts-check langgraph-tool-routing-check langgraph-session-check langgraph-thresholds langgraph-ops langgraph-ops-strict langgraph-run langgraph-demo langgraph-policy-demo langgraph-tool-demo langgraph-metadata-demo langgraph-chain-demo langgraph-session-demo langgraph-demo-ready langgraph-all langgraph-all-quick langgraph-gold-build langgraph-eval-prompts langgraph-topology-eval langgraph-topology-optimize agentic-check agentic-run agentic-demo agentic-session-demo agentic-status agentic-case-report agentic-demo-ready multi-model-run multi-model-check multi-model-demo multi-model-status multi-model-demo-ready model-show model-smoke model-spl-eval model-planner-eval model-planner-eval-hf model-planner-vram-smoke model-rag-ab model-spl-quality-deep spl-hardening-benchmark live-domain-benchmark live-domain-benchmark-offline spl-hardening-benchmark-botsv3 spl-hardening-benchmark-botsv3-inventory check-gold-oracles investigation-e2e spl-autonomy-check spl-autonomy-nightly env-profile-build env-profile-check env-profile-refresh env-profile-tests env-profile-schedule-install env-profile-schedule-show sourcetype-research spl-skillpack-refresh dev ui-dev docker-build docker-up docker-down docker-logs docker-deploy-build docker-deploy-up docker-deploy-down docker-deploy-logs docker-deploy-manual ollama-log-tests tdir-core-tests kvstore-case-tests docs-index report-freshness refresh-reports ops prune-summary prune-snapshot prune-trend prune-freshness prune-dry-run prune-apply prune-ops splunk-app-package splunk-app-install-local splunk-app-symlink-dev screenshots screenshots-diff configure-check configure-screenshots configure-screenshots-diff configure-e2e configure-tag-show configure-tag-record local-lab-preflight setup-local-ui-env

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
SPLUNK_APP_VERSION ?= 0.2.0-splunk
SPLUNK_HOME ?= /opt/splunk
SCREENSHOT_VERSION ?= v1.5.1
CONFIGURE_UI_TAG ?= configure-ui-dev
CONFIGURE_UI_BASELINE ?= configure-ui-p0
CASES ?= benchmarks/spl_cases.json
OUT ?= artifacts/benchmark

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
	@echo "  make model-planner-eval # isolated planner_node benchmark for OLLAMA_MODEL_QUERY_PLANNER"
	@echo "  make model-planner-eval-hf # HF/new-tag planner benchmark (see hf_exhaustive_research.md)"
	@echo "  make model-planner-vram-smoke # VRAM smoke for planner candidate tags"
	@echo "  make model-rag-ab [MODEL='...'] [RUNS=1] # A/B benchmark: vanilla vs RAG-augmented SPL writing"
	@echo "  make model-spl-quality-deep # deep live-dataset SPL quality pass (Windows/Linux/Apache)"
	@echo "  make spl-hardening-benchmark # MCP-backed benchmark suite against the current environment"
	@echo "  make live-domain-benchmark # profile-driven gold vs agtsmith SPL benchmark (live lab MCP)"
	@echo "  make spl-hardening-benchmark-botsv3 # separate BOTSv3 all-time benchmark suite"
	@echo "  make spl-hardening-benchmark-botsv3-inventory # planner-backed overview benchmark across the full BOTSv3 sourcetype inventory"
	@echo "  make check-gold-oracles # offline gold SPL oracle validation (no MCP)"
	@echo "  make investigation-e2e # Playwright Investigation UI E2E (live lab)"
	@echo "  make spl-improvement-loop [SPL_IMPROVEMENT_REPORT=...] # classify benchmark failures into learning candidates"
	@echo "  make spl-offline-docs-index # build SPL RAG index from Splunk Offline Docs search-index.json"
	@echo "  make spl-benchmark-compare CURRENT=... # compare run JSON against baseline manifest"
	@echo "  make spl-multi-layout-matrix # offline gold oracle matrix across profile fixtures"
	@echo "  make lab-data-matrix-bootstrap # provision+verify all lab layouts then run matrix"
	@echo "  make spl-autonomy-nightly # env refresh + autonomy loop with --promote"
	@echo "  make env-profile-build [FOCUS_HOST=<linux-host>] # rebuild append-only environment profile from Splunk MCP (+ optional host focus)"
	@echo "  make env-profile-check # fail if environment profile is missing/stale"
	@echo "  make env-profile-refresh # build + freshness-check environment profile (full first-time field enrichment, then incremental maintenance)"
	@echo "  make lab-data-refresh-mcp-token # mint MCP token (user mcp) into config/ui.env"
	@echo "  make lab-data-provision [LAB_DATA_LAYOUT=existing_lab] # create Splunk indexes for layout profile"
	@echo "  make lab-data-generate [LAB_DATA_LAYOUT=...] [LAB_DATA_HOURS=6] [LAB_DATA_COUNT=50] # inject fresh HEC events"
	@echo "  make lab-data-verify # MCP verify -24h row counts per benchmark domain"
	@echo "  make lab-data-bootstrap # provision + generate + verify + env-profile-refresh"
	@echo "  make lab-data-install # one-shot: HEC + creds + bootstrap (requires sudo -u splunk once)"
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
	@echo "  make docker-deploy-hotpatch # sync repo UI into running deploy container (keeps volume creds)"
	@echo "  make docker-deploy-down # stop/remove deployment container"
	@echo "  make docker-deploy-logs # tail deployment container logs"
	@echo "  make docker-deploy-manual # deploy via plain docker when compose plugin missing"
	@echo "  make setup-local-ui-env # write config/ui.env from SPLUNK_USER/SPLUNK_PASS env"
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
	@echo "  make splunk-app-package # build dist/agent_smith-<version>.tgz"
	@echo "  make splunk-app-install-local # install package to SPLUNK_HOME"
	@echo "  make splunk-app-symlink-dev # symlink splunk_app/agent_smith into SPLUNK_HOME/etc/apps"
	@echo "  make screenshots [SCREENSHOT_VERSION=...] # Playwright UI captures"
	@echo "  make screenshots-diff [SCREENSHOT_VERSION=...] # visual diff vs baseline"
	@echo "  make configure-check # static/API configure page tests"
	@echo "  make configure-screenshots [CONFIGURE_UI_TAG=...] # configure lane captures"
	@echo "  make configure-screenshots-diff # diff configure lane screenshots"
	@echo "  make configure-e2e # Playwright configure flow (live lab)"
	@echo "  make configure-tag-show / configure-tag-record # Configure UI version tags"
	@echo "  make local-lab-preflight # curl checks for local Splunk/Ollama/sidecar"
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
	@echo "[check] gold SPL oracle validation"
	@$(MAKE) --no-print-directory check-gold-oracles
	@echo "[check] core tdir enrichment tests"
	@$(MAKE) --no-print-directory tdir-core-tests
	@echo "[check] kvstore case backend tests"
	@$(MAKE) --no-print-directory kvstore-case-tests
	@echo "[check] configure page tests"
	@$(MAKE) --no-print-directory configure-check
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
	@echo "=== Model Configuration (v1.5.x US-primary defaults) ==="
	@echo "OLLAMA_MODEL_PRIMARY=$${OLLAMA_MODEL_PRIMARY:-granite4:3b}"
	@echo "OLLAMA_MODEL_REASONING=$${OLLAMA_MODEL_REASONING:-hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest}"
	@echo "OLLAMA_MODEL_AGENTIC_SUMMARY=$${OLLAMA_MODEL_AGENTIC_SUMMARY:-$${OLLAMA_MODEL_REASONING:-hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest}}"
	@echo "OLLAMA_MODEL_QUERY_PLANNER=$${OLLAMA_MODEL_QUERY_PLANNER:-TechyShishy/ministral-3:3b-reasoning-2512-q4_K_M}"
	@echo "OLLAMA_MODEL_QUERY_PLANNER_FALLBACK=$${OLLAMA_MODEL_QUERY_PLANNER_FALLBACK:-ministral-3:3b}"
	@echo "OLLAMA_MODEL_QUERY_WRITER=$${OLLAMA_MODEL_QUERY_WRITER:-granite4:3b}"
	@echo "OLLAMA_MODEL_QUERY_REPAIR=$${OLLAMA_MODEL_QUERY_REPAIR:-granite4:3b}"
	@echo "OLLAMA_MODEL_SECURITY_REVIEWER=$${OLLAMA_MODEL_SECURITY_REVIEWER:-$${OLLAMA_MODEL_REASONING:-hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF:latest}}"
	@echo "OLLAMA_MODEL_PEER_REVIEWER=$${OLLAMA_MODEL_PEER_REVIEWER:-gemma3:4b}"
	@echo "OLLAMA_MODEL_PEER_REVIEWER_2=$${OLLAMA_MODEL_PEER_REVIEWER_2:-gemma3:4b}"
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

model-planner-eval:
	@echo "[model-planner-eval] isolated planner_node benchmark (see artifacts/model_eval/planner_bakeoff/)"
	@.venv/bin/python scripts/evaluate_planner_models.py
	@echo "[model-planner-eval] complete"

model-planner-eval-hf:
	@echo "[model-planner-eval-hf] HF/new-tag planner benchmark (see hf_exhaustive_research.md)"
	@.venv/bin/python scripts/evaluate_planner_models.py \
		--models "$$(PYTHONPATH=scripts .venv/bin/python -c 'from evaluate_planner_models import DEFAULT_HF_PLANNER_MODELS; print(DEFAULT_HF_PLANNER_MODELS)')" \
		--skip-models granite3-moe:3b
	@echo "[model-planner-eval-hf] complete"

model-planner-vram-smoke:
	@echo "[model-planner-vram-smoke] VRAM smoke for planner candidates"
	@.venv/bin/python scripts/smoke_planner_vram.py
	@echo "[model-planner-vram-smoke] complete"

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
	@echo "[spl-hardening-benchmark] cases=$(CASES) out=$(OUT)"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/run_spl_hardening_benchmark.py --cases $(CASES) --out-dir $(OUT)
	@echo "[spl-hardening-benchmark] complete"

LIVE_DOMAIN_BENCHMARK_OUT ?= artifacts/spl_autonomy/live_benchmark

live-domain-benchmark:
	@echo "[live-domain-benchmark] profile-driven gold vs agtsmith SPL benchmark"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/run_live_domain_benchmark.py --out-root $(LIVE_DOMAIN_BENCHMARK_OUT) $(LIVE_DOMAIN_BENCHMARK_ARGS)
	@echo "[live-domain-benchmark] complete"

live-domain-benchmark-offline:
	@echo "[live-domain-benchmark-offline] offline compare (no MCP execution)"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/run_live_domain_benchmark.py --out-root $(LIVE_DOMAIN_BENCHMARK_OUT) --skip-mcp
	@echo "[live-domain-benchmark-offline] complete"

check-gold-oracles:
	@echo "[check-gold-oracles] validating gold SPL oracles offline"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/check_gold_spl_oracles.py
	@echo "[check-gold-oracles] complete"

spl-multi-layout-matrix:
	@echo "[spl-multi-layout-matrix] offline gold oracle matrix across profile fixtures"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/run_multi_layout_matrix.py \
		--out artifacts/benchmark/multi_layout_matrix_latest.json
	@echo "[spl-multi-layout-matrix] complete"

lab-data-matrix-bootstrap:
	@echo "[lab-data-matrix-bootstrap] bootstrap each lab layout and run offline matrix"
	@for layout in existing_lab multi_index_ideal minimal_ci; do \
		echo "[lab-data-matrix-bootstrap] layout=$$layout"; \
		$(MAKE) --no-print-directory lab-data-provision LAB_DATA_LAYOUT=$$layout || exit 1; \
		$(MAKE) --no-print-directory lab-data-generate LAB_DATA_LAYOUT=$$layout || exit 1; \
		$(MAKE) --no-print-directory lab-data-verify LAB_DATA_LAYOUT=$$layout || exit 1; \
	done
	@$(MAKE) --no-print-directory env-profile-refresh
	@$(MAKE) --no-print-directory spl-multi-layout-matrix
	@echo "[lab-data-matrix-bootstrap] complete"

check-gold-oracles-live:
	@echo "[check-gold-oracles-live] validating gold SPL oracles against live environment profile when present"
	@if [ -f artifacts/environment/environment_profile_latest.json ]; then \
		PYTHONPATH=.:scripts .venv/bin/python scripts/check_gold_spl_oracles.py \
			--profile artifacts/environment/environment_profile_latest.json; \
	else \
		echo "[check-gold-oracles-live] skip: artifacts/environment/environment_profile_latest.json not found"; \
	fi
	@echo "[check-gold-oracles-live] complete"

investigation-e2e:
	@echo "[investigation-e2e] Playwright Investigation UI flow"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/investigation_e2e.py
	@echo "[investigation-e2e] complete"

SPL_AUTONOMY_OUT ?= artifacts/spl_autonomy
SPL_AUTONOMY_CASES ?= benchmarks/pilot_live_20_cases.json
SPL_IMPROVEMENT_REPORT ?= artifacts/benchmark/spl_hardening_benchmark_latest.json

spl-improvement-loop:
	@echo "[spl-improvement-loop] classify failures and propose learning candidates"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/spl_improvement_loop.py --report $(SPL_IMPROVEMENT_REPORT)
	@echo "[spl-improvement-loop] complete"

SPL_OFFLINE_DOCS_SOURCE ?= /home/joehaga/ai_projects/Splunk4Offlinedocs/artifacts/staging/splunk_offline_docs/appserver/static/docs/manifest/search-index.json
SPL_OFFLINE_DOCS_RAG_OUT ?= artifacts/knowledge/spl_offline_docs_rag_index.json

spl-offline-docs-index:
	@echo "[spl-offline-docs-index] building SPL-focused RAG index from offline docs"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/build_spl_offline_docs_rag_index.py --source $(SPL_OFFLINE_DOCS_SOURCE) --out $(SPL_OFFLINE_DOCS_RAG_OUT)
	@echo "[spl-offline-docs-index] complete"

spl-benchmark-compare:
	@echo "[spl-benchmark-compare] compare current benchmark to baseline"
	@test -n "$(CURRENT)" || (echo "ERROR: set CURRENT=path/to/spl_hardening_benchmark_latest.json" >&2; exit 1)
	@PYTHONPATH=.:scripts .venv/bin/python scripts/spl_benchmark_compare.py \
		--baseline artifacts/spl_autonomy/baseline/spl_hardening_benchmark_latest.json \
		--current "$(CURRENT)"
	@echo "[spl-benchmark-compare] complete"

spl-autonomy-check: check check-gold-oracles spl-multi-layout-matrix
	@echo "[spl-autonomy-check] live-domain offline + pilot hardening subset + investigation E2E"
	@if [ "$${LAB_DATA_ENABLED:-0}" = "1" ]; then $(MAKE) --no-print-directory lab-data-verify; fi
	@if [ "$${SPL_AUTONOMY_STRICT_PROFILE:-0}" = "1" ]; then $(MAKE) --no-print-directory env-profile-check; fi
	@$(MAKE) --no-print-directory live-domain-benchmark-offline
	@$(MAKE) --no-print-directory spl-hardening-benchmark CASES=$(SPL_AUTONOMY_CASES) OUT=$(SPL_AUTONOMY_OUT)/check
	@$(MAKE) --no-print-directory investigation-e2e
	@if [ "$${SPL_AUTONOMY_LIVE_MCP:-0}" = "1" ]; then $(MAKE) --no-print-directory live-domain-benchmark; fi
	@echo "[spl-autonomy-check] complete"

spl-autonomy-nightly: lab-data-refresh-mcp-token env-profile-refresh
	@SPL_AUTONOMY_STRICT_PROFILE=1 $(MAKE) --no-print-directory env-profile-check
	@if docker inspect -f '{{.State.Running}}' agtsmith-ui-deploy 2>/dev/null | grep -q true; then $(MAKE) --no-print-directory docker-deploy-hotpatch; fi
	@if [ "$${LAB_DATA_ENABLED:-0}" = "1" ]; then $(MAKE) --no-print-directory lab-data-generate lab-data-verify; fi
	@SPL_AUTONOMY_LIVE_MCP=1 $(MAKE) --no-print-directory spl-autonomy-check
	@$(MAKE) --no-print-directory live-domain-benchmark
	@$(MAKE) --no-print-directory spl-hardening-benchmark-botsv3-inventory
	@echo "[spl-autonomy-nightly] classify benchmark failures"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/spl_improvement_loop.py --report artifacts/benchmark/botsv3_inventory/spl_hardening_benchmark_latest.json || true
	@echo "[spl-autonomy-nightly] full closed loop with optional promotion"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/spl_autonomy_loop.py \
		--out-dir $(SPL_AUTONOMY_OUT) \
		--cases $(SPL_AUTONOMY_CASES) \
		--promote
	@echo "[spl-autonomy-nightly] complete"

spl-hardening-benchmark-botsv3:
	@echo "[spl-hardening-benchmark-botsv3] running BOTSv3 all-time benchmark"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/run_spl_hardening_benchmark.py --cases benchmarks/spl_cases_botsv3.json --out-dir artifacts/benchmark/botsv3
	@echo "[spl-hardening-benchmark-botsv3] complete"

spl-hardening-benchmark-botsv3-inventory:
	@echo "[spl-hardening-benchmark-botsv3-inventory] running planner-backed BOTSv3 sourcetype inventory benchmark"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/run_spl_hardening_benchmark.py --cases AUTO_BOTSV3_INVENTORY --use-planner --out-dir artifacts/benchmark/botsv3_inventory
	@echo "[spl-hardening-benchmark-botsv3-inventory] complete"

env-profile-build:
	@echo "[env-profile-build] rebuilding append-only environment profile from Splunk MCP"
	@echo "[env-profile-build] focus_host=$(FOCUS_HOST)"
	@$(LAB_DATA_RUN) .venv/bin/python scripts/build_environment_profile.py --snapshot --focus-host "$(FOCUS_HOST)"
	@echo "[env-profile-build] complete"

env-profile-check:
	@echo "[env-profile-check] checking profile freshness"
	@max_age=$${ENV_PROFILE_MAX_AGE_MINUTES:-11520}; \
	if [ "$${SPL_AUTONOMY_STRICT_PROFILE:-0}" = "1" ]; then max_age=720; fi; \
	$(LAB_DATA_RUN) .venv/bin/python scripts/check_environment_profile_freshness.py --max-age-minutes $$max_age
	@echo "[env-profile-check] complete"

LAB_DATA_LAYOUT ?= existing_lab
LAB_DATA_HOURS ?= 6
LAB_DATA_COUNT ?= 50
LAB_DATA_RUN = .venv/bin/python scripts/lab_data/run_lab_data.py --

lab-data-provision:
	@echo "[lab-data-provision] creating indexes for layout=$(LAB_DATA_LAYOUT)"
	@$(LAB_DATA_RUN) .venv/bin/python scripts/lab_data_provision.py --layout "$(LAB_DATA_LAYOUT)"
	@echo "[lab-data-provision] complete"

lab-data-refresh-mcp-token:
	@echo "[lab-data-refresh-mcp-token] mint MCP token for user mcp -> config/ui.env"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/lab_data/refresh_mcp_token.py
	@echo "[lab-data-refresh-mcp-token] complete"

lab-data-generate:
	@echo "[lab-data-generate] injecting events layout=$(LAB_DATA_LAYOUT) hours=$(LAB_DATA_HOURS) count=$(LAB_DATA_COUNT)"
	@$(LAB_DATA_RUN) .venv/bin/python scripts/lab_data_generate.py \
		--layout "$(LAB_DATA_LAYOUT)" --hours "$(LAB_DATA_HOURS)" --count "$(LAB_DATA_COUNT)"
	@echo "[lab-data-generate] complete"

lab-data-verify:
	@echo "[lab-data-verify] MCP row check for generated lab data"
	@$(LAB_DATA_RUN) .venv/bin/python scripts/lab_data_verify.py --layout "$(LAB_DATA_LAYOUT)"
	@echo "[lab-data-verify] complete"

lab-data-cleanup:
	@echo "[lab-data-cleanup] removing tagged generator events"
	@$(LAB_DATA_RUN) .venv/bin/python scripts/lab_data_cleanup.py --layout "$(LAB_DATA_LAYOUT)"
	@echo "[lab-data-cleanup] complete"

lab-data-bootstrap: lab-data-refresh-mcp-token lab-data-provision lab-data-generate lab-data-verify env-profile-refresh
	@echo "[lab-data-bootstrap] complete"

lab-data-install:
	@echo "[lab-data-install] enable HEC, configure ui.env, bootstrap lab data"
	@bash scripts/lab_data/install_lab_data_prereqs.sh
	@echo "[lab-data-install] complete"

spl-skillpack-refresh:
	@echo "[spl-skillpack-refresh] building SPL skillpack"
	@PYTHON_BIN=$$(if [ -x .venv/bin/python ]; then echo .venv/bin/python; else echo python3; fi); \
	$$PYTHON_BIN scripts/build_spl_skillpack.py
	@echo "[spl-skillpack-refresh] complete"

env-profile-refresh: env-profile-build env-profile-check spl-skillpack-refresh
	@echo "[env-profile-refresh] complete"

env-profile-tests:
	@echo "[env-profile-tests] running parser/validation unit tests"
	@PYTHONPATH=.:scripts .venv/bin/python -m unittest scripts.tests.test_environment_profile scripts.tests.test_spl_query_repair scripts.tests.test_intent_field_contracts scripts.tests.test_langgraph_coherence_wiring scripts.tests.test_lab_data_config scripts.tests.test_setup_hec
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
		PYTHONPATH=.:scripts .venv/bin/python scripts/web_ui_server.py --host 0.0.0.0 --port 8787; \
	else \
		echo "[ui-dev] config/ui.env not found; starting with current shell env"; \
		PYTHONPATH=.:scripts .venv/bin/python scripts/web_ui_server.py --host 0.0.0.0 --port 8787; \
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
	@pids=$$(ss -ltnp 2>/dev/null | awk '/:8787 / {print $$NF}' | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u); \
	if [ -n "$$pids" ]; then \
		echo "[docker-deploy-up] stopping non-docker listener(s) on :8787: $$pids"; \
		kill $$pids 2>/dev/null || true; \
		sleep 1; \
	fi
	@docker compose -f docker-compose.deploy.yml up -d
	@echo "[docker-deploy-up] complete (UI creds: docker volume, not host config/ui.env)"

docker-deploy-hotpatch:
	@echo "[docker-deploy-hotpatch] syncing repo UI code into agtsmith-ui-deploy (preserves /app/config volume creds)"
	@docker cp scripts/web_ui_server.py agtsmith-ui-deploy:/app/scripts/web_ui_server.py
	@docker cp scripts/runtime_config.py agtsmith-ui-deploy:/app/scripts/runtime_config.py
	@docker cp scripts/ollama_ops_monitor.py agtsmith-ui-deploy:/app/scripts/ollama_ops_monitor.py
	@docker cp scripts/ollama_log_stream.py agtsmith-ui-deploy:/app/scripts/ollama_log_stream.py
	@docker cp ollama_client.py agtsmith-ui-deploy:/app/ollama_client.py
	@docker cp VERSION agtsmith-ui-deploy:/app/VERSION
	@docker restart agtsmith-ui-deploy
	@echo "[docker-deploy-hotpatch] complete"

docker-deploy-down:
	@echo "[docker-deploy-down] stopping deployment container"
	@docker compose -f docker-compose.deploy.yml down
	@echo "[docker-deploy-down] complete"

docker-deploy-logs:
	@docker compose -f docker-compose.deploy.yml logs --tail=200 -f

docker-deploy-manual:
	@bash ./scripts/docker-deploy-manual.sh

setup-local-ui-env:
	@bash ./scripts/setup_local_ui_env.sh

ollama-log-tests:
	@echo "[ollama-log-tests] running remote log stream tests"
	@.venv/bin/python -m unittest scripts.tests.test_ollama_log_stream_unit scripts.tests.test_ollama_log_stream_integration
	@echo "[ollama-log-tests] complete"

tdir-core-tests:
	@echo "[tdir-core-tests] running deterministic tdir-core unit tests"
	@.venv/bin/python -m unittest scripts.tests.test_tdir_core
	@echo "[tdir-core-tests] complete"

kvstore-case-tests:
	@echo "[kvstore-case-tests] running KV store case mirror tests"
	@.venv/bin/python -m unittest scripts.tests.test_kvstore_case_backend
	@echo "[kvstore-case-tests] complete"

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

local-lab-preflight:
	@bash ./.cursor/skills/agtsmith-local-lab/scripts/preflight.sh

splunk-app-package:
	@echo "[splunk-app-package] building dist/agent_smith-$(SPLUNK_APP_VERSION).tgz"
	@mkdir -p dist
	@tar -czf dist/agent_smith-$(SPLUNK_APP_VERSION).tgz -C splunk_app agent_smith
	@echo "[splunk-app-package] complete"

splunk-app-install-local: splunk-app-package
	@echo "[splunk-app-install-local] installing to $(SPLUNK_HOME)/etc/apps"
	@sudo -u splunk $(SPLUNK_HOME)/bin/splunk install app dist/agent_smith-$(SPLUNK_APP_VERSION).tgz -update 1
	@echo "[splunk-app-install-local] restart Splunk to load nav: sudo -u splunk $(SPLUNK_HOME)/bin/splunk restart"

splunk-app-symlink-dev:
	@echo "[splunk-app-symlink-dev] linking $(CURDIR)/splunk_app/agent_smith -> $(SPLUNK_HOME)/etc/apps/agent_smith"
	@sudo ln -sfn "$(CURDIR)/splunk_app/agent_smith" "$(SPLUNK_HOME)/etc/apps/agent_smith"
	@echo "[splunk-app-symlink-dev] complete — restart Splunk to pick up changes"

screenshots:
	@echo "[screenshots] capturing version $(SCREENSHOT_VERSION)"
	@if [ -x .venv/bin/python ]; then .venv/bin/python .cursor/skills/agtsmith-screenshots/scripts/capture.py --version $(SCREENSHOT_VERSION); else python3 .cursor/skills/agtsmith-screenshots/scripts/capture.py --version $(SCREENSHOT_VERSION); fi
	@echo "[screenshots] complete"

screenshots-diff:
	@echo "[screenshots-diff] comparing version $(SCREENSHOT_VERSION)"
	@if [ -x .venv/bin/python ]; then .venv/bin/python .cursor/skills/agtsmith-screenshots/scripts/compare.py --version $(SCREENSHOT_VERSION); else python3 .cursor/skills/agtsmith-screenshots/scripts/compare.py --version $(SCREENSHOT_VERSION); fi
	@echo "[screenshots-diff] complete"

CONFIGURE_SCREENSHOT_VERSION ?= v1.5.2-config-p3
CONFIGURE_PY = $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

configure-check:
	@echo "[configure-check] static + API configure tests"
	@$(CONFIGURE_PY) -m unittest scripts.tests.test_web_ui_configure scripts.tests.test_configure_ui_tag -v
	@echo "[configure-check] complete"

configure-screenshots:
	@echo "[configure-screenshots] tag=$(CONFIGURE_UI_TAG) version=$(CONFIGURE_SCREENSHOT_VERSION)"
	@CONFIGURE_UI_TAG=$(CONFIGURE_UI_TAG) SCREENSHOT_VERSION=$(CONFIGURE_SCREENSHOT_VERSION) \
		$(CONFIGURE_PY) .cursor/skills/agtsmith-screenshots/scripts/capture.py \
		--version $(CONFIGURE_SCREENSHOT_VERSION) \
		--configure-ui-tag $(CONFIGURE_UI_TAG) \
		--target-id configure-connect --target-id configure-models \
		--target-id configure-validate --target-id configure-ground
	@echo "[configure-screenshots] complete"

configure-screenshots-diff:
	@echo "[configure-screenshots-diff] current=$(CONFIGURE_SCREENSHOT_VERSION) baseline tag=$(CONFIGURE_UI_BASELINE)"
	@$(CONFIGURE_PY) .cursor/skills/agtsmith-screenshots/scripts/compare.py \
		--version $(CONFIGURE_SCREENSHOT_VERSION) \
		--baseline $(CONFIGURE_UI_BASELINE)
	@echo "[configure-screenshots-diff] complete"

configure-e2e:
	@echo "[configure-e2e] tag=$(CONFIGURE_UI_TAG)"
	@CONFIGURE_UI_TAG=$(CONFIGURE_UI_TAG) $(CONFIGURE_PY) scripts/configure_e2e.py
	@echo "[configure-e2e] complete"

configure-tag-show:
	@CONFIGURE_UI_TAG=$(CONFIGURE_UI_TAG) $(CONFIGURE_PY) scripts/configure_ui_tag.py show --tag $(CONFIGURE_UI_TAG)

configure-tag-record:
	@CONFIGURE_UI_TAG=$(CONFIGURE_UI_TAG) SCREENSHOT_VERSION=$(CONFIGURE_SCREENSHOT_VERSION) \
		CONFIGURE_UI_TESTS=configure-check $(CONFIGURE_PY) scripts/configure_ui_tag.py record \
		--tag $(CONFIGURE_UI_TAG) --screenshot-version $(CONFIGURE_SCREENSHOT_VERSION) \
		--tests configure-check
	@echo "[configure-tag-record] recorded artifacts/configure_ui/$(CONFIGURE_UI_TAG)/manifest.json"
