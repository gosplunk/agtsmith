.PHONY: help check status snapshot all langgraph-status langgraph-policy-status langgraph-policy-snapshot langgraph-policy-trend langgraph-policy-freshness langgraph-policy-trend-freshness langgraph-policy-trend-anomaly langgraph-docs-check langgraph-artifacts-check langgraph-tool-routing-check langgraph-session-check langgraph-thresholds langgraph-ops langgraph-ops-strict langgraph-run langgraph-demo langgraph-policy-demo langgraph-tool-demo langgraph-metadata-demo langgraph-chain-demo langgraph-session-demo langgraph-demo-ready langgraph-all langgraph-all-quick langgraph-gold-build langgraph-eval-prompts langgraph-topology-eval langgraph-topology-optimize agentic-check agentic-run agentic-demo agentic-session-demo agentic-status agentic-case-report agentic-demo-ready multi-model-run multi-model-check multi-model-demo multi-model-status multi-model-demo-ready model-show model-smoke model-spl-eval model-planner-eval model-planner-eval-hf model-planner-vram-smoke model-rag-ab model-spl-quality-deep spl-hardening-benchmark live-domain-benchmark live-domain-benchmark-offline spl-hardening-benchmark-botsv3 spl-hardening-benchmark-botsv3-inventory check-gold-oracles investigation-e2e spl-autonomy-check spl-autonomy-nightly env-profile-build env-profile-check env-profile-refresh env-profile-tests env-profile-schedule-install env-profile-schedule-show sourcetype-research spl-skillpack-refresh dev ui-dev docker-build docker-up docker-down docker-logs docker-deploy-build docker-deploy-up docker-deploy-down docker-deploy-logs docker-deploy-manual deployment-auth-tests ollama-log-tests tdir-core-tests kvstore-case-tests docs-index report-freshness refresh-reports ops prune-summary prune-snapshot prune-trend prune-freshness prune-dry-run prune-apply prune-ops splunk-app-package splunk-app-install-local splunk-app-symlink-dev screenshots screenshots-diff configure-check configure-screenshots configure-screenshots-diff configure-e2e configure-tag-show configure-tag-record local-lab-preflight setup-local-ui-env
.PHONY: lab-data-ui lab-data-extractions
.PHONY: docker-deploy-up-nvidia docker-deploy-hotpatch docker-deploy-contract-tests
.PHONY: internal-spl-discover internal-spl-accuracy internal-spl-accuracy-offline internal-spl-accuracy-multimodel check-internal-spl-oracles
.PHONY: linux-spl-discover linux-spl-accuracy linux-spl-accuracy-offline linux-spl-accuracy-multimodel check-linux-spl-oracles linux-sourcetype-cards spl-quality-tracker phase2-automation ten-domain-learning-loop

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
# Docker deploy images install packages onto the system interpreter (no .venv);
# fall back to python3 so env-profile-refresh and friends work in both contexts.
PYTHON_BIN := $(shell if [ -x .venv/bin/python ]; then echo .venv/bin/python; else echo python3; fi)
SPL_QUALITY_TRACKER_PORT ?= 8791
SPLUNK_APP_VERSION ?= 0.2.0-splunk
SPLUNK_HOME ?= /opt/splunk
SCREENSHOT_VERSION ?= v1.5.2
CONFIGURE_UI_TAG ?= configure-ui-dev
CONFIGURE_UI_BASELINE ?= configure-ui-p0
CASES ?= benchmarks/spl_cases.json
OUT ?= artifacts/benchmark
UNKNOWN_ENV_MODEL ?= granite4:3b
ROLLOUT_MODE ?= observe
SPL_SCENARIO_PROFILE ?= benchmarks/fixtures/scenario_environment_profile.json
SPL_LIVE_SCENARIO_PROFILE ?= artifacts/environment/environment_profile_latest.json
SPL_LIVE_SCENARIO_DIR ?= artifacts/benchmark/spl_rollout/live_scenarios
SPL_SCENARIO_MAX_CASES ?= 0
SPL_MIN_EVIDENCE_CASES ?= 12
SPL_MIN_EVIDENCE_PLATFORMS ?= 3
SPL_MIN_EVIDENCE_PER_PLATFORM ?= 2
SPL_LIVE_MCP_TIMEOUT_SEC ?= 30
SPL_LIVE_OLLAMA_TIMEOUT_SEC ?= 45
SPL_LIVE_CASE_TIMEOUT_SEC ?= 120
SPL_LIVE_RUN_TIMEOUT_SEC ?= 900
SPL_LIVE_CONCURRENCY ?= 2
SPL_LIVE_PREFLIGHT_CONCURRENCY ?= 1

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
	@echo "  make unknown-env-benchmark # cold-profile / unknown-environment SPL benchmark"
	@echo "  make live-domain-benchmark # profile-driven gold vs agtsmith SPL benchmark (live lab MCP)"
	@echo "  make spl-hardening-benchmark-botsv3 # separate BOTSv3 all-time benchmark suite"
	@echo "  make spl-hardening-benchmark-botsv3-inventory # planner-backed overview benchmark across the full BOTSv3 sourcetype inventory"
	@echo "  make check-gold-oracles # offline gold SPL oracle validation (no MCP)"
	@echo "  make investigation-e2e # Playwright Investigation UI E2E (live lab)"
	@echo "  make spl-improvement-loop [SPL_IMPROVEMENT_REPORT=...] # classify benchmark failures into learning candidates"
	@echo "  make holdout-baseline-replay # verify protected eval21 baseline without generation or MCP"
	@echo "  make holdout-eval-live # explicitly run protected eval21 release holdout"
	@echo "  make spl-plan-parity # record typed-plan/template parity manifest"
	@echo "  make spl-scenario-generate # reproducibly generate metadata-derived scenario splits"
	@echo "  make spl-train-scenario-eval # evaluate every generated training composition"
	@echo "  make spl-dev-scenario-eval # evaluate every generated development composition"
	@echo "  make spl-live-equivalence ROLLOUT_MODE=observe|prefer|enforce # live dev MCP equivalence"
	@echo "  make spl-rollout-release-gate # full regressions, sequential live modes, protected holdout"
	@echo "  make spl-rollout-report # aggregate manifests without protected case details"
	@echo "  make spl-offline-docs-index # build SPL RAG index from Splunk Offline Docs search-index.json"
	@echo "  make spl-benchmark-compare CURRENT=... # compare run JSON against baseline manifest"
	@echo "  make spl-multi-layout-matrix # offline gold oracle matrix across profile fixtures"
	@echo "  make lab-data-matrix-bootstrap # provision+verify all lab layouts then run matrix"
	@echo "  make spl-autonomy-nightly # env refresh + autonomy loop with --promote"
	@echo "  make spl-autonomy-loop [LONG_HORIZON=1] [MAX_ITERATIONS=10] # closed-loop or long-horizon autonomy"
	@echo "  make spl-phase-gate PHASE=0|1|2|3|4|5 # progressive SPL autonomy phase gate"
	@echo "  make spl-phase-report # cumulative SPL phase progress table"
	@echo "  make spl-quality-tracker [SPL_QUALITY_TRACKER_PORT=8791] # host-side SPL benchmark console (not the :8787 sidecar)"
	@echo "  make phase2-automation # run Phase 2 sign-off gates end-to-end (host; logs under artifacts/spl_autonomy/phase2_automation/)"
	@echo "  make ten-domain-learning-loop [MAX_HOURS=8] # autonomous 10-domain SPL loop with lab ingest + fixes"
	@echo "  make sourcetype-cards-build # build sourcetype oracle cards from environment profile"
	@echo "  make spl-embedding-index-build # build hybrid embedding RAG index (Ollama nomic-embed-text)"
	@echo "  make spl-domain-embedding-index-build # build domain/sourcetype embedding index for resolve_authoritative_domains_for_question retrieval"
	@echo "  make env-profile-build [FOCUS_HOST=<linux-host>] # rebuild append-only environment profile from Splunk MCP (+ optional host focus)"
	@echo "  make env-profile-check # fail if environment profile is missing/stale"
	@echo "  make env-profile-refresh # build + freshness-check environment profile (full first-time field enrichment, then incremental maintenance)"
	@echo "  make lab-data-refresh-mcp-token # ensure MCP token in config/ui.env (reuse when valid; pass FORCE_ROTATE=1 to rotate)"
	@echo "  make lab-data-provision [LAB_DATA_LAYOUT=existing_lab] # create Splunk indexes for layout profile"
	@echo "  make lab-data-extractions # install search-time XML/JSON field extractions"
	@echo "  make lab-data-generate [LAB_DATA_LAYOUT=...] [LAB_DATA_HOURS=6] [LAB_DATA_COUNT=50] # inject fresh HEC events"
	@echo "  make lab-data-ui [LAB_DATA_UI_PORT=8790] # open the local visual data generator"
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
	@echo "  make docker-deploy-build # build revision-tagged deployment image from current source"
	@echo "  make docker-deploy-up # build, run, and verify the current source revision"
	@echo "  make docker-deploy-up-nvidia # opt in to host NVIDIA metrics devices"
	@echo "  make docker-deploy-hotpatch # disabled; rebuild to preserve revision identity"
	@echo "  make docker-deploy-down # stop/remove deployment container"
	@echo "  make docker-deploy-logs # tail deployment container logs"
	@echo "  make docker-deploy-contract-tests # host compatibility and revision guard tests"
	@echo "  make docker-deploy-manual # compatibility alias for the verified Compose deploy"
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
	@echo "[check] Docker deployment contract"
	@$(MAKE) --no-print-directory docker-deploy-contract-tests
	@echo "[check] template safety"
	@.venv/bin/python scripts/check_query_templates.py
	@echo "[check] query policy regression"
	@.venv/bin/python scripts/check_query_policy.py
	@echo "[check] environment profile helper tests"
	@$(MAKE) --no-print-directory env-profile-tests
	@echo "[check] lab data studio"
	@PYTHONPATH=.:scripts .venv/bin/python -m unittest \
		scripts.tests.test_lab_data_web \
		scripts.tests.test_lab_data_generate \
		scripts.tests.test_lab_data_fidelity_extractions \
		scripts.tests.test_hec_client
	@echo "[check] operational SPL accuracy (offline)"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/run_operational_spl_accuracy.py --offline --out-dir artifacts/benchmark/operational_spl_accuracy_offline
	@echo "[check] internal SPL oracle validation (offline)"
	@$(MAKE) --no-print-directory check-internal-spl-oracles
	@$(MAKE) --no-print-directory internal-spl-accuracy-offline
	@$(MAKE) --no-print-directory check-linux-spl-oracles
	@$(MAKE) --no-print-directory linux-spl-accuracy-offline
	@PYTHONPATH=.:scripts .venv/bin/python -m unittest scripts.tests.test_internal_spl_accuracy
	@PYTHONPATH=.:scripts .venv/bin/python -m unittest scripts.tests.test_index_activity_profile scripts.tests.test_operational_spl_accuracy scripts.tests.test_index_question_routing scripts.tests.test_apache_intent
	@echo "[check] SPL autonomy phase modules"
	@PYTHONPATH=.:scripts .venv/bin/python -m unittest \
		scripts.tests.test_sourcetype_cards \
		scripts.tests.test_spl_query_schema \
		scripts.tests.test_spl_field_binding \
		scripts.tests.test_spl_structure_validate \
		scripts.tests.test_spl_domain_knowledge \
		scripts.tests.test_run_spl_phase_gate \
		scripts.tests.test_spl_autonomy_fix_dispatch \
		scripts.tests.test_spl_query_normalize
	@echo "[check] gold SPL oracle validation"
	@$(MAKE) --no-print-directory check-gold-oracles
	@echo "[check] core tdir enrichment tests"
	@$(MAKE) --no-print-directory tdir-core-tests
	@echo "[check] kvstore case backend tests"
	@$(MAKE) --no-print-directory kvstore-case-tests
	@echo "[check] saved query library tests"
	@$(MAKE) --no-print-directory saved-query-library-tests
	@echo "[check] configure page tests"
	@$(MAKE) --no-print-directory configure-check
	@echo "[check] deployment auth contract"
	@$(MAKE) --no-print-directory deployment-auth-tests
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
	@echo "[model-spl-eval] full spl_cases.json writer benchmark (few-shot prompts)"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/evaluate_spl_writer_models.py --cases benchmarks/spl_cases.json --models "$${OLLAMA_MODEL_QUERY_WRITER:-granite4:3b}"
	@echo "[model-spl-eval] complete"

model-spl-eval-quick:
	@echo "[model-spl-eval-quick] 5-prompt smoke for query-writer SPL model"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/evaluate_spl_writer_models.py --cases quick
	@echo "[model-spl-eval-quick] complete"

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

unknown-env-benchmark:
	@echo "[unknown-env-benchmark] cold-profile / unknown-environment SPL benchmark"
	@AGTSMITH_WRITER_MODE=constrained AGTSMITH_TEMPLATE_OVERRIDE=fallback \
		PYTHONPATH=.:scripts .venv/bin/python scripts/run_unknown_env_benchmark.py --model "$(UNKNOWN_ENV_MODEL)"
	@echo "[unknown-env-benchmark] complete"

LIVE_DOMAIN_BENCHMARK_OUT ?= artifacts/spl_autonomy/live_benchmark

live-domain-benchmark:
	@echo "[live-domain-benchmark] profile-driven gold vs agtsmith SPL benchmark"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/run_live_domain_benchmark.py --out-root $(LIVE_DOMAIN_BENCHMARK_OUT) $(LIVE_DOMAIN_BENCHMARK_ARGS)
	@echo "[live-domain-benchmark] complete"

live-domain-benchmark-offline:
	@echo "[live-domain-benchmark-offline] offline compare (no MCP execution)"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/run_live_domain_benchmark.py --out-root $(LIVE_DOMAIN_BENCHMARK_OUT) --skip-mcp
	@echo "[live-domain-benchmark-offline] complete"

check-gold-oracles:
	@echo "[check-gold-oracles] validating gold SPL oracles offline"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/check_gold_spl_oracles.py
	@echo "[check-gold-oracles] complete"

spl-multi-layout-matrix:
	@echo "[spl-multi-layout-matrix] offline gold oracle matrix across profile fixtures"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/run_multi_layout_matrix.py \
		--out artifacts/benchmark/multi_layout_matrix_latest.json
	@echo "[spl-multi-layout-matrix] complete"

lab-data-matrix-bootstrap:
	@echo "[lab-data-matrix-bootstrap] bootstrap each lab layout and run offline matrix"
	@$(MAKE) --no-print-directory lab-data-extractions
	@for layout in existing_lab multi_index_ideal minimal_ci cloud_only; do \
		echo "[lab-data-matrix-bootstrap] layout=$$layout"; \
		$(MAKE) --no-print-directory lab-data-provision LAB_DATA_LAYOUT=$$layout || exit 1; \
		$(MAKE) --no-print-directory lab-data-generate LAB_DATA_LAYOUT=$$layout || exit 1; \
		$(MAKE) --no-print-directory lab-data-verify LAB_DATA_LAYOUT=$$layout || exit 1; \
	done
	@$(MAKE) --no-print-directory env-profile-refresh
	@$(MAKE) --no-print-directory spl-multi-layout-matrix
	@echo "[lab-data-matrix-bootstrap] complete"

lab-data-hec-sync:
	@echo "[lab-data-hec-sync] update HEC allowed indexes for layout=$(LAB_DATA_LAYOUT)"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/lab_data/setup_hec.py --layout "$(LAB_DATA_LAYOUT)"
	@echo "[lab-data-hec-sync] complete"

lab-data-expanded-bootstrap: lab-data-refresh-mcp-token
	@echo "[lab-data-expanded-bootstrap] provision expanded heterogeneous lab indexes and onboard all domains"
	@$(MAKE) --no-print-directory lab-data-provision LAB_DATA_LAYOUT=expanded_lab
	@$(MAKE) --no-print-directory lab-data-hec-sync LAB_DATA_LAYOUT=expanded_lab
	@$(MAKE) --no-print-directory lab-data-extractions
	@$(MAKE) --no-print-directory lab-data-generate LAB_DATA_LAYOUT=expanded_lab LAB_DATA_HOURS=24 LAB_DATA_COUNT=80
	@$(MAKE) --no-print-directory lab-data-verify LAB_DATA_LAYOUT=expanded_lab
	@$(MAKE) --no-print-directory env-profile-refresh
	@echo "[lab-data-expanded-bootstrap] complete"

spl-expanded-live-benchmark: lab-data-expanded-bootstrap
	@echo "[spl-expanded-live-benchmark] live MCP domain benchmark against expanded lab profile"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/run_live_domain_benchmark.py \
		--out-root $(LIVE_DOMAIN_BENCHMARK_OUT) --cases-from-json
	@$(MAKE) --no-print-directory spl-multi-layout-matrix
	@echo "[spl-expanded-live-benchmark] complete"

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

holdout-baseline-replay:
	@echo "[holdout-baseline-replay] verifying frozen eval21 baseline"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/run_holdout_eval.py
	@echo "[holdout-baseline-replay] complete"

holdout-eval-live:
	@echo "[holdout-eval-live] running protected release holdout; never feed this report to improvement targets"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/run_holdout_eval.py --live --min-equivalence 0.75 --out artifacts/benchmark/holdout_eval/latest.json
	@echo "[holdout-eval-live] complete"

spl-plan-parity:
	@echo "[spl-plan-parity] validating template representation and read-only policy"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/run_spl_plan_parity.py
	@echo "[spl-plan-parity] complete"

spl-scenario-generate:
	@echo "[spl-scenario-generate] profile=$(SPL_SCENARIO_PROFILE)"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/generate_profile_scenarios.py \
		--profile "$(SPL_SCENARIO_PROFILE)" \
		--out-dir benchmarks/scenario_splits/generated
	@echo "[spl-scenario-generate] complete"

spl-live-scenario-generate:
	@echo "[spl-live-scenario-generate] current_profile=$(SPL_LIVE_SCENARIO_PROFILE)"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/generate_profile_scenarios.py \
		--profile "$(SPL_LIVE_SCENARIO_PROFILE)" \
		--out-dir "$(SPL_LIVE_SCENARIO_DIR)"
	@echo "[spl-live-scenario-generate] complete"

spl-reference-preflight: spl-live-scenario-generate
	@echo "[spl-reference-preflight] deterministic references only"
	@AGTSMITH_ENVIRONMENT_PROFILE_PATH="$(SPL_LIVE_SCENARIO_PROFILE)" \
		PYTHONPATH=.:scripts .venv/bin/python scripts/run_generated_scenario_eval.py \
		--split dev --execution live --mode observe \
		--scenario-dir "$(SPL_LIVE_SCENARIO_DIR)" \
		--max-cases "$(SPL_SCENARIO_MAX_CASES)" \
		--reference-preflight-only \
		--min-evidence-cases "$(SPL_MIN_EVIDENCE_CASES)" \
		--min-evidence-platforms "$(SPL_MIN_EVIDENCE_PLATFORMS)" \
		--min-evidence-per-platform "$(SPL_MIN_EVIDENCE_PER_PLATFORM)" \
		--mcp-request-timeout-sec "$(SPL_LIVE_MCP_TIMEOUT_SEC)" \
		--ollama-request-timeout-sec "$(SPL_LIVE_OLLAMA_TIMEOUT_SEC)" \
		--case-timeout-sec "$(SPL_LIVE_CASE_TIMEOUT_SEC)" \
		--run-timeout-sec "$(SPL_LIVE_RUN_TIMEOUT_SEC)" \
		--live-concurrency "$(SPL_LIVE_CONCURRENCY)" \
		--reference-preflight-concurrency "$(SPL_LIVE_PREFLIGHT_CONCURRENCY)"
	@echo "[spl-reference-preflight] complete"

spl-train-scenario-eval:
	@echo "[spl-train-scenario-eval] full static training composition gate"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/run_generated_scenario_eval.py \
		--split train --execution static --mode observe
	@echo "[spl-train-scenario-eval] complete"

spl-dev-scenario-eval:
	@echo "[spl-dev-scenario-eval] full static development composition gate"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/run_generated_scenario_eval.py \
		--split dev --execution static --mode observe
	@echo "[spl-dev-scenario-eval] complete"

spl-live-equivalence: spl-live-scenario-generate
	@echo "[spl-live-equivalence] mode=$(ROLLOUT_MODE) max_cases=$(SPL_SCENARIO_MAX_CASES)"
	@AGTSMITH_ENVIRONMENT_PROFILE_PATH="$(SPL_LIVE_SCENARIO_PROFILE)" \
		PYTHONPATH=.:scripts .venv/bin/python scripts/run_generated_scenario_eval.py \
		--split dev --execution live --mode "$(ROLLOUT_MODE)" \
		--scenario-dir "$(SPL_LIVE_SCENARIO_DIR)" \
		--max-cases "$(SPL_SCENARIO_MAX_CASES)" \
		--min-evidence-cases "$(SPL_MIN_EVIDENCE_CASES)" \
		--min-evidence-platforms "$(SPL_MIN_EVIDENCE_PLATFORMS)" \
		--min-evidence-per-platform "$(SPL_MIN_EVIDENCE_PER_PLATFORM)" \
		--mcp-request-timeout-sec "$(SPL_LIVE_MCP_TIMEOUT_SEC)" \
		--ollama-request-timeout-sec "$(SPL_LIVE_OLLAMA_TIMEOUT_SEC)" \
		--case-timeout-sec "$(SPL_LIVE_CASE_TIMEOUT_SEC)" \
		--run-timeout-sec "$(SPL_LIVE_RUN_TIMEOUT_SEC)" \
		--live-concurrency "$(SPL_LIVE_CONCURRENCY)" \
		--reference-preflight-concurrency "$(SPL_LIVE_PREFLIGHT_CONCURRENCY)"
	@echo "[spl-live-equivalence] complete"

spl-rollout-offline-gate: spl-plan-parity spl-train-scenario-eval spl-dev-scenario-eval
	@echo "[spl-rollout-offline-gate] complete"

spl-rollout-regressions: check check-gold-oracles spl-multi-layout-matrix
	@$(MAKE) --no-print-directory unknown-env-benchmark
	@$(MAKE) --no-print-directory operational-spl-accuracy-multimodel
	@PYTHONPATH=.:scripts .venv/bin/python -m unittest -v \
		scripts.tests.test_apache_intent \
		scripts.tests.test_explicit_sourcetype_routing
	@echo "[spl-rollout-regressions] complete"

spl-rollout-live-gate:
	@set -e; for mode in observe prefer enforce; do \
		echo "[spl-rollout-live-gate] validating $$mode"; \
		$(MAKE) --no-print-directory spl-live-equivalence ROLLOUT_MODE=$$mode SPL_SCENARIO_MAX_CASES=$(SPL_SCENARIO_MAX_CASES); \
	done
	@echo "[spl-rollout-live-gate] complete"

spl-holdout-release-gate:
	@$(MAKE) --no-print-directory holdout-eval-live
	@$(MAKE) --no-print-directory spl-rollout-report
	@echo "[spl-holdout-release-gate] complete"

spl-rollout-report:
	@PYTHONPATH=.:scripts .venv/bin/python scripts/build_spl_rollout_report.py
	@echo "[spl-rollout-report] complete"

spl-rollout-release-gate: spl-rollout-regressions spl-rollout-offline-gate spl-rollout-live-gate spl-holdout-release-gate
	@echo "[spl-rollout-release-gate] complete"

spl-improvement-cycle:
	@echo "[spl-improvement-cycle] failure classify + skillpack/cards/embed refresh + re-benchmark"
	@set -a && [ -f config/ui.env ] && . config/ui.env; set +a; \
		AGTSMITH_TEMPLATE_OVERRIDE=fallback AGTSMITH_WRITER_MODE=$${AGTSMITH_WRITER_MODE:-constrained} \
		PYTHONPATH=.:scripts .venv/bin/python scripts/run_spl_improvement_cycle.py \
		--report $(SPL_IMPROVEMENT_REPORT) \
		--target-score $${SPL_TARGET_SCORE:-85} \
		--max-cycles $${SPL_MAX_CYCLES:-5} \
		$(if $(filter 1,$(SPL_PHASE_QUICK)),--quick,)
	@echo "[spl-improvement-cycle] complete"

SPL_OFFLINE_DOCS_SOURCE ?= /home/joehaga/ai_projects/Splunk4Offlinedocs/artifacts/staging/splunk_offline_docs/appserver/static/docs/manifest/search-index.json
SPL_OFFLINE_DOCS_RAG_OUT ?= artifacts/knowledge/spl_offline_docs_rag_index.json

spl-offline-docs-index:
	@echo "[spl-offline-docs-index] building SPL-focused RAG index from offline docs"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/build_spl_offline_docs_rag_index.py --source $(SPL_OFFLINE_DOCS_SOURCE) --out $(SPL_OFFLINE_DOCS_RAG_OUT)
	@echo "[spl-offline-docs-index] complete"

spl-offline-docs-index-if-stale:
	@echo "[spl-offline-docs-index-if-stale] rebuilding offline docs RAG index when source is newer"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/build_spl_offline_docs_rag_index.py --source $(SPL_OFFLINE_DOCS_SOURCE) --out $(SPL_OFFLINE_DOCS_RAG_OUT) --if-stale
	@echo "[spl-offline-docs-index-if-stale] complete"

operational-spl-accuracy:
	@echo "[operational-spl-accuracy] running operational SPL accuracy harness"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/run_operational_spl_accuracy.py --out-dir artifacts/benchmark/operational_spl_accuracy
	@echo "[operational-spl-accuracy] complete"

operational-spl-accuracy-offline:
	@echo "[operational-spl-accuracy-offline] operational SPL routing/policy/structure checks"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/run_operational_spl_accuracy.py --offline --out-dir artifacts/benchmark/operational_spl_accuracy_offline
	@echo "[operational-spl-accuracy-offline] complete"

operational-spl-accuracy-multimodel:
	@echo "[operational-spl-accuracy-multimodel] template + live multi-model operational accuracy"
	@AGTSMITH_TEMPLATE_OVERRIDE=fallback AGTSMITH_WRITER_MODE=constrained \
		PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/run_operational_spl_accuracy.py --multi-model --out-dir artifacts/benchmark/operational_spl_accuracy
	@echo "[operational-spl-accuracy-multimodel] complete"

check-internal-spl-oracles:
	@echo "[check-internal-spl-oracles] validating internal SPL oracle corpus offline"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/check_internal_spl_oracles.py
	@echo "[check-internal-spl-oracles] complete"

internal-spl-discover:
	@echo "[internal-spl-discover] discovering _internal/_audit/_introspection catalog via MCP"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/discover_internal_index_catalog.py
	@echo "[internal-spl-discover] complete"

internal-spl-accuracy:
	@echo "[internal-spl-accuracy] running internal SPL accuracy harness (template path)"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/run_internal_spl_accuracy.py --out-dir artifacts/spl_autonomy/internal_benchmark
	@echo "[internal-spl-accuracy] complete"

internal-spl-accuracy-offline:
	@echo "[internal-spl-accuracy-offline] internal SPL routing/policy/structure checks"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/run_internal_spl_accuracy.py --offline --out-dir artifacts/spl_autonomy/internal_benchmark
	@echo "[internal-spl-accuracy-offline] complete"

internal-spl-accuracy-multimodel:
	@echo "[internal-spl-accuracy-multimodel] template + live multi-model internal accuracy"
	@AGTSMITH_TEMPLATE_OVERRIDE=fallback AGTSMITH_WRITER_MODE=constrained \
		PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/run_internal_spl_accuracy.py --multi-model --out-dir artifacts/spl_autonomy/internal_benchmark
	@echo "[internal-spl-accuracy-multimodel] complete"

internal-sourcetype-cards:
	@echo "[internal-sourcetype-cards] building internal sourcetype oracle cards"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/build_sourcetype_cards.py \
		--scope internal --out artifacts/environment/internal_sourcetype_cards.json
	@echo "[internal-sourcetype-cards] complete"

check-linux-spl-oracles:
	@echo "[check-linux-spl-oracles] validating Linux SPL oracle corpus offline"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/check_linux_spl_oracles.py
	@echo "[check-linux-spl-oracles] complete"

linux-spl-discover:
	@echo "[linux-spl-discover] discovering linux index catalog via MCP"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/discover_linux_index_catalog.py
	@echo "[linux-spl-discover] complete"

linux-spl-accuracy:
	@echo "[linux-spl-accuracy] running Linux SPL accuracy harness (template path)"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/run_linux_spl_accuracy.py --out-dir artifacts/spl_autonomy/linux_benchmark
	@echo "[linux-spl-accuracy] complete"

linux-spl-accuracy-offline:
	@echo "[linux-spl-accuracy-offline] Linux SPL routing/policy/structure checks"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/run_linux_spl_accuracy.py --offline --out-dir artifacts/spl_autonomy/linux_benchmark
	@echo "[linux-spl-accuracy-offline] complete"

linux-spl-accuracy-multimodel:
	@echo "[linux-spl-accuracy-multimodel] template + live multi-model Linux accuracy"
	@AGTSMITH_TEMPLATE_OVERRIDE=fallback AGTSMITH_WRITER_MODE=constrained \
		PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/run_linux_spl_accuracy.py --multi-model --out-dir artifacts/spl_autonomy/linux_benchmark
	@echo "[linux-spl-accuracy-multimodel] complete"

linux-sourcetype-cards:
	@echo "[linux-sourcetype-cards] building linux sourcetype oracle cards"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/build_sourcetype_cards.py \
		--scope linux --out artifacts/environment/linux_sourcetype_cards.json
	@echo "[linux-sourcetype-cards] complete"

spl-quality-tracker:
	@echo "[spl-quality-tracker] host-side console at http://127.0.0.1:$(SPL_QUALITY_TRACKER_PORT)/"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/spl_quality_tracker.py --serve --host 127.0.0.1 --port $(SPL_QUALITY_TRACKER_PORT)

phase2-automation:
	@./scripts/run_phase2_automation.sh

MAX_HOURS ?= 8
TEN_DOMAIN_MAX_CYCLES ?= 12
SKIP_BOOTSTRAP ?= 0

ten-domain-learning-loop:
	@echo "[ten-domain-learning-loop] max_hours=$(MAX_HOURS) target=90% domains=10 skip_bootstrap=$(SKIP_BOOTSTRAP)"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/run_ten_domain_learning_loop.py --max-hours $(MAX_HOURS) --max-cycles $(TEN_DOMAIN_MAX_CYCLES) $(if $(filter 1,$(SKIP_BOOTSTRAP)),--skip-bootstrap,)

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

PHASE ?= 0
SPL_PHASE_QUICK ?= 0
SPL_PHASE_USE_EXISTING ?= 0
LONG_HORIZON ?= 0
MAX_ITERATIONS ?= 10

spl-phase-gate:
	@echo "[spl-phase-gate] phase=$(PHASE) quick=$(SPL_PHASE_QUICK) use_existing=$(SPL_PHASE_USE_EXISTING)"
	@AGTSMITH_TEMPLATE_OVERRIDE=fallback AGTSMITH_WRITER_MODE=$${AGTSMITH_WRITER_MODE:-constrained} \
		PYTHONPATH=.:scripts .venv/bin/python scripts/run_spl_phase_gate.py --phase=$(PHASE) \
		$(if $(filter 1,$(SPL_PHASE_QUICK)),--quick,) \
		$(if $(filter 1,$(SPL_PHASE_USE_EXISTING)),--use-existing,)
	@echo "[spl-phase-gate] complete"

spl-phase-report:
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/run_spl_phase_gate.py --report --phase=0
	@echo "[spl-phase-report] complete"

spl-phases-live:
	@echo "[spl-phases-live] executing live phase gates 0-6 (real benchmarks, no artifact reuse)"
	@set -e; for phase in 0 1 2 3 4 5 6; do \
		echo "=== LIVE PHASE $$phase ==="; \
		$(MAKE) --no-print-directory spl-phase-gate PHASE=$$phase SPL_PHASE_USE_EXISTING=0; \
	done
	@$(MAKE) --no-print-directory spl-phase-report
	@echo "[spl-phases-live] complete"

sourcetype-cards-build:
	@echo "[sourcetype-cards-build] projecting sourcetype oracle cards from environment profile"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/build_sourcetype_cards.py
	@echo "[sourcetype-cards-build] complete"

spl-embedding-index-build:
	@echo "[spl-embedding-index-build] building hybrid SPL embedding index"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/build_spl_embedding_index.py --skip-embed
	@echo "[spl-embedding-index-build] complete"

spl-domain-embedding-index-build:
	@echo "[spl-domain-embedding-index-build] building domain/sourcetype embedding index (Ollama nomic-embed-text; falls back to metadata-only if unreachable)"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/build_domain_embedding_index.py \
		|| PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/build_domain_embedding_index.py --skip-embed
	@echo "[spl-domain-embedding-index-build] complete"

spl-domain-patterns-build:
	@echo "[spl-domain-patterns-build] building SPL domain pattern oracle from templates and benchmarks"
	@PYTHONPATH=.:scripts $(PYTHON_BIN) scripts/build_spl_domain_patterns.py
	@echo "[spl-domain-patterns-build] complete"

spl-autonomy-loop:
	@echo "[spl-autonomy-loop] long_horizon=$(LONG_HORIZON) max_iterations=$(MAX_ITERATIONS)"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/spl_autonomy_loop.py \
		--out-dir $(SPL_AUTONOMY_OUT) \
		--cases $(SPL_AUTONOMY_CASES) \
		--max-iterations $(MAX_ITERATIONS) \
		--skip-preflight --skip-e2e \
		$(if $(filter 1,$(LONG_HORIZON)),--long-horizon,) \
		$(if $(filter 1,$(SPL_PHASE_QUICK)),--quick,) \
		$(if $(filter 1,$(SPL_PHASE_USE_EXISTING)),--use-existing-artifacts,)
	@echo "[spl-autonomy-loop] complete"

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
	@$(LAB_DATA_RUN) $(PYTHON_BIN) scripts/build_environment_profile.py --snapshot --focus-host "$(FOCUS_HOST)"
	@echo "[env-profile-build] complete"

env-profile-check:
	@echo "[env-profile-check] checking profile freshness"
	@$(LAB_DATA_RUN) $(PYTHON_BIN) scripts/check_environment_profile_freshness.py --max-age-minutes $(ENV_PROFILE_MAX_AGE_MINUTES)
	@echo "[env-profile-check] complete"

LAB_DATA_LAYOUT ?= existing_lab
LAB_DATA_HOURS ?= 6
LAB_DATA_COUNT ?= 50
LAB_DATA_UI_PORT ?= 8790
LAB_DATA_UI_NO_BROWSER ?= 0
LAB_DATA_RUN = $(PYTHON_BIN) scripts/lab_data/run_lab_data.py --

lab-data-provision:
	@echo "[lab-data-provision] creating indexes for layout=$(LAB_DATA_LAYOUT)"
	@$(LAB_DATA_RUN) .venv/bin/python scripts/lab_data_provision.py --layout "$(LAB_DATA_LAYOUT)"
	@echo "[lab-data-provision] complete"

lab-data-refresh-mcp-token:
	@echo "[lab-data-refresh-mcp-token] ensure MCP token for user mcp -> config/ui.env"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/lab_data/refresh_mcp_token.py $(if $(FORCE_ROTATE),--force-rotate,)
	@echo "[lab-data-refresh-mcp-token] complete"

lab-data-extractions:
	@echo "[lab-data-extractions] installing source-native XML/JSON search-time fields"
	@$(LAB_DATA_RUN) .venv/bin/python scripts/lab_data/setup_fidelity_extractions.py
	@echo "[lab-data-extractions] complete"

lab-data-generate:
	@echo "[lab-data-generate] injecting events layout=$(LAB_DATA_LAYOUT) hours=$(LAB_DATA_HOURS) count=$(LAB_DATA_COUNT)"
	@$(LAB_DATA_RUN) .venv/bin/python scripts/lab_data_generate.py \
		--layout "$(LAB_DATA_LAYOUT)" --hours "$(LAB_DATA_HOURS)" --count "$(LAB_DATA_COUNT)"
	@echo "[lab-data-generate] complete"

lab-data-ui:
	@echo "[lab-data-ui] opening local Splunk Lab Data Studio on port $(LAB_DATA_UI_PORT)"
	@$(LAB_DATA_RUN) .venv/bin/python scripts/lab_data_web.py \
		--host 127.0.0.1 --port "$(LAB_DATA_UI_PORT)" \
		$(if $(filter 1,$(LAB_DATA_UI_NO_BROWSER)),--no-browser,)

lab-data-verify:
	@echo "[lab-data-verify] MCP row check for generated lab data"
	@$(LAB_DATA_RUN) .venv/bin/python scripts/lab_data_verify.py --layout "$(LAB_DATA_LAYOUT)"
	@echo "[lab-data-verify] complete"

lab-data-cleanup:
	@echo "[lab-data-cleanup] removing tagged generator events"
	@$(LAB_DATA_RUN) .venv/bin/python scripts/lab_data_cleanup.py --layout "$(LAB_DATA_LAYOUT)"
	@echo "[lab-data-cleanup] complete"

lab-data-bootstrap: lab-data-refresh-mcp-token lab-data-provision lab-data-extractions lab-data-generate lab-data-verify env-profile-refresh
	@echo "[lab-data-bootstrap] complete"

lab-data-install:
	@echo "[lab-data-install] enable HEC, configure ui.env, bootstrap lab data"
	@bash scripts/lab_data/install_lab_data_prereqs.sh
	@echo "[lab-data-install] complete"

spl-skillpack-refresh:
	@echo "[spl-skillpack-refresh] building SPL skillpack"
	@$(PYTHON_BIN) scripts/build_spl_skillpack.py
	@echo "[spl-skillpack-refresh] complete"

env-profile-refresh: env-profile-build env-profile-check sourcetype-cards-build spl-embedding-index-build spl-domain-embedding-index-build spl-domain-patterns-build spl-offline-docs-index-if-stale spl-skillpack-refresh
	@echo "[env-profile-refresh] complete"

env-profile-tests:
	@echo "[env-profile-tests] running parser/validation unit tests"
	@PYTHONPATH=.:scripts .venv/bin/python -m unittest scripts.tests.test_environment_profile scripts.tests.test_index_activity_profile scripts.tests.test_spl_query_repair scripts.tests.test_intent_field_contracts scripts.tests.test_langgraph_coherence_wiring scripts.tests.test_lab_data_config scripts.tests.test_setup_hec scripts.tests.test_question_routing scripts.tests.test_spl_writer_prompt scripts.tests.test_spl_hardening_scorer scripts.tests.test_live_domain_benchmark scripts.tests.test_spl_field_strategy scripts.tests.test_field_discovery_wiring scripts.tests.test_post_execution_diagnostics scripts.tests.test_domain_embedding_retrieval scripts.tests.test_edge_question_classifier
	@echo "[env-profile-tests] complete"

env-profile-schedule-install:
	@echo "[env-profile-schedule-install] installing cron scheduler (INTERVAL_MIN=$${INTERVAL_MIN:-45})"
	@INTERVAL_MIN=$${INTERVAL_MIN:-45} bash scripts/install_env_profile_scheduler.sh
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
	@echo "[docker-deploy-build] building revision-tagged deployment image from current source"
	@python3 scripts/docker_deploy.py build
	@echo "[docker-deploy-build] complete"

docker-deploy-up:
	@echo "[docker-deploy-up] building and verifying current source on host port 8787"
	@python3 scripts/docker_deploy.py up
	@echo "[docker-deploy-up] complete (private named config volume; enter runtime credentials in the UI)"
	@echo "[docker-deploy-up] fresh volume: complete first-run setup at /setup/first-run"
	@echo "[docker-deploy-up] restart persistence: docker compose down preserves the config volume"
	@echo "[docker-deploy-up] reset auth: remove the Compose-managed agtsmith_deploy_config volume, then rerun"

docker-deploy-up-nvidia:
	@echo "[docker-deploy-up-nvidia] building and verifying with optional NVIDIA metrics access"
	@python3 scripts/docker_deploy.py up --nvidia
	@echo "[docker-deploy-up-nvidia] complete"

docker-deploy-hotpatch:
	@echo "[docker-deploy-hotpatch] disabled: hotpatching invalidates image revision identity" >&2
	@echo "[docker-deploy-hotpatch] use make docker-deploy-up to rebuild and verify current source" >&2
	@false

docker-deploy-down:
	@echo "[docker-deploy-down] stopping deployment container"
	@python3 scripts/docker_deploy.py down
	@echo "[docker-deploy-down] complete"

docker-deploy-logs:
	@python3 scripts/docker_deploy.py logs

docker-deploy-contract-tests:
	@PYTHONPATH=.:scripts .venv/bin/python -m unittest scripts.tests.test_docker_deploy_contract

deployment-auth-tests:
	@echo "[deployment-auth-tests] verifying fresh-install auth contract"
	@PYTHONPATH=.:scripts .venv/bin/python -m unittest scripts.tests.test_deployment_auth_contract
	@echo "[deployment-auth-tests] complete"

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

saved-query-library-tests:
	@echo "[saved-query-library-tests] running saved query library tests"
	@PYTHONPATH=.:scripts .venv/bin/python -m unittest \
		scripts.tests.test_saved_query_library \
		scripts.tests.test_build_spl_embedding_index \
		scripts.tests.test_saved_queries_api
	@echo "[saved-query-library-tests] complete"

multi-model-run:
	@echo "[multi-model-run] question=$(QUESTION)"
	@PYTHONPATH=.:scripts .venv/bin/python scripts/langgraph_multi_model_soc.py --write-artifact "$(QUESTION)"
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
