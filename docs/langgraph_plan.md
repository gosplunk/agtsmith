# LangGraph Plan

## Objective
Introduce LangGraph only after baseline infrastructure and Splunk MCP call path are stable.

## Phase Sequence
1. Phase 1 (current): infrastructure validation and wrapper-first model access
2. Phase 2: Splunk MCP integration with read-only first query flow
3. Phase 3: LangGraph workflow integration
4. Phase 4: optional UI, memory, RAG, and reporting enhancements

## Planned Graph Responsibilities
- Input intent handling
- Tool-call decisioning for Splunk MCP
- Response synthesis and summarization
- Logging hooks for each state transition
- Guardrails for safe/restricted query behavior
- Query-policy validation for planned tool arguments before execution

## Initial Node Candidates
- `ingest_question`
- `plan_query`
- `select_splunk_tool`
- `run_splunk_tool`
- `analyze_results`
- `compose_answer`
- `log_step`

## Current Pre-LangGraph Working Baseline
- Script: `scripts/minimal_question_to_answer.py`
- Proven path:
  1. question ingest
  2. safe query mapping
  3. MCP `splunk_run_query` call
  4. Ollama summary generation
- This script is the reference behavior to preserve when splitting logic into LangGraph nodes.
- Current mapping has two validated templates:
  - sourcetype/internal activity view
  - top indexes activity view
  - auth/failed-login activity view
- Template metadata is now normalized in code (`intent`, `keywords`, query bounds, `summary_hint`), which maps directly to future LangGraph state fields.
- Template metadata is now split into a dedicated module (`scripts/query_templates.py`) so planning logic and template data can evolve independently.

## First Implemented LangGraph Baseline (2026-03-08)
- Script: `scripts/langgraph_minimal_flow.py`
- Implemented nodes:
  1. `ingest_question`
  2. `plan_query`
  3. `select_splunk_tool`
  4. `run_splunk_query`
  5. `summarize_results`
  6. `finalize`
- Data path:
  - question -> template intent/query planning -> MCP query execution -> Ollama summary -> structured output
- Current state:
  - synchronous single-path graph
  - conditional branching now added via `guardrail_check`
  - intended as migration bridge from script pipeline to graph-first architecture

### Guardrail Branch (Added)
- Node: `guardrail_check`
- Purpose:
  - block non-read-only intent patterns (for example delete/restart/modify wording)
- Routing:
  - supported -> `validate_query_policy`
  - blocked -> `finalize` (no query execution)

### Query Policy Validation (Added)
- Node: `validate_query_policy`
- Purpose:
  - validate planned Splunk query arguments before execution
  - enforce starter policy for:
    - read-style query prefix (`search ...`)
    - forbidden risky query terms (for example `| outputlookup`, `| collect`)
    - required time bounds
    - bounded row limit
- Routing:
  - policy pass -> `run_splunk_query`
  - policy fail -> `finalize` (no query execution)
- State fields:
  - `query_policy_ok`
  - `query_policy_reason`
- Regression check:
  - `python scripts/check_query_policy.py`
  - covered by `make check`
- Demo path check:
  - `make langgraph-policy-demo`
  - includes a policy-fail run using `--row-limit-override 500`

### Planner Observability (Added)
- Planning node now emits:
  - `intent`
  - `intent_confidence` (starter heuristic score)
  - `planner_reason` (human-readable why the intent was chosen)
- Purpose:
  - make pre-query decisioning transparent for debugging and future policy controls

### Tool Selection (Added)
- Node: `select_splunk_tool`
- Current behavior:
  - selects `splunk_run_query` for read-only query-analysis path
  - selects `splunk_get_indexes` for index-inventory wording (for example "list indexes I can access")
  - selects `splunk_get_metadata` for metadata inventory wording (for example "list hosts metadata")
  - selects `splunk_get_info` for Splunk instance info wording (for example "show Splunk version details")
- State field:
  - `selected_tool`
- Additional state field:
  - `metadata_args` (planned arguments when metadata tool is selected)
  - `tool_chain_mode` (planned two-tool chain mode when requested)
- Purpose:
  - make tool routing explicit in graph state and decision logs before execution
  - provide a clear extension point for future multi-tool routing

### Two-Tool Chain Planning (Added)
- Node: `plan_tool_chain`
- Current behavior:
  - detects chain mode `indexes_to_metadata_sourcetypes` for wording such as:
    - "investigate top index"
    - "drill down top index"
    - "index drilldown"
  - plans second tool:
    - `splunk_get_metadata`
  - plans second-tool arguments with placeholder index:
    - `index=__TOP_INDEX_FROM_PRIMARY__`
    - `type=sourcetypes`
    - bounded time window and row limit
- Additional state fields:
  - `chain_second_tool`
  - `chain_second_tool_args`
- Purpose:
  - make multi-step tool chaining explicit and auditable before execution.

### Tool Allowlist Validation (Added)
- Node: `validate_selected_tool`
- Current behavior:
  - allows `splunk_run_query`, `splunk_get_indexes`, `splunk_get_metadata`, and `splunk_get_info`
  - blocks any unexpected selected tool value before execution
  - applies metadata argument policy checks when `splunk_get_metadata` is selected:
    - allowed `type`: `hosts|sources|sourcetypes`
    - bounded metadata `row_limit` max: `200`
    - requires `earliest_time` and `latest_time`
- State fields:
  - `selected_tool_allowed`
  - `selected_tool_reason`
- Purpose:
  - enforce explicit safe-tool allowlist before tool execution
  - improve failure clarity in decision logs

### Secondary Tool Execution (Added)
- Node: `run_second_tool`
- Current behavior:
  - resolves `__TOP_INDEX_FROM_PRIMARY__` from first tool rows (`title` field fallback `_internal`)
  - executes planned second tool (`splunk_get_metadata`)
  - merges primary + secondary results into chain-aware `splunk_data` structure
  - records per-step row counts and mapped arguments in `chain_steps`
- Routing:
  - `run_splunk_query` -> `run_second_tool` when chain is planned
  - otherwise `run_splunk_query` -> `summarize_results`
- Purpose:
  - provide a controlled starter investigation chain while preserving single-tool behavior.

### Decision Trace Logging (Added)
- Graph state now includes `decision_log` (list of node-level decision entries).
- Current entries include:
  - question ingest acceptance
  - planner intent/confidence/reason
  - guardrail decision and reason
  - chain planning decision
  - query row count (when query executed)
  - second-tool row count (when chain executed)
  - summary generation status (when summary executed)
- Purpose:
  - provide run-level traceability for debugging, auditing, and future evaluation tooling.

### Session Memory (Added)
- CLI option:
  - `--session-id <id>`
- Behavior:
  - loads lightweight context from `docs/logs/sessions/session_<id>.json`
  - feeds recent question context into summarization prompt
  - persists updated session context after each run
- Stored fields:
  - `recent_questions`
  - `recent_tools`
  - `last_rows_returned`
  - `last_summary_preview`
- Purpose:
  - provide minimal investigation continuity in the lab without full memory infrastructure.

### Summary Quality Gate (Added)
- Node: `summarize_results`
- Current behavior:
  - attempts model summary first
  - applies cleanup and quality checks:
    - minimum length
    - bullet-count floor
    - simple truncation heuristic
  - if model output fails checks or raises exception:
    - emits deterministic structured summary from returned tool data
- Decision log fields:
  - `summary_fallback_used`
  - `summary_error`
  - `summary_quality_reason`
- Purpose:
  - keep demo/operator output readable and stable even when model output quality varies.

## Agentic Investigation Loop V1 (Added)
- Script:
  - `scripts/langgraph_agentic_soc.py`
- Goal:
  - run bounded iterative investigations with safe pivoting instead of one-shot tool execution.

### Agentic Loop Nodes
1. `ingest_question`
2. `guardrail_check`
3. `initial_plan`
4. `execute_step`
5. `evaluate_step`
6. `summarize`
7. `finalize`

### Loop Behavior
- The flow executes a step, evaluates results, then either:
  - proposes next safe pivot tool/action, or
  - stops when no additional safe pivot exists, or
  - stops when `max_steps` is reached.

### Current Safe Pivot Heuristics
- `splunk_get_indexes` -> `splunk_get_metadata` on top index sourcetypes.
- `splunk_get_metadata(type=sourcetypes)` -> `splunk_run_query` host distribution for top sourcetype.
- `splunk_run_query` failed-login style query -> `splunk_get_metadata(type=hosts)`.
- `splunk_get_metadata(type=hosts)` -> `splunk_run_query` sourcetype distribution for top host.

### Safety Controls
- Read-only guardrail on question wording.
- Query policy validation before any dynamic `splunk_run_query` pivot.
- Metadata argument validation before metadata pivots.
- Bounded loop depth via `--max-steps` (default 3).

### Agentic Ops Commands
- `make agentic-check`
- `make agentic-run`
- `make agentic-demo`
- `make agentic-session-demo`
- `make agentic-status`
- `make agentic-demo-ready`

### Agentic Artifacts
- Run artifacts:
  - `artifacts/runs/agentic/agentic_run_<UTCSTAMP>.json`
- Latest run index:
  - `docs/logs/agentic_runs/latest_index.csv`
- Case report outputs:
  - `docs/logs/agentic_case_report_latest.json`
  - `docs/logs/agentic_case_report_latest.md`

### Agentic Evidence/Confidence Tracking (Added)
- Each trajectory step now records:
  - `confidence` (bounded 0.05 to 0.99)
  - `evidence_signals` (compact extracted evidence for operator review)

## Multi-Model Review Workflow V1 (Added)
- Script:
  - `scripts/langgraph_multi_model_soc.py`
- Goal:
  - run a true multi-model review chain while keeping tool execution deterministic and policy-gated.

### Multi-Model Nodes
1. `ingest_question`
2. `guardrail`
3. `planner`
4. `security_review`
5. `peer_review`
6. `validate_final_plan`
7. `run_tool`
8. `summarize`
9. `finalize`

### Role Assignment
- Planner model:
  - drafts initial tool/query plan.
- Security reviewer model:
  - critiques query quality/safety and proposes revision.
- Peer reviewer model:
  - adjudicates planner vs reviewer candidate.
- Deterministic validator:
  - enforces tool allowlist, query policy, metadata args policy, and explicit question/tool alignment for stability.

### Multi-Model Ops Commands
- `make multi-model-run`
- `make multi-model-check`
- `make multi-model-demo`
- `make multi-model-status`
- `make multi-model-demo-ready`

### Multi-Model Artifacts
- Run artifacts:
  - `docs/logs/multi_model_runs/multi_model_run_<UTCSTAMP>.json`
- Latest run index:
  - `docs/logs/multi_model_runs/latest_index.csv`
- Purpose:
  - make pivot reasoning and step quality easier to audit and explain.

### Run Artifact Persistence (Added)
- Script option:
  - `python scripts/langgraph_minimal_flow.py --write-artifact "<question>"`
- Output directory:
  - `docs/logs/langgraph_runs/`
- File pattern:
  - `langgraph_run_<UTCSTAMP>.json`
- Artifact content:
  - run timestamp
  - full result payload (intent, guardrail state, query args, row counts, summary, decision log)

### Run Artifact Indexing (Added)
- Script:
  - `python scripts/summarize_langgraph_runs.py --limit 10`
- CSV option:
  - `python scripts/summarize_langgraph_runs.py --limit 10 --csv-out docs/logs/langgraph_runs/latest_index.csv`
- Purpose:
  - print compact summary of latest run files (timestamp, intent, guardrail/supported state, row counts, question)

### Policy Outcome Summary (Added)
- Script:
  - `python scripts/summarize_langgraph_policy.py --limit 20`
- Make target:
  - `make langgraph-policy-status`
- Outputs:
  - `docs/logs/langgraph_runs/latest_policy_summary.json`
  - `docs/logs/langgraph_runs/latest_policy_rows.csv`
- Purpose:
  - summarize recent policy-pass vs policy-fail behavior
  - show reason counts for policy and guardrail blocks

### Policy Summary History Snapshots (Added)
- Script:
  - `python scripts/snapshot_langgraph_policy_summary.py`
- Make target:
  - `make langgraph-policy-snapshot`
- Output directory:
  - `docs/logs/langgraph_policy_summary_history/`
- Purpose:
  - preserve timestamped weekly snapshots of policy summary telemetry for trend review

### Policy History Trend Summary (Added)
- Script:
  - `python scripts/summarize_langgraph_policy_history.py --limit 20 --csv-out docs/logs/langgraph_policy_summary_history/latest_trend.csv`
- Make target:
  - `make langgraph-policy-trend`
- Purpose:
  - summarize week-over-week policy summary counter changes
  - provide machine-readable trend export for review artifacts

### Policy Trend Freshness (Added)
- Script:
  - `python scripts/check_langgraph_policy_trend_freshness.py --max-age-minutes 10080`
- Make target:
  - `make langgraph-policy-trend-freshness`
- Threshold override:
  - `make langgraph-policy-trend-freshness POLICY_TREND_MAX_AGE_MINUTES=1440`
- Purpose:
  - ensure weekly review uses recent policy trend CSV output

### Policy Trend Anomaly Check (Added)
- Script:
  - `python scripts/check_langgraph_policy_trend_anomalies.py --max-abs-delta 5`
- Make target:
  - `make langgraph-policy-trend-anomaly`
- Threshold override:
  - `make langgraph-policy-trend-anomaly POLICY_MAX_ABS_DELTA=2`
- Purpose:
  - flag unexpected jumps in key policy delta counters from trend CSV
  - provide a simple fail-fast control for weekly policy telemetry review

### Policy Summary Freshness (Added)
- Script:
  - `python scripts/check_langgraph_policy_freshness.py --max-age-minutes 180`
- Make target:
  - `make langgraph-policy-freshness`
- Threshold override:
  - `make langgraph-policy-freshness POLICY_SUMMARY_MAX_AGE_MINUTES=60`
- Purpose:
  - fail fast when policy summary artifacts are stale
  - align LangGraph policy telemetry with existing report freshness checks

### LangGraph Ops Meta-Target (Added)
- Make target:
  - `make langgraph-ops`
- Threshold override:
  - `make langgraph-ops POLICY_MAX_ABS_DELTA=2`
  - `make langgraph-ops POLICY_MAX_ABS_DELTA=2 POLICY_SUMMARY_MAX_AGE_MINUTES=60 POLICY_TREND_MAX_AGE_MINUTES=1440`
- Runs:
  - `make langgraph-status`
  - `make langgraph-policy-status`
  - `make langgraph-policy-trend`
  - `make langgraph-policy-freshness`
  - `make langgraph-policy-trend-freshness`
  - `make langgraph-policy-trend-anomaly`
  - `make langgraph-docs-check`
  - `make langgraph-artifacts-check`
- Purpose:
  - provide one command to refresh and validate current LangGraph observability artifacts and docs alignment

### LangGraph Threshold Visibility (Added)
- Make target:
  - `make langgraph-thresholds`
- Purpose:
  - print active policy anomaly and freshness threshold values for operator verification

### LangGraph Strict Ops Preset (Added)
- Make target:
  - `make langgraph-ops-strict`
- Purpose:
  - run `langgraph-ops` with stricter recommended thresholds in one command

### LangGraph Quick Full Workflow (Added)
- Make target:
  - `make langgraph-all-quick`
- Purpose:
  - provide a fast telemetry/docs validation path without model-backed demo runs
  - useful for frequent operator checks between full demo cycles

## Constraints for Initial Graph
- Keep read-only data access initially
- Keep prompts and outputs transparent for educational clarity
- Prefer explicit state over implicit side effects
