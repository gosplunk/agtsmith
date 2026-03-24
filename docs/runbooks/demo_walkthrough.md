# Demo Walkthrough (Lab V1)

Use this runbook when presenting the current SOC assistant to another learner.

## Demo Goal
Show an end-to-end, read-only, agentic SOC flow with:
1. single-tool routing
2. two-tool chain routing
3. policy/guardrail behavior
4. lightweight session continuity
5. iterative multi-step pivoting
6. two-model SPL workflow (planner -> SPL writer -> reviewer -> conditional peer review)
7. analyst-governed deeper investigation after one automatic continuation pass
8. offline LangGraph optimization loop for empirical workflow tuning

## Preconditions
- Run from project root: `/home/joe/splunk-soc-agent`
- Virtual environment activated:
```bash
source .venv/bin/activate
```
- Optional browser UI mode:
```bash
make dev
```

## 1) Quick Readiness Check
```bash
make model-show
make langgraph-ops POLICY_MAX_ABS_DELTA=2 POLICY_SUMMARY_MAX_AGE_MINUTES=60 POLICY_TREND_MAX_AGE_MINUTES=1440
```
Expected:
- PASS on tool routing, docs consistency, and telemetry artifacts.

## 2) Single-Tool Routes Demo
```bash
make langgraph-tool-demo
```
This should show:
- `splunk_run_query` route
- `splunk_get_indexes` route
- `splunk_get_metadata` route
- `splunk_get_info` route

## 3) Two-Tool Chain Demo
```bash
make langgraph-chain-demo
```
Expected chain behavior:
1. First call retrieves index inventory.
2. Second call retrieves metadata for the top index from the first call.

## 4) Session Continuity Demo
```bash
make langgraph-session-demo
```
Expected:
- `session_context=docs/logs/sessions/session_demo_night_shift.json` printed.
- session file shows recent questions and tools from both demo runs.

Optional inspect:
```bash
sed -n '1,120p' docs/logs/sessions/session_demo_night_shift.json
```

## 5) Policy/Guardrail Demo
```bash
make langgraph-demo
make langgraph-policy-demo
```
Expected:
- non-read-only wording blocked by guardrail.
- high `row_limit` override blocked by policy.

## 6) Artifact Review for Demo Wrap-Up
```bash
make langgraph-status
make langgraph-policy-status
make agentic-status
```
Review files:
- `docs/logs/langgraph_runs/latest_index.csv`
- `docs/logs/langgraph_runs/latest_policy_summary.json`
- `docs/logs/langgraph_runs/latest_policy_rows.csv`
- `docs/logs/agentic_runs/latest_index.csv`

## 7) Agentic Loop Demo (Iterative Pivoting)
```bash
make agentic-demo-ready
make agentic-case-report
```
Expected:
- bounded multi-step trajectories (default 3 steps)
- safe pivot behavior recorded in each trajectory step
- one automatic deeper-investigation round can execute when continuation is justified
- any additional deeper continuation is held for analyst approval
- fallback summaries only when model output quality is insufficient
- latest case report generated in `docs/logs/agentic_case_report_latest.{json,md}`

## 8) Multi-Model Reviewer Demo (True Review Workflow)
```bash
make multi-model-demo-ready
```
Expected:
- planner model drafts the structured search plan.
- SPL writer model generates the bounded SPL.
- security reviewer model critiques and optionally revises.
- peer reviewer stages run only when the reviewer does not cleanly approve the writer output.
- deterministic policy gate validates final selection before execution.
- latest runs indexed in `docs/logs/multi_model_runs/latest_index.csv`.

## 9) Offline LangGraph Topology Optimization Demo
```bash
make langgraph-gold-build
make langgraph-eval-prompts
make langgraph-topology-eval
make langgraph-topology-optimize
```
Expected:
- a gold corpus is built from seed questions
- prompt variants are generated from those reference cases
- topology experiments are ranked by score, support rate, intent match, and latency
- the best current topology is printed from the latest eval artifact

## Demo Script (Short Spoken Sequence)
1. "We start with read-only tool routing and safety checks."
2. "Now I run multi-tool demos to show route selection by question intent."
3. "Now I run a two-step chain to drill from indexes to metadata automatically."
4. "Now I rerun with a shared session id to show minimal investigation continuity."
5. "Now I run the bounded agentic loop so it executes, performs one safe automatic follow-up if justified, and then hands deeper continuation back to the analyst."
6. "Now I run the two-model chain so one model plans, one model writes SPL, one model reviews, and peer review only runs when the query is still contested."
7. "Now I run the offline eval loop so workflow changes are measured against a shared prompt set instead of changed by opinion."
8. "Finally, we confirm guardrails, policy failures, and telemetry artifacts."

## Lab-Only Note
All credentials/tokens/addresses used here are lab-only, temporary, and not production-safe.
