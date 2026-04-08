# Changelog

## v1.0.0

- first public release of A.G.E.N.T. Smith
- Docker-first deployment flow with first-run bootstrap
- controller-hosted LangGraph orchestration with bounded Splunk MCP retrieval
- configurable primary inference host and optional edge helper
- runtime validation, dependency checks, and live MCP probe in the UI
- architecture, setup, and operator documentation aligned to the current product state

## v1.0.1

- local guarded Linux-auth grounding improvements
- local working clone on 8788 for learning and personalization design

## v1.1.0

- added guarded local learning with a dedicated Control Center page, pending/approved/stale state, and model-driven candidate generation
- improved Linux auth, Windows auth, Apache, and cross-platform failed-login investigation quality
- added async local-learning status, progress, and run-log visibility in the UI
- improved Investigation UI sample-result rendering so it matches working MCP query behavior more reliably
- added pilot benchmark pack generation and a full-pipeline hardening benchmark runner
- validated core live-environment and BOTSv3 benchmark slices to pilot-ready quality locally

## v1.2.0

- redesigned the Investigation UI into a desktop-first two-column workspace with a sticky left control rail and dominant right results area
- improved investigation usability with a dedicated Pivot Drawer, clearer follow-up actions, hidden-by-default advanced controls, and collapsed SPL sample results
- added richer ATT&CK investigation support including hover definitions, ATT&CK pivots, progression hints, persisted ATT&CK bundles, and `Run This Follow-Up` actions
- added model-backed ATT&CK validation using `Foundation-Sec-8B-Reasoning` as a second-pass ATT&CK reviewer layered on top of deterministic mappings
- improved investigation state handling so in-progress runs show pending status and zero-row runs produce a bounded no-evidence outcome instead of a misleading investigation narrative
- added ATT&CK logic benchmark generation and validation for BOTSv3-oriented investigation logic coverage
- added built-in HTTPS support for the web UI when a cert and key are provided
- masked the Splunk bearer token in Configuration and preserved it server-side without rendering it back in plain text
- sanitized repo defaults and shipped logic to remove hardcoded environment URLs and local-environment learning assumptions before publish

## v1.2.1

- aligned the live investigation runtime to the saved role model assignments instead of falling back to process defaults
- moved security review, evidence review, continuation review, and final summary to `Foundation-Sec-8B-Reasoning` while keeping `Qwen` for planning and `deepseek-coder-v2:lite` for SPL generation and repair
- updated architecture docs, runbooks, model strategy guidance, and investigation graphs to reflect the split-role model pipeline
- added a canonical next-release planning document for `v1.3.0`, including the planned persistent follow-up context enhancement for standard pivots
- fixed the runtime configuration save flow so host changes persist cleanly without leaving the UI stuck on `Saving...`
- verified remote Ollama host validation and end-to-end live investigation execution through the web UI

## v1.2.2

- improved SPL Optimization AI Engine messaging so operators can understand what it does, why it helps, and what approving a suggestion actually changes
- cleaned local learning history handling by auto-staling older pending suggestions and stripping legacy truncated sourcetype references from learned proposals
- bounded SPL Optimization AI Engine runs to a smaller, faster working set and shortened per-model timeouts so the page no longer appears stuck at the same bundle for long periods
- hardened local learning run-state handling so interrupted runs surface as interrupted instead of appearing to remain in progress indefinitely
- rebuilt and refreshed the public `v1.2.1` screenshot set from the live `v1.2.1` container so the repo visuals match the actual running UI

## v1.2.3

- clarified SPL Optimization AI Engine operator messaging so the page explicitly reports whether the run used the fast deterministic mode or the guarded model-assisted path
- added clearer no-gain messaging when a learning run finds no environment-aware SPL-writing improvement beyond the current baseline
- added active learned-state, cache hit/miss, candidate filtering, and run-duration visibility so operators can tell what changed between runs
- hardened the Learning page client behavior by fixing the onboarding modal click interception on `/learning` and removing the JavaScript parse error that made `Run Optimization Cycle` appear dead
- added the current `v1.2.3` Learning page screenshot to the public README screenshot set

## v1.2.4

- redesigned the investigation drawer into a sticky Splunk-first analyst workbench with non-redundant `Pivot`, `Evidence`, `SPL`, `Case Flow`, `ATT&CK`, `Decision Trace`, and `JSON` views
- improved investigation trust cues with phase-state visibility, clearer long-running guidance, stronger evidence handoff, and row-level Splunk drill-down links that preserve the original search scope and time range
- expanded the SPL Optimization AI Engine into a real repository-backed workflow with reusable SPL assets, explicit approval flow, and a dedicated SPL Asset Repository surface
- reorganized the admin/control surfaces around current state, next action, and working context, including grouped Operator Audit history and workflow-first artifact views
- refreshed the public README screenshots and release notes so the GitHub view matches the current `v1.2.4` interface

## v1.3.1

- made environment grounding materially more authoritative by learning field inventory per `index + sourcetype`, rewriting generic SPL toward the discovered local domains, and blocking unsupported data families instead of inventing fake local mappings
- fixed several demo-breaking intent paths so successful logins, Apache web activity, Linux session activity, Office 365 management activity, and CloudTrail routing use learned local domains and pass the same runtime validation path the UI enforces
- replaced the old saved-step investigation memory with a durable PostgreSQL-backed case store, persistent case/node ids, structured pivot context, and a richer Investigation Timeline workflow for reopening original findings and deeper pivots without rerunning Splunk
- added a dedicated Case Workspace and a rebuilt Investigation Drawer timeline that behaves like an analyst reasoning surface instead of a chronological log
- fixed SPL asset repository approval and rejection so actions resolve correctly against persisted records
- hardened analyst-facing output so even when the final-summary model falls back, the UI still shows intent-aware, evidence-aware current assessments instead of a generic execution stub

## v1.3.2

- fixed `/api/ask` so optional post-run enrichment and case persistence can no longer turn a successful investigation into an HTTP 500 failure after the result already exists
- added surfaced multi-model summary diagnostics for fallback behavior: `summary_fallback_used`, `summary_error`, and `summary_quality_reason`
- clarified new-install guidance in the Initial Setup Guide and live Configuration page so operators build Data Domains and run real investigations before starting SPL Optimization
- retained green `Open In Splunk` handoff in the Investigation drawer and MCP chat client, and restored clickable evidence-row drilldown so analysts can open focused searches directly from sample rows
- removed the unintended fallback default UI credential path so fresh installs no longer invent or honor `analyst/changeme123!` before first-run setup completes
- restored clean first-run bootstrap behavior for deployment installs by allowing the server to stay up with no configured users and redirect `/login` to `/setup/first-run`
- fixed live MCP query execution after runtime configuration changes by resolving `SPLUNK_MCP_URL` at call time instead of caching a stale startup value while the Configuration probe uses the current saved value
