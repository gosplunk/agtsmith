# Changelog

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

## v1.1.0

- added guarded local learning with a dedicated Control Center page, pending/approved/stale state, and model-driven candidate generation
- improved Linux auth, Windows auth, Apache, and cross-platform failed-login investigation quality
- added async local-learning status, progress, and run-log visibility in the UI
- improved Investigation UI sample-result rendering so it matches working MCP query behavior more reliably
- added pilot benchmark pack generation and a full-pipeline hardening benchmark runner
- validated core live-environment and BOTSv3 benchmark slices to pilot-ready quality locally

## v1.0.1

- local guarded Linux-auth grounding improvements
- local working clone on 8788 for learning and personalization design

## v1.0.0

- first public release of A.G.E.N.T. Smith
- Docker-first deployment flow with first-run bootstrap
- controller-hosted LangGraph orchestration with bounded Splunk MCP retrieval
- configurable primary inference host and optional edge helper
- runtime validation, dependency checks, and live MCP probe in the UI
- architecture, setup, and operator documentation aligned to the current product state
