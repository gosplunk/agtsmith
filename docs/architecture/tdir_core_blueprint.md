# Core TDIR Blueprint (Splunk + Current Lab Stack)

## Objective
Define the current production-like **core TDIR** shape we can achieve with existing components, without SOAR automation yet.

## In Scope Now
- Splunk as primary detection data source via MCP tools.
- Read-only retrieval guardrails and policy validation.
- Multi-model investigation workflow:
  - Query Writer
  - Security Reviewer
  - Peer Reviewer
  - Evidence Reviewer
  - Continuation Reviewer
  - Final Summary
- Deterministic TDIR case enrichment:
  - severity
  - risk score
  - incident hypothesis
  - key entities
  - recommended pivots
- Agentic bounded drilldown workflow for deeper investigations with one automatic continuation pass and analyst approval for anything deeper.
- Web UI visibility of TDIR case details per run.

## Out of Scope (Explicitly Deferred)
- SOAR orchestration and automated response actions.
- Ticketing/case system automation.
- Automated containment and recovery playbooks.

## End-to-End Core TDIR Runtime Flow
1. Analyst asks question in Investigation UI.
2. Backend receives request and runs guardrail checks.
3. Multi-model or agentic planner decides safe read-only query path.
4. Deterministic policy layer validates tool and query/arg bounds.
5. Splunk MCP call executes and returns structured evidence.
6. Evidence Reviewer checks returned rows and gaps.
7. Continuation Reviewer decides whether another bounded pivot is warranted.
8. Outer loop control allows one automatic follow-up, then requires analyst approval for deeper continuation.
9. TDIR case enrichment computes severity/risk/hypothesis/entities/pivots.
10. Summary model produces analyst narrative.
11. UI renders:
   - Summary
   - Model Decisions
   - TDIR Case
   - Deeper Investigation Control
   - Full JSON output
12. Optional artifact persistence under `artifacts/`.

## SOAR-Later Hook
Current payloads now include a stable placeholder:
- `tdir_case.phase_status.soar_automation = not_enabled_yet`
- `tdir_case.response_note` explains manual response mode.

This keeps the output schema ready for later SOAR integration without reworking core investigation flow.
