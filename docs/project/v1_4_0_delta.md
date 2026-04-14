# v1.4.0 Release Highlights

This document summarizes the operator-facing changes introduced in `v1.4.0` compared with `v1.3.5`.

## Why This Matters

`v1.4.0` is not a cosmetic pass. The main changes improve decision speed, investigation trust, pivot continuity, and operator control.

## Headline Changes

### 1. MCP is now analyst-first instead of template-first

`/mcp` now defaults to `LLM-Assisted` query generation instead of behaving like a deterministic canned-template page.

What changed:
- `LLM-Assisted` is now the primary MCP mode
- `Deterministic` remains available as an explicit fallback
- `Live Mode` and `Demo Mode` are presented as strong mutually-exclusive controls
- mode selection is visually obvious instead of checkbox-like

Why it matters:
- analysts expect MCP to interpret the question and write bounded SPL, not just map to rigid canned behavior
- deterministic mode still exists for fallback, demos, and health-check style use cases

### 2. Investigation UI is now decision-first

The top of `/investigation` was redesigned around the first-year SOC analyst decision loop:

1. What happened?
2. Is this suspicious enough to continue?
3. What is the single best next action?

What changed:
- one dominant center-column answer flow
- `Answer Card`
- `Confidence + Why`
- one `Primary Next Action`
- concise `Evidence`
- inline `Open SPL Used` trust validation

What was removed or demoted:
- side surfaces no longer compete with the main decision flow
- the left rail now mirrors staged work instead of acting like a second primary action surface
- rerun behavior is still available, but it is explicitly secondary after a result exists

Why it matters:
- the operator no longer has to hunt across multiple panels to decide whether to continue
- the page now behaves like a triage surface instead of a dense dashboard

### 3. Pivoting is more usable and more honest

The runtime now does a better job of preserving and exposing structured follow-up context.

What changed:
- saved IOC values in evidence can stage the best preserved pivot directly
- Investigation Timeline entities can also stage the best saved pivot
- the workspace now explains what changes from the prior step
- the primary next action includes both:
  - why this is the best move
  - when not to choose this

Why it matters:
- analysts should not have to copy values manually out of evidence tables
- the system now makes a clearer distinction between a real stronger follow-up and a low-value repetitive pivot

### 4. The Investigation Drawer is secondary support, not the primary decision surface

The bottom drawer remains important, but it now serves timeline, audit, and case-memory support rather than acting as the place where the analyst must figure out what to do next.

What changed:
- the top workspace owns the decision
- the drawer retains lane-based navigation for:
  - next step
  - evidence
  - SPL
  - timeline
  - context
- the drawer remains useful for saved-case reopening and auditability without carrying the whole triage burden

Why it matters:
- novice analysts need one clear decision surface first
- audit and timeline detail remain accessible without becoming the main story

### 5. Environment-aware grounding is tighter

Query grounding and routing changed in ways that matter to investigation quality, not just cosmetics.

What changed:
- stronger canonical intent handling
- better ranking of authoritative indexes and sourcetypes per intent
- better style-aware domain selection across Linux, Windows, and web telemetry
- failed-login auth searches are less likely to inherit irrelevant web-like sourcetypes
- portable investigation playbooks now influence which pivots are recommended for each intent family

Why it matters:
- better local grounding reduces bad query rewrites
- pivot suggestions are more consistent with the actual investigation type

### 6. Learning is easier to review and operate

The `/learning` workflow now reads more like a bounded SPL optimization workbench and less like an opaque background task.

What changed:
- clearer run-state visibility and progress reporting
- a `What Changed This Run` summary for the latest optimization cycle
- stronger pending-review and approved-asset visibility
- clearer operator guidance before optimization starts
- repository-backed SPL asset workflow remains visible from the UI

Why it matters:
- operators can tell whether a run improved anything
- approval and reuse decisions are easier to make without digging through low-level logs

## Analyst-Facing Summary

If you used `v1.3.5`, the practical `v1.4.0` change is this:

- MCP now feels like a guarded analyst copilot instead of a deterministic template shell
- Investigation UI now tells you the answer, confidence, and one best next step much faster
- saved pivots are easier to stage directly from evidence and timeline context
- trust validation is closer to the action because SPL is accessible inline
- the page is more explicit about when to continue and when to stop
- Learning now shows clearer optimization outcomes and review state

## What Did Not Change

The product boundary is still the same:

- Detect, Triage, and Investigate are implemented
- Respond and Recover are still manual
- Splunk remains the evidence source of truth
- read-only bounded execution is still enforced
- deterministic validation is still required before approved paths can execute

## Recommended Reading

If you want more than this release summary:

- [Technical Deep Dive](/docs/view?path=whitepapers/technical_deep_dive.md)
- [TDIR Blueprint](/docs/view?path=architecture/tdir_core_blueprint.md)
- [Documentation Guide](/docs/view?path=project_overview.md)
- `README.md` at the repository root for install and release context
