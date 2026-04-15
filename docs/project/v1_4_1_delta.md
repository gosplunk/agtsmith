# v1.4.1 Release Highlights

This document summarizes the operator-facing changes introduced in `v1.4.1` compared with `v1.4.0`.

## Why This Patch Matters

`v1.4.1` is a refinement release. The core investigation workflow introduced in `v1.4.0` remains the same, but the SPL asset review experience is cleaner, easier to scan, and more consistent with the rest of the analyst workspace.

## Headline Changes

### 1. SPL Asset Repository now behaves like a review workspace instead of a code grid

`/spl-assets` was reworked so the page reads like an analyst-facing repository review surface rather than a dense admin table.

What changed:
- a stable two-column layout now separates support context from the main work surface
- the left rail remains supportive instead of visually competing with the asset tables
- the lower review area is grouped more intentionally so the page no longer fades into empty space

Why it matters:
- operators can scan the repository faster
- the main review surface now feels consistent with the decision-first direction of the Investigation UI

### 2. Full SPL is still available, but no longer lives in every row by default

The page now favors scanning first and inspection second.

What changed:
- table rows now show a short SPL preview instead of a persistent code box
- `View full SPL` opens a dedicated detail region for the selected row
- full SPL, rationale, environment fit, proof, and review controls stay together in that revealed detail state

Why it matters:
- the asset tables remain readable at normal desktop widths
- long SPL no longer turns the repository into a wall of nested scroll areas

### 3. Row-level inspection controls are more deliberate

The `View full SPL` action was updated to match the command-surface treatment used elsewhere in the `v1.4.x` UI.

What changed:
- compact capsule-style row action
- clearer hover, focus, pressed, and expanded states
- stronger visual alignment with the dark analyst-workspace aesthetic

Why it matters:
- the control now looks intentional instead of generic
- inspection feels like a first-class workflow, not a default table button

### 4. Release hardening improved

This patch also tightened the release path itself.

What changed:
- MCP demo-mode regression coverage now stays isolated when the full UI test bundle is run together
- Splunk Web handoff regression coverage no longer depends on cross-test import order

Why it matters:
- patch releases are easier to validate before push
- the UI regression suite is a more trustworthy release gate

## Operator-Facing Summary

If you already adopted `v1.4.0`, the practical `v1.4.1` change is this:

- the SPL Asset Repository is easier to scan
- full SPL inspection is cleaner and less cluttered
- the repository page feels more like the rest of the premium analyst workspace
- the release itself is better hardened for repeatable validation

## What Did Not Change

- MCP remains `LLM-Assisted` by default
- the Investigation UI remains decision-first
- saved pivots and timeline staging continue to work the same way
- the product boundary is still Detect, Triage, and Investigate, not response automation

## Recommended Reading

If you want more than this patch summary:

- [v1.4.0 Release Highlights](/docs/view?path=project/v1_4_0_delta.md)
- [Technical Deep Dive](/docs/view?path=whitepapers/technical_deep_dive.md)
- [Documentation Guide](/docs/view?path=project_overview.md)
- `README.md` at the repository root for install and release context
