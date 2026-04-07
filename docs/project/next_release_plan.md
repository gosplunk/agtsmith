# Next Release Plan

Target release: `v1.3.2`
Status: planned

This document is the canonical planning note for the next A.G.E.N.T. Smith release. It is intended to complement the changelog and architecture docs by separating:
- committed near-term work
- candidate enhancements
- known gaps that should be described honestly before release
- items explicitly deferred

The current planning theme is simple:
- strengthen investigation continuity
- keep Splunk evidence first
- improve analyst usability without hiding traceability

## Committed Enhancements

### 1. Richer Branch Visualization And Analyst Notes
Durable case memory and stateful pivots are now shipped. The next release should build on that with a stronger branch view and analyst note-taking.

Target additions:
- explicit branch view for sibling pivots and alternate investigation paths
- analyst notes/bookmarks on any timeline step
- easier evidence-diff view between parent and child steps

Expected outcome:
- complex investigations remain understandable even when multiple pivots branch from the same original evidence
- analysts can annotate why one branch mattered and another did not

Guardrails:
- case memory remains visible and bounded
- read-only validation remains deterministic
- annotations do not silently alter the underlying saved evidence

### 2. Runtime Model Wiring Must Match Saved Configuration By Default
The live runtime should continue to honor saved role assignments from Configuration without depending on ad hoc environment-variable injection.

Expected outcome:
- displayed pipeline roles match actual runtime behavior
- planner, writer, reviewer, evidence, continuation, and summary assignments stay consistent across restarts

### 3. Cleaner Investigation Continuity Cues In The UI
When context from a previous investigation is applied, the analyst should see that clearly.

Expected UI direction:
- compact `Follow-Up Context Applied` indicator
- visible source investigation reference
- compact entity chips or case context summary where appropriate

## Candidate Enhancements

### 1. Stronger Pivot Cards
Potential improvements:
- show pivot target field explicitly
- show expected value and likely scope more clearly
- include short Splunk query preview where safe and useful

### 2. Better No-Evidence Handling
Potential improvements:
- tighter no-hit assessment language
- clearer difference between:
  - no matching rows
  - partial coverage
  - likely visibility gap

### 3. Additional ATT&CK Logic Coverage
Potential improvements:
- broaden deterministic ATT&CK mappings
- improve likely follow-on technique suggestions
- keep ATT&CK clearly subordinate to Splunk evidence

## Known Gaps

### 1. Investigation Timeline Still Needs Better Branch Visualization
Current state:
- durable cases, node persistence, and stateful pivots are now implemented
- the current Investigation Timeline is strongest for linear progressions and shallow branch depth

User-facing implication:
- continuity is real today, but larger cases would benefit from a clearer branch graph and stronger node comparison tools

### 2. Some Investigation Summaries Still Depend On Backend Result Shape Consistency
Current state:
- the UI has been hardened against inconsistent result shapes
- the cleaner long-term fix is tighter backend result normalization so the front end does not need to infer as much

## Deferred

### 1. Secret Backend Integration
Deferred for now:
- AWS Secrets Manager or equivalent backend integration
- current direction remains local runtime config with better masking and cleaner operator UX

### 2. Full Production Hardening
Still outside the scope of the next release:
- enterprise IAM
- HA/SLA guarantees
- full secret-management platform support
- automated response / SOAR by default

## Release Readiness Questions
Before calling `v1.3.2` ready, answer these directly:

1. Can an analyst understand a multi-branch case without reading every saved node in sequence?
2. Can the analyst compare what changed between a parent finding and a child pivot quickly?
3. Do analyst notes and bookmarks stay clearly separate from deterministic evidence?
4. Does Splunk remain the clear evidence source of truth throughout the follow-up flow?
5. Are no-evidence and partial-coverage outcomes still presented conservatively?

## Relationship To Other Docs
- [README](/home/joe/agtsmith/README.md): project overview and public roadmap summary
- [Changelog](/home/joe/agtsmith/CHANGELOG.md): shipped changes only
- [Model Strategy](/home/joe/agtsmith/docs/model_strategy.md): current role assignment guidance
- [System Design](/home/joe/agtsmith/docs/architecture/system_design.md): current runtime architecture
