# Next Release Plan

Target release: `v1.3.0`
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

### 1. Persistent Follow-Up Context For Standard Investigation Pivots
Standard investigation pivots currently rerun as fresh bounded questions. The next release should allow the normal investigation workflow to carry forward bounded context from the previous run.

Target carry-forward context:
- original question
- previous executed SPL
- highest-priority entities such as host, source IP, username, process, or URI
- current assessment / working hypothesis
- Splunk coverage and visibility notes
- pivot source and rationale

Expected outcome:
- `Run This Follow-Up` becomes a true continuation step rather than only a convenient question rewrite
- follow-up planning remains grounded in what Splunk already showed
- the analyst can continue down an investigation path without losing case context

Guardrails:
- carried context must remain visible and bounded
- read-only validation remains deterministic
- follow-up context must not silently override explicit analyst wording

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

### 1. Standard Pivot Continuity Is Not Yet True Investigation Memory
Current state:
- standard pivots in the normal investigation page are mostly rerun as new bounded questions
- only the agentic continuation path persists richer session/case context today

User-facing implication:
- pivoting is useful, but it is not yet the same thing as a fully stateful follow-on investigation in the normal non-agentic workflow

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
Before calling `v1.3.0` ready, answer these directly:

1. Does a standard pivot retain bounded context from the previous investigation?
2. Does the UI make that carried context visible to the analyst?
3. Does the runtime model split shown in the UI match the models actually used?
4. Does Splunk remain the clear evidence source of truth throughout the follow-up flow?
5. Are no-evidence and partial-coverage outcomes still presented conservatively?

## Relationship To Other Docs
- [README](/home/joe/agtsmith/README.md): project overview and public roadmap summary
- [Changelog](/home/joe/agtsmith/CHANGELOG.md): shipped changes only
- [Model Strategy](/home/joe/agtsmith/docs/model_strategy.md): current role assignment guidance
- [System Design](/home/joe/agtsmith/docs/architecture/system_design.md): current runtime architecture
