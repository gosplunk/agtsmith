# RAG Source Triage for SPL Planner/Repair

## Purpose
Define which local RAG sources are safe and useful for:
- SPL query planning
- SPL syntax repair
- read-only SOC investigation workflows in this lab

## High-Value Sources (Use First)
- `docs/reference/rag_sources/spl_quick_reference.md`
  - Good for syntax patterns, command usage, and baseline query structure.
- `docs/reference/rag_sources/search_commands_rex.md`
  - Good for extraction repair (`rex`) and parser-oriented fixes.
- `docs/reference/rag_sources/search_commands_timechart.md`
  - Good for time-bucket and trend query patterns.
- `docs/reference/rag_sources/search_commands_datamodel.md`
  - Critical for MCP constraints and `datamodel ... | stats` fallback.
- `docs/reference/rag_sources/search_commands_tstats.md`
  - Critical MCP caveat: avoid `tstats ... by ...` in this environment; use datamodel workaround.
- `docs/reference/rag_sources/search_commands_eventcode_4688.md`
  - Strong Windows process/PowerShell examples for SOC detections.
- `docs/reference/rag_sources/security_correlation_searches.md`
  - Strong detection logic patterns and risk-scoring ideas (adapt to read-only mode).
- `docs/reference/rag_sources/escu_correlation_searches.md`
  - Useful for data-source mapping and CIM-aligned detection structure.
- `docs/reference/rag_sources/ioc_threat_hunting_example.md`
  - Useful workflow examples and investigation sequencing.

## Current Runtime Scope
Only the high-value sources listed above are included in the current runtime RAG path.
If a source is not listed there, it is not part of the active planner/repair context.

## Low Value / Exclude from SPL Planner Context
- Very large governance/compliance manuals not focused on SPL authoring:
  - `dod_sap_security_manual_full.md`
  - `nist_sp_800_53r5_security_privacy_controls.md`
- Product/service catalogs and SOW content not tied to query authoring.
- Files prefixed with `._` (AppleDouble metadata artifacts).

## Policy-Sensitive Patterns to Filter Out
The following appear in references but should be blocked or rewritten in this lab's read-only flow:
- `collect`
- `sendalert`
- `outputlookup`
- any write/modify or administrative mutation action

These are valid in production ES workflows but conflict with this lab’s current deterministic read-only policy.

## Immediate Implementation Guidance
For initial RAG query-planning and repair retrieval, prioritize this set:
1. `spl_quick_reference.md`
2. `search_commands_rex.md`
3. `search_commands_timechart.md`
4. `search_commands_datamodel.md`
5. `search_commands_tstats.md`
6. `search_commands_eventcode_4688.md`
7. `security_correlation_searches.md`
8. `escu_correlation_searches.md`
9. `ioc_threat_hunting_example.md`

## Environment-Specific Notes
- MCP in this environment rejects `tstats ... by ...` patterns.
- Preferred fallback:
  - `| datamodel <Model> <Dataset> flat | stats ... by ...`
- Keep row limits and time windows bounded to satisfy deterministic policy gate.

## Lab Safety Note
These references are used in a sandbox educational environment and must be filtered through:
- read-only tool allowlist
- query policy validation
- deterministic guardrails before execution
