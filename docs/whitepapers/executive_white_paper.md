# Executive White Paper
## A.G.E.N.T. Smith
### Autonomous Guardrail-Enforced Networked Tasker

## 1. Executive Summary
A.G.E.N.T. Smith (Autonomous Guardrail-Enforced Networked Tasker) is a minimum viable agentic SOC analyst augment designed to help analysts ask plain-English questions, retrieve security-relevant data from Splunk through MCP tools, and receive structured, evidence-first answers. The platform is intentionally constrained to read-only analysis flows while it is hardened toward broader operational use.

The current system combines deterministic safety controls with a two-model workflow, and it can optionally add a small edge-hosted helper model for low-cost routing:
- a planner interprets analyst intent and search strategy,
- a coding-focused writer generates SPL,
- a reviewer critiques the generated SPL,
- an optional small edge helper can classify questions or suggest split-query handling before the main planner runs,
- peer reviewer roles adjudicate only when the reviewer does not cleanly approve the writer output,
- deterministic policy gates approve or block execution.

This architecture provides a practical balance between AI flexibility and operational safety in a SOC learning environment.

The project now also includes an offline evaluation loop that builds reference cases, derives test prompts, and compares LangGraph workflow layouts empirically before changing the default runtime behavior.

## 2. Business Problem
SOC teams face recurring friction:
- analysts spend time translating questions into SPL,
- context switching between query design and interpretation slows triage,
- inconsistent query quality leads to blind spots,
- unrestricted AI tooling introduces operational risk.

This lab addresses those challenges by enforcing a controlled AI-assisted workflow while retaining analyst oversight.

## 3. What This System Demonstrates
The current build demonstrates that a local analyst augment can:
- accept natural language security questions,
- route requests to approved Splunk MCP tools,
- enforce read-only and bounded-query policy controls,
- produce investigation summaries with explicit evidence context,
- block unsafe or non-read-only requests consistently,
- log decisions and artifacts for auditability,
- keep a local operator record of who launched which web investigation.
## 4. Architecture at a Glance
Environment:
- Controller: Linux host such as a Raspberry Pi or small server (orchestration, LangGraph flows, docs portal, runtime artifacts).
- Primary LLM Host: Windows + NVIDIA 3090 running Ollama.
- Optional edge helper: small model on an edge device for routing or split-query hints.
- Splunk: MCP endpoint on Splunk management interface.

Control model:
- Agent roles collaborate, critique, and verify before action.
- Deterministic Python and LangGraph nodes enforce policy and tool execution boundaries.

## 5. Governance and Safety Posture
Current safeguards include:
- read-only intent guardrails,
- Splunk tool allowlist enforcement,
- query policy validation,
- metadata argument policy validation,
- fail-closed behavior when final plan fails policy,
- artifact logging for replay and review.

This reduces risk of unsafe execution while preserving analyst productivity gains.

## 6. Why The Multi-Role Workflow Matters
A single-model pipeline can produce brittle query plans. The current workflow introduces critique and verification:
- planner proposes,
- SPL writer generates,
- security reviewer critiques and improves,
- peer reviewers adjudicate only when needed,
- deterministic gates validate,
- evidence review confirms whether the results support the claim.

Result: improved consistency, better explainability, and stronger confidence in lab outputs.

The addition of the offline eval loop also means workflow changes can now be measured, not just discussed. Reviewer stages, peer review, repair, and summary behavior can be compared against the same prompt set before a new topology is adopted.

## 7. Demonstrated Outcomes (Current Lab)
Observed validated behaviors:
- supported read-only questions execute with approved tools,
- non-read-only requests are blocked with a clear reason,
- query policy violations are blocked before execution,
- run artifacts are generated and indexed for review,
- agentic and multi-model modes are both available in the UI.

## 8. Limitations (Explicit)
This is intentionally not production-ready. Key limitations:
- lab credentials and lab token handling,
- local user management rather than enterprise IAM,
- no production secret management integration,
- no formal SLA or HA model,
- no production change-control integration,
- no autonomous remediation actions.

## 9. Recommended Next Phase
To move toward enterprise pilot readiness:
1. Integrate enterprise identity and secret management.
2. Add role-aware policy profiles by analyst tier and use case.
3. Add KPI dashboards for confidence, false positive reduction, and response-time impact.
4. Expand tested detection playbooks and IOC-driven workflows.
5. Formalize deployment, observability, and incident governance controls.

## 10. Executive Takeaway
This project already demonstrates a compelling pattern for SOC augmentation:
- AI-assisted investigation,
- deterministic safety boundaries,
- explicit evidence outputs,
- measurable and auditable behavior.

For a security leadership audience, the message is clear: A.G.E.N.T. Smith is a credible, controlled foundation for an AI-enabled SOC analyst experience, with a pragmatic path from lab proof-of-value to governed pilot.

## Lab-Only Notice
All credentials, tokens, internal addresses, and examples in this project are lab-only, temporary, and not production-safe.
