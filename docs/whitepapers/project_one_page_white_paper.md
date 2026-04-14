# A.G.E.N.T. Smith
## Autonomous Guardrail-Enforced Networked Tasker

> Release note: see [`docs/project/v1_4_0_delta.md`](/docs/view?path=project/v1_4_0_delta.md) for the short operator-facing summary of what changed in `v1.4.0`.

A.G.E.N.T. Smith is a Splunk-centric analyst augmentation platform built to answer a practical question: how do we help analysts investigate faster without giving up control, evidence quality, or transparency?

The current product is intentionally bounded. An analyst asks a natural-language question, the Linux controller assembles environment-aware SPL context, and the request moves through a guarded multi-model workflow before anything can touch Splunk. A reasoning model plans the search, a coding-focused model writes the SPL, a reviewer critiques it, and deterministic validation decides whether the approved read-only plan is allowed to execute. Splunk MCP is then used only for approved read-only retrieval, and the result comes back as an evidence-backed answer rather than a black-box model response.

The runtime architecture is simple enough to explain and test:
- a Linux controller host runs the web UI, orchestration, validation, local user management, audit logging, and Splunk MCP calls
- a primary Ollama host runs the main planner, SPL writer, reviewer, evidence review, continuation, and summary roles
- an optional small edge-hosted model can be enabled for cheap routing or split-query hints, but it is not required and does not replace the main reasoning path
- Splunk remains the source of truth for evidence

What makes the project different from a generic chatbot is disciplined investigation flow. The current scope is Detect, Triage, and Investigate. Query generation is constrained by read-only policy, intent contracts, environment-aware grounding, model review, and fail-closed validation. Operators can see what happened, why it happened, which model roles were used, what SPL ran, and who launched the investigation through the web UI.

The platform is also operator-aware. First-run setup creates the initial local admin account, Configuration manages runtime endpoints and model roles, Users manages local operators, and the runtime records query audit entries so investigations remain attributable. This is intentionally simple local runtime control, not enterprise IAM.

The value today is practical and measurable:
- faster investigation workflows
- more consistent SPL generation
- explicit evidence and executed query visibility
- repeatable setup and configuration
- a controlled path for improving query quality against real data

The value tomorrow is a safer path to deeper capability:
- optional edge-assisted routing for split-query cases
- stronger benchmarking and repair loops
- broader environment-aware SPL quality
- analyst-governed deeper continuation
- controlled response automation later, not by default

This is an MVP investigation platform with explicit guardrails, not a production-ready autonomous SOC control plane. That boundary is deliberate. The point is not to replace analysts; it is to give them a faster, more transparent, and better-governed investigation workflow.
