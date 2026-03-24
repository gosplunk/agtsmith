# Contributing

Thanks for taking a look.

A.G.E.N.T. Smith is trying to solve a pretty specific problem: help analysts write and review better SPL without giving up the safety and traceability you would want around a real investigation workflow. That means good contributions tend to improve one of four things:
- query quality
- guardrails and validation
- workflow clarity
- measurement

## What Good Changes Look Like
Useful changes include:
- tighter SPL generation or repair
- better reviewer behavior
- clearer LangGraph topology and routing
- stronger benchmarks or evals
- better docs and setup guidance
- UI improvements that make the system easier to operate

## Ground Rules
A few things matter here:
- keep Splunk access read-only
- prefer deterministic checks over trusting model output
- avoid broad, unrelated cleanup in the same change
- do not commit secrets, tokens, runtime artifacts, or local environment state

## Local Project Expectations
- live local config belongs in `config/ui.env`
- public examples belong in `config/ui.env.example`
- runtime outputs belong under `artifacts/` and should stay untracked except for intentional placeholders
- if you add references or docs to the runtime RAG path, they should actually be used

## Validation
If you change behavior, include the most relevant validation you ran.

Examples:
- `python3 -m py_compile ...`
- `make spl-hardening-benchmark`
- `make langgraph-topology-eval`
- targeted live prompt checks
- Docker smoke checks

If you could not run something important, say so.

## Pull Requests
A good PR should make four things easy to understand:
- what changed
- why it changed
- how it was validated
- what still needs follow-up, if anything

## Style
Keep the repo readable.
- write directly
- prefer clear names over clever ones
- keep prompts and policy logic explicit
- avoid AI-sounding filler in docs and comments

## License
By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
