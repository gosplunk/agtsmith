# Contributing

## Project Standard
A.G.E.N.T. Smith is opinionated about three things:
- explainable behavior
- read-only guardrails around Splunk access
- empirical improvement through benchmarks and evals

Changes should preserve those properties.

## Good Contributions
Useful contributions include:
- tighter SPL generation and validation
- better LangGraph orchestration and topology evaluation
- better docs and setup clarity
- improved benchmark coverage
- safer defaults
- cleaner UI/UX for operator workflows

## Before You Open A PR
Please:
1. keep changes focused
2. explain the motivation and tradeoff clearly
3. avoid unrelated formatting churn
4. do not commit local secrets, tokens, or runtime artifacts

## Development Notes
Important local patterns:
- live local config belongs in `config/ui.env` and should not be committed
- public examples belong in `config/ui.env.example`
- runtime outputs belong under `artifacts/` and should stay untracked except for intentional placeholders
- benchmark and eval changes should be accompanied by a short explanation of what improved and how it was measured

## Validation Expectations
If you change behavior, include the most relevant validation you ran, for example:
- `python3 -m py_compile ...`
- `make spl-hardening-benchmark`
- `make langgraph-topology-eval`
- targeted live prompt checks
- Docker smoke checks

If you could not run a check, say so explicitly.

## Pull Request Guidance
A good PR should state:
- what changed
- why it changed
- what was validated
- any known limitations or follow-up work

## License
By contributing to this repository, you agree that your contributions will be licensed under the Apache License 2.0.
