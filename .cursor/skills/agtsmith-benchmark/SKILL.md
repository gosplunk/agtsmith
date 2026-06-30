---
name: agtsmith-benchmark
description: >-
  Run and interpret agtsmith Makefile benchmarks including make check,
  spl-hardening-benchmark, and langgraph-topology-eval. Use when validating SPL
  quality, regression, or release readiness.
---

# agtsmith Benchmark

## Core checks (no live Splunk required)

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-docker.txt
make check
```

## Live Splunk benchmarks

Requires `config/ui.env` with MCP token and reachable Splunk/Ollama:

```bash
make env-profile-refresh
make spl-hardening-benchmark
```

## LangGraph topology eval (offline tuning)

```bash
make langgraph-gold-build
make langgraph-eval-prompts
make langgraph-topology-eval
```

## Interpretation

| Result | Meaning |
|--------|---------|
| `make check` PASS | Templates, policy, unit tests OK |
| `spl-hardening-benchmark` | Live MCP query quality against environment |
| rows_returned=0 | Routing works; dataset may lack matching events |

See [reference/benchmark-interpretation.md](reference/benchmark-interpretation.md).
