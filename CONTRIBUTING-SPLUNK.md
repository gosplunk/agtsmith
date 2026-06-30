# Contributing (Splunk App Fork)

Extends [CONTRIBUTING.md](CONTRIBUTING.md) with fork-specific guidance.

## What goes where

- **Upstream PR** — SPL quality, LangGraph, benchmarks, docs fixes in `scripts/` or future `core/`
- **Fork only** — `splunk_app/`, `.cursor/`, Splunk runbooks, `CONTRIBUTING-SPLUNK.md`

## Secrets

Never commit `config/ui.env`, bearer tokens, or sandbox passwords.

## Validation before PR (engine changes)

```bash
make check
make spl-hardening-benchmark   # when MCP configured
```

## Validation before app package

```bash
make splunk-app-package
# inspect tarball — no passwords.conf with real secrets in default/
make splunk-app-install-local
```
