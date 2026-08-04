---
name: agtsmith-local-lab
description: >-
  Operate the local Splunk sandbox at 127.0.0.1:8000/8089 with agtsmith sidecar
  on 8787. Use for MCP token setup, config/ui.env, preflight checks, and sandbox
  dev user workflows.
---

# agtsmith Local Lab

## Pre-flight

```bash
.cursor/skills/agtsmith-local-lab/scripts/preflight.sh
```

## MCP bearer token

```bash
export SPLUNK_USER=dev SPLUNK_PASS='...'   # sandbox only — never commit
.cursor/skills/agtsmith-local-lab/scripts/mcp-token.sh
```

Copy printed token into gitignored `config/ui.env`:

```
SPLUNK_MCP_URL=https://127.0.0.1:8089/services/mcp
SPLUNK_BASE_URL=https://127.0.0.1:8089
SPLUNK_WEB_URL=http://127.0.0.1:8000
SPLUNK_LAB_BEARER_TOKEN=<token>
OLLAMA_HOST=http://127.0.0.1:11434
```

## Docker deploy

```bash
export AGTSMITH_UID=$(id -u) AGTSMITH_GID=$(id -g)
make docker-deploy-build docker-deploy-up
```

UI: `http://127.0.0.1:8787`
The Docker deployment uses its private named config volume and does not read
the host `config/ui.env`; enter runtime endpoints and credentials through the
first-run and Configuration pages. Host-runtime and local-lab commands may
continue to use `config/ui.env`.

See [docs/runbooks/local_splunk_dev.md](../../docs/runbooks/local_splunk_dev.md).
