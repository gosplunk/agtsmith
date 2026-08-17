---
name: agtsmith-docker-build
description: >-
  Build, deploy, verify, and restart the A.G.E.N.T. Smith Docker sidecar
  (agtsmith-ui-deploy on :8787). Use when implementing or validating any
  agtsmith engine or UI change, after editing scripts/, Dockerfile.deploy, or
  docker-compose files, before live MCP investigations, screenshots, or telling
  the user to test the UI. Never use make ui-dev or host web_ui_server for
  runtime validation on this dev box.
---

# agtsmith Docker Build

## Policy (non-negotiable on this dev box)

- **Runtime sidecar = Docker only.** Use the deploy script below, not `make ui-dev`.
- **No hotpatch.** `make docker-deploy-hotpatch` is disabled; rebuild preserves revision identity.
- **Config lives in the container volume**, not host `config/ui.env`. The Docker UI reads
  `agtsmith_deploy_config`; enter Splunk/MCP credentials through first-run / Configure.
- **Host `.venv` is for CI-style checks only** (`make check`, unit tests, offline benchmarks).
  It is not the running product.

## When to rebuild + restart

Run deploy after changes to any of:

- `scripts/**`, `core/**`, `Dockerfile.deploy`, `docker-compose.deploy*.yml`
- `requirements-docker.txt`, static UI assets bundled in the image

Also restart when:

- `:8787` is down, stale, or still serving old behavior after a code change
- Container revision/build_id labels do not match current source identity

## Standard workflow

```bash
export AGTSMITH_UID=$(id -u) AGTSMITH_GID=$(id -g)
.cursor/skills/agtsmith-docker-build/scripts/deploy.sh
```

Optional NVIDIA host metrics overlay:

```bash
.cursor/skills/agtsmith-docker-build/scripts/deploy.sh --nvidia
```

Tail logs after a failed deploy:

```bash
make docker-deploy-logs
```

Stop the deployment stack:

```bash
make docker-deploy-down
```

## After deploy — cross-skill handoff

| Next step | Skill |
|-----------|-------|
| Configure Splunk MCP in the UI | `agtsmith-local-lab` |
| Validate SPL / regressions | `agtsmith-benchmark` |
| Capture README screenshots | `agtsmith-screenshots` |
| Package Splunk app (separate path) | `agtsmith-splunk-app` |

## Splunk app note

`splunk_app/**` is installed with `make splunk-app-install-local`, not Docker.
After engine changes that affect the app wrapper, deploy Docker **and** reinstall
the Splunk app when testing in Splunk Web.

## Forbidden shortcuts

| Do not use | Why |
|------------|-----|
| `make ui-dev` | Host runtime; bypasses revision verification |
| `docker cp` / bind-mount hotpatch | Breaks build-id contract |
| `make docker-up` (legacy compose) | Use `docker-deploy-up` instead |
| Tell user to hard-refresh without deploy | Code may not be in the running image |

## Verification checklist

- [ ] `docker ps` shows `agtsmith-ui-deploy` running
- [ ] `deploy.sh` printed matching `revision` and `build_id`
- [ ] `curl` to `http://127.0.0.1:8787/` returns HTTP (not connection refused)
- [ ] One smoke investigation in the UI behaves as expected

## Reference

- Deploy contract, volumes, reset: [reference/deploy-contract.md](reference/deploy-contract.md)
- Local Splunk + MCP setup: [agtsmith-local-lab](../agtsmith-local-lab/SKILL.md)
