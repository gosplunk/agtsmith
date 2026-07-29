# v1.4.2 Release Highlights

This document summarizes the operator-facing changes introduced in `v1.4.2` compared with `v1.4.1`.

## Why This Patch Matters

`v1.4.2` fixes first-time deployment bootstrap. Fresh installs should create the initial UI user through `/setup/first-run` instead of stopping on a login page with credentials the operator never set.

## Headline Changes

### 1. First-run setup is enforced on fresh installs

What changed:
- uninitialized controller config now always requires `/setup/first-run`
- example placeholder passwords from `config/ui.env.example` no longer bypass setup
- `/login` redirects to first-run until the operator creates the initial admin user

Why it matters:
- Docker deploy and host installs now follow the documented first-run path
- operators are not blocked by a login screen they cannot complete

### 2. Splunk MCP token minting works with Splunk MCP Server 1.x

What changed:
- local lab token minting uses the Splunk MCP app encrypted token endpoint
- token parsing preserves full base64 values when writing `config/ui.env`

Why it matters:
- Splunk 10 + MCP Server 1.x auth works for live MCP tool calls and environment profile refresh

### 3. Same-host Docker deploy reaches local Ollama and Splunk

What changed:
- deploy compose uses host networking for the controller on single-box labs
- PostgreSQL remains available on `127.0.0.1:5432`

Why it matters:
- local GPU Ollama on `127.0.0.1:11434` and Splunk on `127.0.0.1:8089` validate correctly from the container

## Upgrade Notes

If you already completed first-run on an existing volume, nothing changes until you reset auth config.

To experience first-run again on a lab host:

```bash
make docker-deploy-down
docker volume rm agtsmith_agtsmith_deploy_config
make docker-deploy-up
```

Then open `http://127.0.0.1:8787/login` and complete setup.
