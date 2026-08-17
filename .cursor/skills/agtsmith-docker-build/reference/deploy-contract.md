# Docker deploy contract

## Canonical commands

| Goal | Command |
|------|---------|
| Build + start + verify | `make docker-deploy-up` |
| Build image only | `make docker-deploy-build` |
| NVIDIA metrics overlay | `make docker-deploy-up-nvidia` |
| Contract guard tests | `make docker-deploy-contract-tests` |
| Logs | `make docker-deploy-logs` |
| Stop | `make docker-deploy-down` |

Implementation: `scripts/docker_deploy.py` (revision-pinned image tags, running-container verification).

## Identity labels

Every deployment image and running container carry:

| Label | Meaning |
|-------|---------|
| `org.opencontainers.image.revision` | `git rev-parse HEAD` at build time |
| `io.agtsmith.build-id` | HEAD, or `HEAD-dirty-<hash>` when the tree has local changes |

The deploy script fails if the running container's image ID or labels do not match the
source identity computed at deploy time.

## Services and ports

| Container | Role | Reachable at |
|-----------|------|--------------|
| `agtsmith-ui-deploy` | Web UI + LangGraph engine | `http://127.0.0.1:8787` |
| `agtsmith-case-db` | Postgres case store | `127.0.0.1:5432` (default) |

Compose file: `docker-compose.deploy.yml` (+ optional `docker-compose.deploy.nvidia.yml`).

Network mode for the UI service is `host` so the sidecar can reach Splunk/Ollama on localhost.

## Named volumes (persist across restarts)

| Volume | Mount | Contents |
|--------|-------|----------|
| `agtsmith_deploy_config` | `/app/config` | UI auth, runtime endpoints, secrets |
| `agtsmith_deploy_artifacts` | `/app/artifacts` | Run artifacts, benchmarks output |
| `agtsmith_deploy_case_db` | Postgres data | Investigation cases |

`docker compose down` preserves these volumes. Rebuild/restart (`make docker-deploy-up`) does **not**
wipe configuration.

## Fresh install vs reset

**Fresh Docker install (no operator account yet):**

1. `make docker-deploy-up`
2. Open `http://127.0.0.1:8787/setup/first-run`
3. Create operator account, then enter Splunk/MCP settings in Configure

**Full auth/config reset:**

```bash
make docker-deploy-down
docker volume rm agtsmith_deploy_config   # only when intentional reset
make docker-deploy-up
```

Never commit secrets from the config volume; use `config/ui.env.example` for placeholders only.

## Host env vars

```bash
export AGTSMITH_UID=$(id -u)
export AGTSMITH_GID=$(id -g)
```

Optional case DB overrides: `AGTSMITH_CASE_DB_*` (see `docker-compose.deploy.yml`).

## What host `.venv` is for

Host `.venv` + `make check` validates templates, policy, and unit tests **before or after**
image build. It does not replace the Docker sidecar for UI or live MCP validation.
