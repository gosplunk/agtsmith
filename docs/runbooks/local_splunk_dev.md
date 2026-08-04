# Local Splunk Development

Daily loop for this fork on a single machine with Splunk at `/opt/splunk`.

## Services

| Service | URL |
|---------|-----|
| Splunk Web | http://127.0.0.1:8000 |
| Splunk API | https://127.0.0.1:8089 |
| MCP | https://127.0.0.1:8089/services/mcp |
| agtsmith sidecar | http://127.0.0.1:8787 |

## Pre-flight

```bash
.cursor/skills/agtsmith-local-lab/scripts/preflight.sh
```

## MCP token (sandbox)

```bash
export SPLUNK_USER=dev SPLUNK_PASS='<sandbox-password>'
.cursor/skills/agtsmith-local-lab/scripts/mcp-token.sh
```

Add output to **gitignored** `config/ui.env` (copy from `config/ui.env.example`).
This file is intentionally for host-runtime and local-lab workflows; the Docker
deployment keeps its own named config volume and does not mount this file.

## Sidecar

Requires Docker Compose v2 (`docker compose`). Install if missing:

```bash
sudo apt-get install -y docker-compose-v2
```

```bash
export AGTSMITH_UID=$(id -u) AGTSMITH_GID=$(id -g)
make docker-deploy-build docker-deploy-up
```

Fresh Docker deployments do not create a reusable default login. Open
`http://127.0.0.1:8787/setup/first-run` and create the initial operator account.
After login, enter the Docker runtime endpoints and MCP credential through
`Control Center -> Configuration`.

Python venv for `make check`:

```bash
sudo apt-get install -y python3.12-venv
python3 -m venv .venv && .venv/bin/pip install -r requirements-docker.txt
make check
```

## Splunk app dev

```bash
sudo ln -sfn "$(pwd)/splunk_app/agent_smith" /opt/splunk/etc/apps/agent_smith
sudo -u splunk /opt/splunk/bin/splunk restart
```

## Teardown

- Delete sandbox `dev` user when finished
- Remove symlink from `/opt/splunk/etc/apps/agent_smith` if no longer needed
