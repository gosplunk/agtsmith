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

## Sidecar

```bash
export AGTSMITH_UID=$(id -u) AGTSMITH_GID=$(id -g)
make docker-deploy-build docker-deploy-up
```

## Splunk app dev

```bash
sudo ln -sfn "$(pwd)/splunk_app/agent_smith" /opt/splunk/etc/apps/agent_smith
sudo -u splunk /opt/splunk/bin/splunk restart
```

## Teardown

- Delete sandbox `dev` user when finished
- Remove symlink from `/opt/splunk/etc/apps/agent_smith` if no longer needed
