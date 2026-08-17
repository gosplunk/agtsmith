# Phase 1 — Live Validation Checklist

Complete these on the host (requires sudo for Docker group and Splunk app install).

## 1. Docker access

```bash
sudo usermod -aG docker "$USER"
newgrp docker   # or log out/in
docker ps
```

## 2. Host-runtime/local-lab config (optional for Docker)

```bash
export SPLUNK_USER=dev SPLUNK_PASS='<sandbox-password>'
make setup-local-ui-env
```

## 3. Start sidecar

```bash
make docker-deploy-up
```

Docker Compose v2 is required. The compatibility `docker-deploy-manual` target
uses the same verified Compose path and refuses an unverified direct-run
fallback.

Open http://127.0.0.1:8787 — complete first-run setup if prompted, then paste values from `config/ui.env` in Configuration.
The deployment container uses a private named config volume; `config/ui.env` is
not bind-mounted into Docker.

## 4. Ollama

```bash
# install/start Ollama, then:
ollama pull deepseek-coder-v2:lite
# pull other models per config/ui.env.example
curl http://127.0.0.1:11434/api/tags
```

## 5. Splunk app

```bash
make splunk-app-symlink-dev
# or: make splunk-app-install-local
sudo -u splunk /opt/splunk/bin/splunk restart
```

Open http://127.0.0.1:8000 → Apps → A.G.E.N.T. Smith → Investigate

## 6. Validate

```bash
make check
make spl-hardening-benchmark   # live MCP
make screenshots SCREENSHOT_VERSION=v1.5.1
```

## 7. KV Store mode (optional)

In `config/ui.env`:

```
AGTSMITH_CASE_BACKEND=kvstore
AGTSMITH_KVSTORE_SYNC=1
```

Restart sidecar after changing env.
