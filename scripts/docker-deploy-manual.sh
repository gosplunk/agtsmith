#!/usr/bin/env bash
# Compatibility entry point for the verified Compose deployment.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! docker compose version >/dev/null 2>&1; then
  echo "[docker-deploy-manual] Docker Compose v2 is required." >&2
  echo "[docker-deploy-manual] Refusing an unverified direct-run fallback." >&2
  exit 1
fi

exec python3 scripts/docker_deploy.py up
