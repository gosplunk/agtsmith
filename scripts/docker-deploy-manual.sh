#!/usr/bin/env bash
# Docker deploy without compose plugin (plain docker commands).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

NET="${AGTSMITH_DOCKER_NETWORK:-agtsmith-deploy}"
DB_NAME="${AGTSMITH_CASE_DB_NAME:-agtsmith}"
DB_USER="${AGTSMITH_CASE_DB_USER:-agtsmith}"
DB_PASS="${AGTSMITH_CASE_DB_PASSWORD:-agtsmith-local-change-me}"
PORT="${AGTSMITH_DEPLOY_PORT:-8787}"

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET"

if ! docker ps -a --format '{{.Names}}' | grep -qx agtsmith-case-db; then
  docker volume create agtsmith_deploy_case_db >/dev/null
  docker run -d --name agtsmith-case-db --network "$NET" \
    -e POSTGRES_DB="$DB_NAME" \
    -e POSTGRES_USER="$DB_USER" \
    -e POSTGRES_PASSWORD="$DB_PASS" \
    -v agtsmith_deploy_case_db:/var/lib/postgresql/data \
    postgres:16
fi

docker start agtsmith-case-db >/dev/null 2>&1 || true

echo "[docker-deploy-manual] building image"
docker build -f Dockerfile.deploy -t agtsmith-ui-deploy:local .

docker rm -f agtsmith-ui-deploy >/dev/null 2>&1 || true
docker volume create agtsmith_deploy_config >/dev/null
docker volume create agtsmith_deploy_artifacts >/dev/null

docker run -d --name agtsmith-ui-deploy --network "$NET" \
  -e AGTSMITH_CASE_DB_HOST=agtsmith-case-db \
  -e AGTSMITH_CASE_DB_PORT=5432 \
  -e AGTSMITH_CASE_DB_NAME="$DB_NAME" \
  -e AGTSMITH_CASE_DB_USER="$DB_USER" \
  -e AGTSMITH_CASE_DB_PASSWORD="$DB_PASS" \
  -p "${PORT}:8787" \
  -v agtsmith_deploy_config:/app/config \
  -v agtsmith_deploy_artifacts:/app/artifacts \
  agtsmith-ui-deploy:local

echo "[docker-deploy-manual] sidecar http://127.0.0.1:${PORT}"
