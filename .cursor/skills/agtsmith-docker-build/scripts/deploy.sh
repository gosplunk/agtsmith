#!/usr/bin/env bash
# Build, verify, and restart the revision-pinned agtsmith-ui-deploy container.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
cd "$ROOT"

USE_NVIDIA=0
for arg in "$@"; do
  case "$arg" in
    --nvidia) USE_NVIDIA=1 ;;
    -h|--help)
      echo "Usage: deploy.sh [--nvidia]"
      echo "  Builds contract tests, deploys agtsmith-ui-deploy on :8787, waits for HTTP."
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

export AGTSMITH_UID="${AGTSMITH_UID:-$(id -u)}"
export AGTSMITH_GID="${AGTSMITH_GID:-$(id -g)}"

if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  echo "[agtsmith-docker-build] bootstrapping .venv for contract tests"
  python3 -m venv "$ROOT/.venv"
  "$ROOT/.venv/bin/pip" install -q -r "$ROOT/requirements-docker.txt"
fi

echo "[agtsmith-docker-build] running deploy contract tests"
make docker-deploy-contract-tests

if [[ "$USE_NVIDIA" -eq 1 ]]; then
  echo "[agtsmith-docker-build] deploying with NVIDIA overlay"
  make docker-deploy-up-nvidia
else
  echo "[agtsmith-docker-build] deploying standard stack"
  make docker-deploy-up
fi

echo "[agtsmith-docker-build] waiting for http://127.0.0.1:8787/"
ready=0
for _ in $(seq 1 45); do
  code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/ 2>/dev/null || echo 000)"
  if [[ "$code" != "000" ]]; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "$ready" -ne 1 ]]; then
  echo "[agtsmith-docker-build] ERROR: UI did not become reachable on :8787" >&2
  echo "[agtsmith-docker-build] try: make docker-deploy-logs" >&2
  exit 1
fi

if docker inspect agtsmith-ui-deploy >/dev/null 2>&1; then
  docker inspect -f \
    'revision={{ index .Config.Labels "org.opencontainers.image.revision" }} build_id={{ index .Config.Labels "io.agtsmith.build-id" }} state={{ .State.Status }}' \
    agtsmith-ui-deploy
fi

echo "[agtsmith-docker-build] UI ready at http://127.0.0.1:8787 (http_status=${code})"
