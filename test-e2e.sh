#!/usr/bin/env sh
set -eu

PROJECT_NAME="${COMPOSE_PROJECT_NAME:-wedo-e2e}"
COMPOSE_FILE="docker-compose.dev.yml"

cleanup() {
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" --profile e2e down -v
}

trap cleanup EXIT INT TERM

WEDO_DEV_DATABASE_URL=sqlite:////tmp/wedo-e2e.db \
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" --profile e2e up \
  --build \
  --abort-on-container-exit \
  --exit-code-from e2e \
  e2e
