#!/usr/bin/env sh
set -eu

if [ "$#" -eq 0 ]; then
  set -- -q
fi

docker compose -f docker-compose.dev.yml run --rm backend python -m pytest "$@"
