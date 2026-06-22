#!/usr/bin/env bash
# Entitlement-preserving copilot — end-to-end enterprise demo.
#
# Stands up a REAL Postgres warehouse (Docker), seeds sales + finance schemas, mints
# each user's data-entitlement grant from entitlements.grants.yaml (legant apply),
# starts the warehouse API guarded by the shipped Legant RS middleware, and runs the
# shared copilot for Alice and Bob. Bob is denied finance offline; the audit names
# the human.
#
#   ./run.sh            # bring it all up, run, and tear it down
#   ./run.sh --keep     # leave Postgres running afterward
#
# Requires: docker (running), and a Go toolchain.
set -euo pipefail
cd "$(dirname "$0")"

PG="legant-warehouse"
PORT=5433
DSN="postgres://legant:legant@localhost:${PORT}/warehouse?sslmode=disable"
DIR="./.legant"
WH_ADDR="127.0.0.1:7080"
REPO_ROOT="$(cd ../../.. && pwd)"
KEEP="${KEEP_PG:-0}"
[[ "${1:-}" == "--keep" ]] && KEEP=1

BIN="$(mktemp -d)"
WH_PID=""

cleanup() {
  [[ -n "$WH_PID" ]] && kill "$WH_PID" 2>/dev/null || true
  if [[ "$KEEP" != "1" ]]; then
    docker rm -f "$PG" >/dev/null 2>&1 || true
  else
    echo "── leaving Postgres '${PG}' up (--keep). Remove with: docker rm -f ${PG}"
  fi
  rm -rf "$BIN" "$DIR" 2>/dev/null || true
}
trap cleanup EXIT

echo "── building legant + entitlement-copilot ──"
( cd "$REPO_ROOT" && GOTOOLCHAIN=auto go build -o "$BIN/legant" ./cmd/legant )
GOTOOLCHAIN=auto go build -o "$BIN/ecopilot" .

if ! docker ps --format '{{.Names}}' | grep -qx "$PG"; then
  echo "── starting a real Postgres warehouse (Docker) ──"
  docker rm -f "$PG" >/dev/null 2>&1 || true
  docker run -d --name "$PG" -e POSTGRES_USER=legant -e POSTGRES_PASSWORD=legant \
    -e POSTGRES_DB=warehouse -p "${PORT}:5432" postgres:16-alpine >/dev/null
fi
echo "── waiting for Postgres ──"
for i in $(seq 1 30); do
  docker exec "$PG" pg_isready -U legant -d warehouse >/dev/null 2>&1 && break
  sleep 1
  [[ $i == 30 ]] && { echo "postgres did not become ready"; exit 1; }
done

echo "── seeding sales + finance schemas ──"
docker exec -i "$PG" psql -q -U legant -d warehouse < seed.sql >/dev/null

echo "── minting per-user entitlement grants (legant apply) ──"
rm -rf "$DIR"
"$BIN/legant" lint  -f entitlements.grants.yaml
"$BIN/legant" apply -f entitlements.grants.yaml --dir "$DIR" >/dev/null

echo "── starting the warehouse API (real Postgres + Legant RS middleware) ──"
"$BIN/ecopilot" warehouse --dir "$DIR" --dsn "$DSN" --addr "$WH_ADDR" &
WH_PID=$!
for i in $(seq 1 30); do
  curl -fsS "http://${WH_ADDR}/healthz" >/dev/null 2>&1 && break
  sleep 1
  [[ $i == 30 ]] && { echo "warehouse did not become ready"; exit 1; }
done

echo "── running the shared analytics copilot ──"
echo
"$BIN/ecopilot" copilot --warehouse "http://${WH_ADDR}" --dir "$DIR" --dsn "$DSN"
