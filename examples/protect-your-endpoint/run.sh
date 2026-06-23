#!/usr/bin/env bash
# Bound an agent and enforce it at your own HTTP endpoint, fully offline.
# No database, no Docker: just `go`. Builds the CLI and the resource server,
# defines a grant, mints a token, and shows allow / deny-by-constraint /
# deny-by-revocation against a real chi server.
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

ADDR=":8099"
URL="http://localhost:8099/query"
WORK="$(mktemp -d)"
RS_PID=""
cleanup() { [ -n "$RS_PID" ] && kill "$RS_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

say() { printf '\n\033[1m%s\033[0m\n' "$1"; }

say "1. Build the CLI and the resource server"
go build -o "$WORK/legant" ./cmd/legant
go build -o "$WORK/rs" ./examples/protect-your-endpoint
cp examples/protect-your-endpoint/grants.yaml "$WORK/legant.grants.yaml"

say "2. Apply the grant (mints a signed token into .legant/, no database)"
( cd "$WORK" && ./legant apply -f legant.grants.yaml )

say "3. Who can query the finance schema? (offline authorize from the grants file)"
( cd "$WORK" && ./legant who-can -f legant.grants.yaml --scope warehouse:query --resource finance )

start_rs() { LEGANT_DIR="$WORK/.legant" LEGANT_ADDR="$ADDR" "$WORK/rs" >"$WORK/rs.log" 2>&1 & RS_PID=$!; sleep 1.2; }
TOKEN="$(cat "$WORK/.legant/alice-warehouse.jwt")"

say "4. Start the resource server and call it with the agent's token"
start_rs
printf '  allow  (schema=finance): '; curl -s -H "Authorization: Bearer $TOKEN" "$URL?schema=finance"
printf '  deny   (schema=hr):      '; curl -s -o /dev/null -w '%{http_code} (not in the grant: [sales, finance])\n' -H "Authorization: Bearer $TOKEN" "$URL?schema=hr"

say "5. Revoke the token, restart the server, call again"
( cd "$WORK" && ./legant revoke --token-file .legant/alice-warehouse.jwt )
kill "$RS_PID" 2>/dev/null || true; start_rs
printf '  deny   (schema=finance): '; curl -s -o /dev/null -w '%{http_code} (token revoked, killed offline via the signed feed)\n' -H "Authorization: Bearer $TOKEN" "$URL?schema=finance"

say "Done. The agent acted on alice's behalf, bounded to [sales, finance], and the"
echo  "kill-switch took effect offline. Nothing here touched a database or the network."
