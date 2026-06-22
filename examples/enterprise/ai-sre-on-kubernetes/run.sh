#!/usr/bin/env bash
# AI-SRE on real Kubernetes — end-to-end enterprise demo.
#
# Stands up a REAL kind cluster + sample workloads, mints the on-call's incident
# grant from incident.grants.yaml (legant apply), starts a Legant-guarded proxy in
# front of the REAL mcp-server-kubernetes, and runs the AI-SRE agent through it.
# Every denial is enforced offline from the signed token; the cluster mutations are
# real (kubectl get shows them).
#
#   ./run.sh            # create cluster, run the scenario, delete the cluster
#   ./run.sh --keep     # leave the cluster up afterward (re-run faster)
#   KEEP_CLUSTER=1 ./run.sh
#
# Requires: docker (running), kind, kubectl, npx (node), and a Go toolchain.
set -euo pipefail
cd "$(dirname "$0")"

CLUSTER="legant-sre"
CTX="kind-${CLUSTER}"
NS="prod"
DIR="./.legant"
PROXY_ADDR="127.0.0.1:7070"
REPO_ROOT="$(cd ../../.. && pwd)"
KEEP="${KEEP_CLUSTER:-0}"
[[ "${1:-}" == "--keep" ]] && KEEP=1

BIN="$(mktemp -d)"
PROXY_PID=""

cleanup() {
  [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null || true
  if [[ "$KEEP" != "1" ]]; then
    echo "── tearing down kind cluster '${CLUSTER}' ──"
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  else
    echo "── leaving cluster '${CLUSTER}' up (--keep). Delete with: kind delete cluster --name ${CLUSTER}"
  fi
  rm -rf "$BIN" "$DIR" 2>/dev/null || true
}
trap cleanup EXIT

echo "── building legant + ai-sre ──"
( cd "$REPO_ROOT" && GOTOOLCHAIN=auto go build -o "$BIN/legant" ./cmd/legant )
GOTOOLCHAIN=auto go build -o "$BIN/ai-sre" .

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "── creating real kind cluster '${CLUSTER}' ──"
  kind create cluster --name "$CLUSTER" --wait 90s
fi
kubectl config use-context "$CTX" >/dev/null

echo "── deploying sample workloads (prod/payments, prod/billing) ──"
kubectl get ns "$NS" >/dev/null 2>&1 || kubectl create namespace "$NS" >/dev/null
kubectl -n "$NS" get deploy payments >/dev/null 2>&1 || \
  kubectl -n "$NS" create deployment payments --image=registry.k8s.io/pause:3.9 --replicas=1 >/dev/null
kubectl -n "$NS" get deploy billing >/dev/null 2>&1 || \
  kubectl -n "$NS" create deployment billing --image=registry.k8s.io/pause:3.9 --replicas=1 >/dev/null
kubectl -n "$NS" scale deploy/payments --replicas=1 >/dev/null

echo "── minting the incident grant (legant apply) ──"
rm -rf "$DIR"
"$BIN/legant" lint  -f incident.grants.yaml
"$BIN/legant" apply -f incident.grants.yaml --dir "$DIR" >/dev/null

echo "── starting the Legant-guarded k8s MCP proxy (wraps a real mcp-server-kubernetes) ──"
"$BIN/ai-sre" proxy --dir "$DIR" --addr "$PROXY_ADDR" &
PROXY_PID=$!
# Wait for the proxy (which only answers once the MCP server handshake completes).
for i in $(seq 1 60); do
  curl -fsS "http://${PROXY_ADDR}/healthz" >/dev/null 2>&1 && break
  sleep 1
  [[ $i == 60 ]] && { echo "proxy did not become ready"; exit 1; }
done

echo "── running the AI-SRE agent through the guard ──"
echo
"$BIN/ai-sre" agent \
  --proxy "http://${PROXY_ADDR}" \
  --dir "$DIR" \
  --token-file "$DIR/incident.jwt" \
  --legant "$BIN/legant" \
  --kube-context "$CTX" \
  --namespace "$NS" \
  --deploy payments
