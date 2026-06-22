# Deploying Legant on Kubernetes

> **Most users should use the Helm chart** at [`../charts/legant`](../charts/legant) —
> `helm install legant ./legant -f my-values.yaml`. It templates everything below,
> runs migrations as a pre-install/pre-upgrade **hook** (so the ordering can't go
> wrong), and bundles an optional Grafana dashboard. The raw manifests here remain a
> readable reference for what the chart deploys and for non-Helm/Kustomize workflows.

Production-oriented manifests for the Legant authorization server, the MCP
auth-gateway, schema migrations, and data-retention. They assume an external
PostgreSQL (managed service or your own operator) — Legant keeps all state there
and is otherwise stateless.

## Files

| File | What it is |
|---|---|
| `configmap.yaml` | Non-secret server config (issuer URL, bind address). |
| `secret.example.yaml` | **Template** for the DB URL and the three 32-byte secrets. Do not commit real values — source them from a secret manager. |
| `migrate-job.yaml` | One-shot `legant migrate up`, run **before** rollout. |
| `server.yaml` | `legant serve` Deployment + Service + HPA. |
| `gateway.yaml` | `legant gateway` Deployment + Service + its upstream-registry ConfigMap. |
| `retention-cronjob.yaml` | Nightly `legant maintenance prune`. |
| `audit-verify-cronjob.yaml` | Hourly `legant audit verify` (fails the Job on audit tampering). |
| `servicemonitor.yaml` | Prometheus Operator scrape configs for `/metrics`. |

## Apply order

```bash
# 1. Config + secrets (replace the example secret with real values first).
kubectl apply -f configmap.yaml
kubectl apply -f secret.example.yaml        # <-- edit before applying

# 2. Migrate the database to completion.
kubectl apply -f migrate-job.yaml
kubectl wait --for=condition=complete job/legant-migrate --timeout=120s

# 3. Roll out the server (and optionally the gateway).
kubectl apply -f server.yaml
kubectl apply -f gateway.yaml

# 4. Operations.
kubectl apply -f retention-cronjob.yaml
kubectl apply -f audit-verify-cronjob.yaml
kubectl apply -f servicemonitor.yaml        # needs the Prometheus Operator CRDs
```

## Notes

- **Images** are pinned to `ghcr.io/legant-dev/legant:latest` as a placeholder —
  replace with an immutable digest (`@sha256:...`) in production.
- **Pods run non-root** (uid 65532) with a read-only root filesystem, all
  capabilities dropped, and the RuntimeDefault seccomp profile. The image's
  `USER` matches, so no extra setup is needed.
- **Bootstrap a superadmin** once after the first deploy:
  `kubectl exec deploy/legant -- legant admin grant-superadmin you@example.com`.
- **Key rotation** is operational, not a redeploy:
  `kubectl exec deploy/legant -- legant keys rotate` (old key stays published
  during the overlap window).
- **`/metrics` is unauthenticated** — keep it cluster-internal; never route it
  through a public Ingress.
- **TLS** is expected to terminate at your Ingress/load balancer. Keep
  `LEGANT_ISSUER_URL` on `https://` so session cookies are marked `Secure`.
