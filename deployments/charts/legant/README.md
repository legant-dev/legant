# Legant Helm chart

Install the Legant authorization server, the MCP auth-gateway, and the operational
CronJobs with one command instead of hand-editing eight manifests. Database
migrations run as a **pre-install/pre-upgrade hook**, so they always complete before
the workloads roll out — the most common "applied out of order" failure is gone.

> Scope: Legant is the delegated-authority + offline-verify + revocation +
> provenance layer for AI agents. It complements, but does not replace, k8s RBAC,
> SPIFFE/SPIRE, cert-manager, OPA/Gatekeeper, and Kyverno.

## Prerequisites

- A PostgreSQL database reachable from the cluster.
- A container image (default `ghcr.io/legant-dev/legant`; pin a digest in production).
- Optional: the Prometheus Operator (for `serviceMonitor`) and a Grafana sidecar
  (for `dashboard`).

## Install

Reference a Secret you manage out-of-band (recommended):

```sh
# Secret must hold: LEGANT_DATABASE_URL, LEGANT_SECRETS_SYSTEM,
# LEGANT_SECRETS_COOKIE, LEGANT_SECRETS_KEY_ENCRYPTION
helm install legant ./legant \
  --set issuer=https://auth.example.com \
  --set secrets.existingSecret=legant-secrets
```

Or, for a trial, let the chart render the Secret from values (NOT for production):

```sh
helm install legant ./legant -f my-values.yaml
```

```yaml
# my-values.yaml
issuer: https://auth.example.com
secrets:
  create: true
  values:
    LEGANT_DATABASE_URL: "postgres://legant:...@host:5432/legant?sslmode=require"
    LEGANT_SECRETS_SYSTEM: "<32+ bytes>"
    LEGANT_SECRETS_COOKIE: "<32+ bytes, distinct>"
    LEGANT_SECRETS_KEY_ENCRYPTION: "<32+ bytes, distinct>"
```

## Key values

| Key | Default | Description |
|---|---|---|
| `image.repository` / `image.tag` | `ghcr.io/legant-dev/legant` / chart appVersion | Image (pin a digest in prod). |
| `issuer` | `https://auth.example.com` | Public issuer URL (https in prod). |
| `secrets.existingSecret` | `""` | Use a Secret you manage (ESO/Vault/SOPS). |
| `secrets.create` / `secrets.values` | `false` | Render a Secret from values (dev only). |
| `server.replicas` / `server.autoscaling.enabled` | `2` / `false` | Server scale (HPA on CPU when enabled). |
| `gateway.enabled` / `gateway.upstreams` | `true` / one example | MCP gateway + its upstream registry. |
| `migrate.enabled` | `true` | Migrations as a pre-install/pre-upgrade hook. |
| `cronjobs.retention.enabled` / `cronjobs.auditVerify.enabled` | `true` / `true` | Nightly prune + hourly audit-chain check. |
| `serviceMonitor.enabled` | `false` | Prometheus Operator scraping of `/metrics`. |
| `dashboard.enabled` | `false` | Bundle the Grafana dashboard as a sidecar-imported ConfigMap. |

See [values.yaml](values.yaml) for the full set.

## Notes

- `/metrics` is unauthenticated by design — keep it in-cluster, never via Ingress.
- The gateway can also take upstreams at runtime via the DB-backed registry, so you
  need not redeploy to add one.
- Publishing this chart (and signing the image + tagging releases) is a maintainer
  step; this directory is the ready-to-publish artifact.
