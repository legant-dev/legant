# Upgrading Legant

How to move a running Legant deployment to a newer version. Legant keeps all state
in Postgres and is otherwise stateless, so an upgrade is: apply migrations, then roll
the binary.

Until `1.0`, treat every minor version as potentially breaking and read the
[CHANGELOG](../CHANGELOG.md) before upgrading.

## Run migrations as a pre-deploy step

Migrations do not run on boot in production (`LEGANT_DATABASE_AUTO_MIGRATE=false` by
default). Apply them with the same image you're about to deploy, then roll the
Deployment:

```bash
legant migrate up        # apply pending migrations
legant migrate version   # confirm the version, and that it isn't dirty
```

With the Helm chart this is automatic — migrations run as a `pre-install`/`pre-upgrade`
hook (`migrate.enabled=true`), so they always complete before the new pods roll out.
With the raw manifests, apply `migrate-job.yaml` and wait for it to complete first:

```bash
kubectl apply -f deployments/k8s/migrate-job.yaml
kubectl wait --for=condition=complete job/legant-migrate --timeout=120s
```

## Zero-downtime: expand / contract

Schema changes are written to be safe across a rolling update — a migration is
compatible with both the old and the new binary running at once. For your own
extensions, follow the same expand/contract discipline:

1. **Expand** — add columns/tables/indexes; keep them nullable or defaulted. Deploy
   the new code that can use them. Old pods keep working.
2. **Contract** — only after every replica runs the new code, drop the old
   columns/paths in a later release.

Never combine "add a NOT NULL column" with "the old code that doesn't write it" in
one step.

## Keystore & secrets checklist

Signing keys live in Postgres, envelope-encrypted at rest. Before the first start,
set distinct secrets and keep them stable across the fleet:

- `LEGANT_SECRETS_SYSTEM` — Fosite HMAC (32+ bytes).
- `LEGANT_SECRETS_COOKIE` — cookie signing (32+ bytes, distinct).
- `LEGANT_SECRETS_KEY_ENCRYPTION` — master key that wraps the signing keys (32+
  bytes, distinct). If unset, it's derived from `LEGANT_SECRETS_SYSTEM`; set it
  explicitly in production so one leaked secret doesn't compromise both.

On upgrade these don't change. To rotate the key-encryption secret itself:

```bash
legant keys reencrypt --new-secret <new 32+ byte secret>
# then set LEGANT_SECRETS_KEY_ENCRYPTION to the new value before the next start
```

Signing-key rotation is independent of upgrades and needs no redeploy — a running
server picks up `legant keys rotate` on `SIGHUP` or within five minutes.

## Rolling back

Rolling the *binary* back is safe as long as the schema is still compatible
(expand/contract makes the previous version forward-compatible with the new schema).
Rolling *migrations* back is destructive:

```bash
legant migrate down --all   # drops ALL schema and data — refuses without --all
```

There is no partial down-migration. For production, restore from a database backup
rather than down-migrating.

## After upgrading

- `GET /readyz` checks the database is reachable, an active signing key is present,
  and migrations are applied and not dirty — use it as the rollout gate.
- Run `legant audit verify` if you keep the tamper-evident audit chain; an upgrade
  should never break it.
