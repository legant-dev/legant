# OAuth breach replay (Salesloft–Drift / UNC6395)

Re-enacts the **Aug 2025 Salesloft–Drift OAuth-token theft** (UNC6395, ~700 orgs)
against **real HTTP services guarded by Legant's shipped resource-server
middleware** — the exact `sdk.Authenticate` + `sdk.RequireAction` you'd wire into
your own API (see `legant snippet`). Two faithful-mock services stand in for a
Salesforce-style CRM and its Bulk API 2.0 endpoint; one is seeded with **secrets
embedded in a support case** (the real secret-harvest UNC6395 pivoted on).

```sh
make demo-breach        # or: go run .
```

Self-contained — real `net/http` listeners, no external credentials, no Docker.

## The replay

The **same stolen token** is replayed twice:

- **Broad OAuth service-account token** (what was actually stolen): reads contacts,
  **bulk-exports 50k rows**, **harvests live AWS/Snowflake creds** from a case,
  pivots to the Bulk API — and stays valid ~10 days. The breach.
- **Legant on-behalf-of token** (audience = CRM only, no `bulk_export` tool, 15-min
  TTL, business-hours window), replayed identically:
  - bulk-export → **denied** (`tool "bulk_export" not permitted`)
  - harvest case secrets → **denied** (`resource "cases.secrets" not permitted`)
  - pivot to the Bulk API → **denied** (audience mismatch)
  - replayed after 16 min → **denied** (TTL expired; UNC6395 dwelled ~10 days)
  - replayed at 03:00 → **denied** (outside the business-hours window)
  - one signed-feed entry → **revoked**, offline (not an org-wide OAuth revoke)

Every denial is enforced **offline by the middleware**, with no callback — the same
code path a real Legant-protected API runs. The business-hours window is evaluated
against the service's own (injectable, for a deterministic demo) clock.

## Why an enterprise cares

Over-permissioned, long-lived integration tokens (~82:1 machine:human; ~97%
over-privileged) are the breach class behind Salesloft–Drift. Legant replaces the
flat, inherited bearer with a constrained, audience-bound, short-TTL, signed-feed-
revocable grant verified offline — so a stolen token can't bulk-export, can't reach
the secret-bearing records, can't pivot audiences, and dies in minutes or one feed
entry instead of ~10 days. (Honest: Legant doesn't stop the theft; it collapses the
blast radius.)
