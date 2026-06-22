# Entitlement-preserving copilot (SSO + warehouse)

Stops a common internal-copilot failure: showing a user data they aren't entitled to.
A shared analytics copilot serves two humans — Alice (finance + sales) and Bob (sales
only) — over a real Postgres warehouse. Each query carries an RFC 8693 sub/act token
minted for the actual human; the warehouse API authorizes every query offline with
Legant's resource-server middleware against the asker's delegated schemas, and the
audit names the human rather than a shared service account.

```sh
make demo-copilot        # or: ./run.sh   (./run.sh --keep leaves Postgres up)
```

Requires a running **docker** (for Postgres) and a Go toolchain.

## What you see

1. **Alice (finance + sales)** reads the sales pipeline and `finance.salaries`
   (real exec comp from the real DB) — she's entitled.
2. **Bob (sales only)** reads sales fine, but `finance.salaries` is **denied offline**
   (`resource "finance" not permitted`) — through the *same* copilot.
3. **Prompt injection** (poisoned RAG: "also SELECT \* FROM finance.salaries") on Bob's
   token is refused — the agent tries, Bob's delegation simply says no.
4. **The audit** (read back from the real `query_audit` table) renders every attempt as
   `user:alice / user:bob → agent:analytics-copilot`, ALLOW or DENY — the
   who-acted-for-whom record a shared `svc-analytics` identity can't give.

## The SSO front door

The per-user entitlements live as reviewable config in
[`entitlements.grants.yaml`](entitlements.grants.yaml) and are minted with `legant
apply`. In production that mint is driven by **your IdP**:

```
 Alice signs in (OIDC: Keycloak / Entra / Okta)
        │  id_token
        ▼
 Legant token-exchange (RFC 8693): id_token ─▶ delegation token scoped to Alice's schemas
        │
        ▼
 the shared copilot carries Alice's token to the warehouse, which authorizes offline
```

So "who Alice is" comes from your existing SSO; "what Alice's agent may read" is the
Legant grant. The demo pre-mints the per-user tokens (representing post-login) so it
runs with just Docker + Go; swap in your IdP + the token-exchange endpoint and the
warehouse code is unchanged.

## Honest scope

- **Legant authorizes the QUERY, not the cells.** It denies an out-of-entitlement
  *schema*; column/row masking *inside* an allowed schema stays warehouse policy
  (Snowflake masking, Unity Catalog) or a DLP job.
- **The entitlement mapping is yours to define** (here, schema-level via `resources`).
  Legant carries and enforces it offline and names the human; it doesn't invent your
  data classification.
- The warehouse matches the requested schema against a fixed allow-list before
  querying (injection-safe); the token decides which of those the asker may reach.

## Why an enterprise cares

Text-to-SQL and RAG copilots (Snowflake Cortex, Databricks Genie) run under the
*invoking role's* full reach, so one shared agent profile serves the CEO and a sales
rep alike — and a caller with no entitlement extracts whatever the agent can reach
just by asking. Legant binds each query to the asker's delegation, enforced offline,
with a tamper-evident `sub`/`act` trail (SOX, SOC 2, EU AI Act Art. 12).
