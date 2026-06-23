# legant.grants.yaml reference

The grants file is how a human declares, in version-controlled YAML, what an agent can and cannot do.

A `legant.grants.yaml` says "principal P delegates to agent A these scopes, capped by these constraints." You review it in a pull request, lint it in CI, apply it to mint signed tokens, and ask who-can to check what it permits. It is not a policy language. The schema is a fixed 1:1 serialization of Legant's own constraint dimensions, so the rule travels inside the token and verifies offline at any resource server (something an OPA or Kyverno content gate cannot do).

The author loop:

```
legant init grants          # write a commented legant.grants.yaml starter
legant lint  -f legant.grants.yaml   # validate, no side effects, non-zero exit on error
legant apply -f legant.grants.yaml   # mint one signed token per grant into .legant/
legant who-can -f legant.grants.yaml --scope warehouse:query --resource finance
```

`apply` is offline: no Postgres, no Docker. On first run it writes `.legant/` (`key.pem`, `jwks.json`, `feed.jwt`) and mints a token per grant. It is idempotent, so re-applying an unchanged file is a no-op. For a full walkthrough see [docs/GETTING_STARTED.md](GETTING_STARTED.md).

## The scaffold

`legant init grants` writes this starter (abbreviated):

```yaml
version: 1
audience: https://api.example.internal
defaults:
  ttl: 1h
grants:
  - name: alice-analytics
    principal: user:alice
    agent: agent:analytics-copilot
    scopes: [warehouse:query]
    audience: warehouse://analytics
    ttl: 1h
    constraints:
      resources: [sales, finance]
      time_window: { weekdays: [1,2,3,4,5], start: "09:00", end: "17:00", tz: UTC }

  - name: payments-bot
    principal: user:treasury
    agent: agent:payments
    scopes: [transfer:prepare]
    audience: https://treasury.example.internal
    constraints:
      max_amount: 5000
      categories: [vendor, payroll]
    delegate:
      - agent: agent:reconciler
        scopes: [transfer:prepare]
        constraints:
          max_amount: 500
```

Unknown keys are rejected at parse time, so a typo fails loudly at lint instead of being silently ignored.

## Top-level keys

| Field | Type | Meaning | Example |
| --- | --- | --- | --- |
| `version` | int | Schema version. 1 is the only understood value (a warning otherwise). | `version: 1` |
| `audience` | string | Default resource-server audience (RFC 8707) for grants that omit their own `audience`. | `audience: https://api.example.internal` |
| `defaults.ttl` | duration string | Default token lifetime for grants that omit `ttl`. Go duration syntax. Falls back to `1h` if unset. | `defaults: { ttl: 1h }` |
| `issuer` | string | Optional. Overrides the issuer in minted tokens. Defaults to the local guard issuer (`https://legant.local`). | `issuer: https://legant.local` |
| `grants` | list | The grants. Required, must be non-empty. | see below |

## A grant

Each entry under `grants` is one root delegation: principal to agent, with constraints and any attenuated hand-offs.

| Field | Type | Meaning | Example |
| --- | --- | --- | --- |
| `name` | string | Label for diffs, lint messages, and the token filename. Optional. Falls back to `principal->agent`. | `name: alice-analytics` |
| `principal` | string | The delegating identity (the human or root principal). Required. Must differ from `agent`. | `principal: user:alice` |
| `agent` | string | The delegatee that receives the authority. Required. | `agent: agent:analytics-copilot` |
| `scopes` | list of string | The capability scopes granted. Required, non-empty. | `scopes: [warehouse:query]` |
| `audience` | string | The resource server this token is for (RFC 8707). Overrides the top-level `audience`. One of the two must be set. | `audience: warehouse://analytics` |
| `ttl` | duration string | Token lifetime. Overrides `defaults.ttl`. Must be positive. | `ttl: 1h` |
| `constraints` | object | Fine-grained limits signed into the token (see next table). Optional. | `constraints: { max_amount: 5000 }` |
| `delegate` | list | Attenuated sub-delegations to further agents. Each child can only do less (see Delegation). | see below |

`apply` mints `.legant/<name>.jwt` per grant. A delegated child is `.legant/<name>__<agent>.jwt` (for example `payments-bot__agent-reconciler.jwt`). The token carries `iss`, `kid=legant-guard-local`, `alg=RS256`, `sub=<principal>`, `act={sub:<agent>}`, `aud=[<audience>]`, `scope` (space-joined), `exp`, `iat`, `jti`.

## Constraint dimensions

Constraints are the fine-grained limits. Every dimension here is signed into the token under the `cnst` claim and checked OFFLINE at the resource server by the SDK (no callback to Legant). An empty or unset dimension means "no restriction on this dimension".

| Constraint | Type | Meaning | Where enforced | Example |
| --- | --- | --- | --- | --- |
| `max_amount` | number | Caps the monetary value of an action. Must be `>= 0`. An action whose amount exceeds it is denied. | Offline at the resource server | `max_amount: 5000` |
| `categories` | list of string | Allow-list of categories an action may target. | Offline at the resource server | `categories: [vendor, payroll]` |
| `tools` | list of string | Allow-list of MCP tool names the holder may invoke. | Offline at the resource server | `tools: [search, read_file]` |
| `resources` | list of string | Allow-list of resource audiences (RFC 8707) the token may target. | Offline at the resource server | `resources: [sales, finance]` |
| `time_window` | object | Restricts WHEN the authority may be used. | Offline at the resource server | see below |

### time_window sub-fields

| Sub-field | Type | Meaning | Example |
| --- | --- | --- | --- |
| `weekdays` | list of int | Allowed days. 0 is Sunday through 6 is Saturday (matches Go's weekday numbering). Empty means any day. Each value must be 0..6. | `weekdays: [1,2,3,4,5]` (Mon to Fri) |
| `start` | string | Inclusive start of the daily window, `HH:MM` 24-hour. Required when `time_window` is set. | `start: "09:00"` |
| `end` | string | Inclusive end of the daily window, `HH:MM`. Must be `>= start` (no wrap across midnight). | `end: "17:00"` |
| `tz` | string | IANA location name the window is evaluated in. Empty means UTC. An unknown zone fails closed (denies). | `tz: America/New_York` |

The weekday convention is confirmed in `internal/delegation/delegation.go` (`Weekdays []int // 0=Sunday ... 6=Saturday`) and the window is checked against the request time, so `weekdays: [1,2,3,4,5]` is Monday through Friday.

## Why there is no `rate` field

A grant has no `rate` key. This is deliberate. A rate cap (for example "at most 10 mints per rolling hour") needs shared state to count past use. A resource server is stateless: it verifies a self-contained token offline, with no callback and no shared counter, so it cannot honestly enforce a rolling count. Putting `rate` in a file that promises offline enforcement would be dishonest.

Rate is therefore enforced at MINT time only, by the live Legant issuer during token exchange, under a per-delegation lock (see `internal/auth/token_exchange.go`). It is not part of the declarative grants schema. Every other constraint in the table above travels in the token and is enforced offline.

## Delegation and attenuation

A `delegate` child is a sub-agent that can only ever do LESS than its parent. Legant enforces this two ways, and they behave differently:

- Over-broad SCOPES are REJECTED. A child whose `scopes` are not a subset of the parent's fails `lint` and `apply` with a non-zero exit. Example error: `delegate agent:b: scopes [read write] exceed delegator's scopes [read]`. Scope attenuation is checked when the grant tree is built (`Delegate` in `internal/delegation/delegation.go`), which `lint` and `apply` both do.

- Over-broad CONSTRAINTS are CLAMPED, not rejected. A child constraint looser than the parent's is silently tightened to the parent, and `lint`/`apply` still succeed. The clamp is `Tighten()` in `internal/delegation/delegation.go`: `max_amount` becomes the minimum of parent and child; `categories`/`tools`/`resources` become the intersection (a disjoint intersection collapses to a deny-all that matches nothing, never to "no restriction"); the time window intersects within the same timezone (cross-timezone keeps the parent as the ceiling). A child declaring `max_amount: 9999` under a parent of `max_amount: 100` lints clean and mints a token capped at 100.

So a child can narrow authority but never widen it. Where it tries to widen scope, you get an error; where it tries to widen a constraint, you get a quietly tighter token. Run `legant who-can` or `legant show --token-file .legant/<name>__<agent>.jwt` to see the effective rule a child token actually carries.

## See also

- [docs/CONCEPTS.md](CONCEPTS.md): the delegation model, the constraint dimensions, and offline verification.
- [docs/GETTING_STARTED.md](GETTING_STARTED.md): the end-to-end author, lint, apply, who-can walkthrough.
