# Legant + coding agents — delegated authority for Claude Code, Codex & opencode

A coding agent runs a lot of actions on your behalf: it reads and writes files,
runs shell commands, fetches URLs, calls MCP tools, and spawns sub-agents. Legant
lets you put **scoped, time-boxed, attenuating, revocable, auditable authority**
around those actions — defined as roles, enforced offline from a signed
delegation token — across **Claude Code, OpenAI Codex CLI, and opencode**.

## Install — one command, any agent

```bash
legant guard install            # detects your agent(s) and wires the guard hook
legant guard install --role builder   # or pick a stricter rule set
legant guard uninstall          # remove it
```

`install` sets up a local guard (signing key, role tokens, revocation feed) if
needed, then wires a **pre-tool hook** into each detected agent so every tool call
is authorized offline. **Start a fresh agent session** to load the hook (hooks
load at session start), then a denied action is refused — **even in bypass /
`--yolo` / full-auto mode**, because the guard blocks via the hook layer that
runs *below* the permission/approval system.

| Agent | Hook mechanism | Block | Config written | Survives "bypass" |
|---|---|---|---|---|
| **Claude Code** | PreToolUse (JSON stdin) | exit 2 | `.claude/settings.local.json` | Yes — bypass doesn't bypass hooks |
| **OpenAI Codex CLI** | PreToolUse (JSON stdin) | exit 2 + stderr | `.codex/hooks.json` | Yes — `--yolo` keeps hooks |
| **opencode** | `tool.execute.before` plugin | plugin throws | `.opencode/plugin/legant-guard.ts` | Yes — plugin runs regardless |

One policy engine, three thin adapters — the rule (token) and the decision logic
are identical; only the per-agent shim differs. The same `legant guard show` /
[rule viewer](../site/guard.html) inspect the rule for any of them.

**Coverage caveats (honest):** Codex's PreToolUse currently intercepts
Bash/`apply_patch`/MCP (not every read path), and its newer `unified_exec`
(Codex Desktop / Windows) isn't reliably hooked yet; opencode's
`tool.execute.before` has historically not fired for **sub-agent** (`task`) tool
calls. For both, pair the guard with the agent's own config-level `deny` rules
and an OS sandbox for hard guarantees. As always, `shell.exec` is a coarse grant
(see below).

---

Claude Code runs a lot of agent actions on your behalf: it reads and writes
files, runs shell commands, fetches URLs, calls MCP tools, and spawns
sub-agents. Legant lets you put **scoped, time-boxed, attenuating, revocable,
auditable authority** around those actions — defined as roles, enforced offline
from a signed delegation token.

There are **two integration surfaces**, plus a bonus that falls out of Legant's
delegation model:

| Door | Governs | How | Status |
|---|---|---|---|
| **A — MCP gateway** | Remote **MCP tools** | Put MCP servers behind `legant gateway`; Claude Code reaches them over OAuth 2.1 | Built ([`internal/mcpgw`](../internal/mcpgw)) |
| **B — Guard hook** | Built-in tools (**Read/Write/Edit/Bash/WebFetch**) | A `legant guard` PreToolUse hook authorizes every tool call | Built ([`internal/ccguard`](../internal/ccguard)) |
| **C — Sub-agent chains** | **Sub-agent** authority | Mint an attenuated child token a sub-agent carries | Built (`legant guard mint --parent`) |

> **Honest framing.** Claude Code already has a native permission system
> (allow/deny/ask globs, plus admin-managed policy). For "block `rm -rf`, allow
> `npm test`" you don't need Legant. Legant earns its place where local rules
> stop: a **central tamper-evident audit trail** across many agents, **live
> revocation** (kill an agent mid-task), **time-boxed** grants, and
> **attenuating delegation across a chain of agents** with cryptographic
> provenance. Use it where those matter.

---

## Door B — the guard hook (governs local tools)

Claude Code fires a **PreToolUse** hook before every tool call and lets the hook
deny it with a reason. `legant guard check` is that hook: it authorizes the call
against a Legant delegation token — entirely offline, no server, no callback.

### One-minute local trial

```bash
# from your project root
legant guard init --project .   # writes a per-project guard dir OUTSIDE the project
                                # (under your user config dir) holding key.pem/jwks.json/feed.jwt/*.jwt
```

The setup deliberately lives **outside** the project — if the signing key and
feed sat inside the agent's writable root, the agent could read the key or roll
back its own revocation, so `init` refuses that layout. `init` prints a ready
`.claude/settings.json` block (env wired inline) with the **builder** role
active. Drop it in, restart Claude Code, and the agent is bounded by the token.
To see it work without Claude Code at all:

```bash
legant guard demo                      # a narrated scenario: scope, paths, tripwires, attenuation, revocation
```

### What a role is

A role compiles to a delegation grant. Four are built in:

| Role | Capabilities | Containment |
|---|---|---|
| `reviewer` | `fs.read` within the project | **hard** — no shell, truly path-contained |
| `builder` | `fs.read fs.write shell.exec`, project root, tight command allow-list (`go git make ls cat grep …`, **no interpreters/network**), deny `.env`/`.ssh`/`curl` | files contained; shell coarse (see below) |
| `open` | `*` EXCEPT deny-path `.env`/`.ssh`/… and deny-cmd `curl`/`ssh`/… | "allow everything except" |
| `operator` | `*` (wildcard, no denies) | none — an audited escape hatch |

The capability verbs a tool maps to:

| Claude Code tool | verb |
|---|---|
| Read, Glob, Grep, LS, NotebookRead | `fs.read` |
| Write, Edit, MultiEdit, NotebookEdit | `fs.write` |
| Bash | `shell.exec` |
| WebFetch, WebSearch | `net.fetch` |
| Task (spawn sub-agent) | `agent.spawn` |
| `mcp__*` | `mcp.call` |
| anything else | `other` (fail closed — a new tool needs an explicit grant) |

The token carries the authority: scope (verbs), an optional tool allow-list, and
constraint "resources" tagged `path:`/`cmd:`/`host:` (allow) and
`deny-path:`/`deny-cmd:`/`deny-host:`/`deny-tool:` (deny, which **overrides**
allow). The guard resolves every path through **symlinks** to its true absolute
target **before** the root check, so neither `../../etc/passwd` nor a planted
symlink escapes a root.

### Granular deny — "allow everything EXCEPT" (the rule Claude Code/Codex can't express)

Coding agents give you *modes* (`auto`, `bypass`), not *rules*. Legant adds the
exclusions they're missing:

```
scope: "*"                              # broad authority…
deny-path: ./secrets, ./.env, .git      # …minus these, always
deny-cmd:  psql, terraform, kubectl      # never, even in full-auto
deny-host: *.internal
```

Deny rules also compose with attenuation: a sub-agent inherits its parent's
denials and can only add more.

**Add your own rules instantly — the deny overlay.** The token is the signed
*ceiling*; on top of it you can keep a local, editable **deny-only overlay** that
takes effect on the **next tool call** (no re-mint, no re-install) and applies to
every installed agent:

```bash
legant guard deny  --cmd terraform --path ./prod --host '*.internal'  # add denials
legant guard allow --cmd terraform                                    # remove one
legant guard rules                                                    # show the overlay
```

The overlay can **only tighten** — it can never grant something the token denies,
so it cannot widen authority or regress the security model (an empty overlay
changes nothing). You can also build one in the browser at the
[rule viewer / builder](../site/guard.html), which emits both the `guard deny`
command and the `overlay.json` to drop in your guard dir. For a live local editor,
run **`legant guard ui`** — a loopback-only control panel (random per-run token,
loopback Host only) that views the role rules and writes the deny overlay directly.

### Capability containment — what's hard vs coarse

- **`fs.read` / `fs.write` are HARD-contained.** Read/Write/Edit are path-checked
  against the allow-roots and deny-rules, symlink-resolved. The `reviewer` role
  (read-only, no shell) is the fully-contained one.
- **`shell.exec` is a COARSE, powerful grant.** A shell command cannot be
  path-contained offline: an allow-listed `cat`/`sed`/`python3` or a redirect can
  touch any path, and no command parser stops that soundly. For `shell.exec` the
  real guarantees are the **command allow/deny lists**, the **catastrophic-command
  tripwires** (`rm -rf /` incl. long-form flags, `curl … | sh`, fork bombs,
  `mkfs`, `dd of=/dev/…`), **best-effort redirect containment**, plus **audit and
  revocation**. We say this plainly: if you need *hard* filesystem containment,
  use a role without `shell.exec`, or run the agent in an OS sandbox (seccomp,
  `sandbox-exec`, a container). The guard is policy + audit + kill-switch, not a
  kernel sandbox.
- **MCP/Task tools are authorized by coarse verb** (`mcp.call`/`agent.spawn`) —
  per-tool argument inspection for MCP servers is future work; use Door A (the
  gateway) for fine-grained MCP control today.

### Two design properties worth knowing

- **Survives "bypass permissions" mode.** This is the point. Claude Code's
  permission *modes* (`auto`, `bypassPermissions`/"YOLO") skip the permission
  *prompts* — but PreToolUse hooks still run, and **bypass does not bypass
  hooks**. The guard denies by exiting with **code 2**, the hard block Claude Code
  applies *before* permission evaluation, so a denied `curl` is refused even when
  the user chose bypass mode. The guard sits *below* the permission system.
- **Additive denial only.** The guard *never* emits an "allow" decision — an
  allowed call exits 0 with no output and falls through to Claude Code's own
  permission prompts. Installing the guard can only ever *tighten* what an agent
  may do, never loosen it. This mirrors Legant's revocation feed, which can miss a
  revoke but can never forge a grant.
- **Fails closed, and protects itself.** The guard's own trust material (signing
  key, feed, token, `.claude/settings.json`) is **always denied** to the agent, so
  it can't roll back its own revocation or read the signing key — and `guard init`
  refuses to place that material inside the project. A configured revocation feed
  that can't be loaded (deleted/corrupt/expired) **fails closed** (deny all)
  rather than silently disabling revocation. A broken config with a token present
  also fails closed; with *no* token the guard is simply off.

### Revoke an agent mid-session

```bash
legant guard revoke --token-file $GUARD/builder.jwt
```

The next tool call the agent makes is denied — the token it already holds is on
the signed feed. This is the offline kill-switch, applied to your own editor.

### Audit

Set `LEGANT_GUARD_AUDIT=path.jsonl` (the `init` settings block does) and every
decision is appended with tool, verb, target, decision, reason, jti, and
provenance — the offline analog of the server-side audit hash chain.

### Connected mode — watch decisions in the live console

By default the guard is fully offline — its decisions go to the local audit
JSONL, nothing leaves the machine. If you *want* central visibility, point it at
a running Legant server and every allow/deny streams into the **`/admin/live`**
console in real time (the authority graph + decision stream), alongside gateway
and mint/revoke events:

```bash
# on the server: enable the ingest endpoint with a shared secret
LEGANT_LIVE_INGEST_TOKEN=$(openssl rand -hex 24) legant serve

# in the guard hook env: where to report, and the same secret
export LEGANT_GUARD_LIVE_URL="https://issuer.you/admin/live/ingest"
export LEGANT_GUARD_LIVE_TOKEN="<the same secret>"
```

The report is best-effort and time-bounded (≤800ms), never affects the allow/deny
outcome, and is a no-op when `LEGANT_GUARD_LIVE_URL` is unset. The decision
appears in the console tagged `claude-code` with its provenance, tool, and reason.
(The token's rule itself isn't a server-side row — it was minted offline — so it
won't show in `/account/delegations`; use `legant guard show` or the
[rule viewer](../site/guard.html) for that.)

### Configuration (environment)

| Variable | Meaning |
|---|---|
| `LEGANT_GUARD_TOKEN` / `LEGANT_GUARD_TOKEN_FILE` | the delegation token (providing one turns the guard ON) |
| `LEGANT_GUARD_JWKS` | path to the issuer JWKS (verifies token + feed) |
| `LEGANT_GUARD_ISSUER` / `LEGANT_GUARD_AUDIENCE` | expected issuer / the guard's resource-server id |
| `LEGANT_GUARD_FEED` | signed revocation feed (file or, in production, the issuer's `/.well-known/revoked`); configured-but-unloadable fails **closed** |
| `LEGANT_GUARD_AUDIT` | append decision audit JSONL here |
| `LEGANT_GUARD_LIVE_URL` / `LEGANT_GUARD_LIVE_TOKEN` | connected mode: stream each decision to a server's `/admin/live` console |

In production the token comes from a real **RFC 8693 token-exchange** against
your Legant issuer, and `JWKS`/`FEED` point at the issuer's published endpoints —
the local `init` files are just a zero-dependency way to try it.

---

## Door A — the MCP gateway (governs MCP tools)

Claude Code supports **remote MCP servers over HTTP with OAuth 2.1**, and
implements the MCP authorization spec: RFC 9728 protected-resource metadata, RFC
8414 AS metadata, RFC 7591 dynamic client registration, RFC 8707 resource
indicators. Legant implements **all of those** (that is the M4 surface + the
gateway), so the fit is native.

Put your MCP servers behind the gateway and point Claude Code at it:

```bash
legant gateway        # serves /mcp/{slug} in front of your registered upstreams
```

```bash
claude mcp add --transport http finance https://gateway.you/mcp/finance
#   /mcp  → browser OAuth → consent on Legant's delegation screen
#   Claude Code now holds a scoped "acting-for-Alice" token and sends it on every call
```

What you get, with no new code (see [`internal/mcpgw`](../internal/mcpgw)):

- **`tools/list` is filtered to the delegated tools** — Claude Code can't even
  see tools the role lacks.
- **`tools/call` is authorized per tool**, with the token's scope + constraints.
- The gateway mints a **fresh, audience-bound downstream token** preserving the
  `sub`/`act` provenance (confused-deputy protection — it never forwards the
  inbound token), with expiry clamped to the inbound token.
- Every call is **revocation-checked** and **audited**.

A sample upstream registry is in
[`examples/claude-code/gateway-upstreams.json`](../examples/claude-code/gateway-upstreams.json).

---

## Door C — sub-agent delegation chains

When Claude Code spawns a sub-agent, that sub-agent should be able to do **less**
than its parent, not more. Legant's multi-hop delegation gives you exactly that:
mint an attenuated child token from the parent's token.

```bash
# the builder agent delegates a read-only slice to a doc-writer sub-agent
legant guard mint \
  --parent $GUARD/builder.jwt \
  --agent agent:doc-writer \
  --scopes fs.read \
  --ttl 30m  > $GUARD/doc-writer.jwt
```

- The child's scopes must be a **subset** of the parent's — asking for a
  capability the parent lacks is **refused at mint** (no escalation, ever).
- Constraints are **tightened**, expiry is **clamped** to the parent's, and the
  `sub`/`act` chain is **extended** (`user:alice -> agent:builder ->
  agent:doc-writer`), so the audit shows which agent in the tree did what.

Point a sub-agent's settings at its child token (`LEGANT_GUARD_TOKEN_FILE`) and
the guard enforces the narrower authority for that sub-agent — a sub-agent
*provably* cannot exceed its parent. This is the [Charter
demo](../examples/charter) idea applied to Claude Code's own agent tree.

---

## Putting it together

A realistic setup uses **all three**: the guard (B) bounds what the local agent
can do to your filesystem and shell; the gateway (A) bounds what it can do to
remote services; and child tokens (C) ensure each spawned sub-agent inherits a
strictly smaller slice — with one audit trail and one revocation switch across
the whole tree.
