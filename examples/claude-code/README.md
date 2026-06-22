# Legant + Claude Code

Runnable artifacts for governing Claude Code agents with Legant. Full write-up:
[`docs/CLAUDE_CODE.md`](../../docs/CLAUDE_CODE.md).

## Door B — the guard hook (local tools: Read/Write/Edit/Bash)

```bash
# See it work with no setup (narrated; no DB, no Claude Code needed):
legant guard demo

# Wire it into THIS project (writes a guard dir OUTSIDE the project + prints a settings.json block):
legant guard init --project .
```

`legant guard init` prints a `.claude/settings.json` block with the env inlined
(active role: `builder`) and the absolute path of the guard dir it created —
call that `$GUARD`. [`settings.json`](settings.json) here is the minimal form
that instead reads `LEGANT_GUARD_*` from your shell:

```bash
export LEGANT_GUARD_TOKEN_FILE="$GUARD/builder.jwt"   # or reviewer.jwt / operator.jwt
export LEGANT_GUARD_JWKS="$GUARD/jwks.json"
export LEGANT_GUARD_FEED="$GUARD/feed.jwt"
export LEGANT_GUARD_AUDIT="$GUARD/audit.jsonl"
export LEGANT_GUARD_ISSUER="https://legant.local"
export LEGANT_GUARD_AUDIENCE="legant:claude-code"
```

Revoke the active agent mid-session (its next tool call is denied):

```bash
legant guard revoke --token-file $GUARD/builder.jwt
```

## Door C — sub-agent gets an attenuated child token

```bash
legant guard mint --parent $GUARD/builder.jwt \
  --agent agent:doc-writer --scopes fs.read --ttl 30m > $GUARD/doc-writer.jwt
```

The child can only ever do *less* than its parent; asking for a scope the parent
lacks is refused at mint. Point a sub-agent's `LEGANT_GUARD_TOKEN_FILE` at it.

## Door A — MCP tools behind the gateway (OAuth 2.1)

[`gateway-upstreams.json`](gateway-upstreams.json) is a sample upstream registry
for `legant gateway`. Once it's serving, add it to Claude Code:

```bash
claude mcp add --transport http finance https://gateway.you/mcp/finance
# /mcp → OAuth consent on Legant → tools/list is filtered to the delegated tools
```
