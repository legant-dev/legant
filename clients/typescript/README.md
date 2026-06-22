# @legant/sdk (TypeScript / Node)

Offline verifier + authorizer for Legant delegation tokens. **Zero runtime
dependencies** — RS256 verification uses Node's built-in `crypto` (Node ≥ 18).

```ts
import { fetchJWKS, Verifier, fetchRevocationFeed } from '@legant/sdk';

const issuer = 'https://auth.example.com';
const keys = await fetchJWKS(`${issuer}/.well-known/jwks.json`);

// Tier B (optional): reject revoked tokens offline, refreshed in the background.
const feed = await fetchRevocationFeed(`${issuer}/.well-known/revoked`, issuer, keys);
feed.startPolling(10_000, (e) => console.error(e));

const verifier = new Verifier(issuer, 'https://my-api.example/', keys, { feed });

// Per request:
const claims = verifier.verify(bearerToken); // throws on bad sig / iss / aud / exp / revoked
claims.authorize({ scope: 'expenses:submit', amount: 120, category: 'travel' }); // throws on 403
console.log(claims.provenance()); // "user:alice -> agent:assistant"
```

`verify` throws on any failure (and a `RevokedError` specifically when the token
is in the feed); `authorize` throws when a scope or constraint is denied. Catch
them to return 401 / 403.

## Guard an agent's tools — any framework

`AgentGuard` wraps any tool so every invocation is authorized against the agent's
delegation token — offline. The wrapped value is a plain async function, so it
drops into the Vercel AI SDK (`tool({ execute })`), Mastra, LangChain.js, or your
own loop. A prompt-injected or buggy agent cannot exceed the scoped, revocable
slice the token carries.

```ts
import { Verifier, AgentGuard } from '@legant/sdk';

const guard = new AgentGuard(verifier, agentDelegationToken); // token may be a () => string to refresh

const submitExpense = guard.tool(
  'expenses:submit',
  async ({ amount, category }: { amount: number; category: string }) => {
    /* ... */ return 'ok';
  },
  { amountArg: 'amount', categoryArg: 'category' },
); // submitExpense({...}) throws unless the token permits this scope/amount/category

// Vercel AI SDK:  tool({ description, parameters, execute: guard.tool('scope', execute, {...}) })
```

Or check inline: `await guard.authorize('scope', { amount })` (throws) /
`await guard.allowed('scope', { amount })` (returns a boolean).

## Build & test

```bash
npm install
npm test    # builds, then runs the shared conformance vectors (see ../conformance)
```
