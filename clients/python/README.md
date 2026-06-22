# legant-sdk (Python)

Offline verifier + authorizer for Legant delegation tokens. Its only dependency
is [`cryptography`](https://pypi.org/project/cryptography/) (Python ≥ 3.9).

```python
from legant_sdk import fetch_jwks, Verifier, Action, fetch_revocation_feed

issuer = "https://auth.example.com"
keys = fetch_jwks(f"{issuer}/.well-known/jwks.json")

# Tier B (optional): reject revoked tokens offline, refreshed in the background.
feed = fetch_revocation_feed(f"{issuer}/.well-known/revoked", issuer, keys)
feed.start_polling(10.0, on_error=print)

verifier = Verifier(issuer, "https://my-api.example/", keys, feed=feed)

# Per request:
claims = verifier.verify(bearer_token)  # raises VerifyError / RevokedError on failure
claims.authorize(Action(scope="expenses:submit", amount=120, category="travel"))  # raises AuthorizeError on 403
print(claims.provenance())  # "user:alice -> agent:assistant"
```

`verify` raises `VerifyError` (or `RevokedError` when the token is in the feed);
`authorize` raises `AuthorizeError` when a scope or constraint is denied. Catch
them to return 401 / 403.

## Guard an agent's tools — any framework

`AgentGuard` wraps any tool callable so every invocation is authorized against
the agent's delegation token — offline, no callback. The wrapped function is a
plain callable, so it drops into LangChain, CrewAI, LlamaIndex, AutoGen, or your
own loop unchanged. A prompt-injected or buggy agent cannot exceed the scoped,
revocable slice the token carries.

```python
from legant_sdk import Verifier, AgentGuard

verifier = Verifier(issuer, "https://my-api.example/", keys, feed=feed)
guard = AgentGuard(verifier, token=agent_delegation_token)  # token may be a callable, to refresh

@guard.tool("expenses:submit", amount_arg="amount", category_arg="category")
def submit_expense(amount: float, category: str) -> str:
    ...  # only runs if the token permits this scope, amount, and category — else AuthorizeError

# LangChain: from langchain_core.tools import tool;  lc_tool = tool(submit_expense)
# CrewAI:    @tool("Submit expense")  def submit_expense(...): ...  then wrap with @guard.tool(...)
```

Or check inline without the decorator: `guard.authorize("scope", amount=…)` (raises)
or `guard.allowed("scope", amount=…)` (returns a bool).

## Test

```bash
python3 -m unittest discover -s tests    # runs the shared conformance vectors (see ../conformance)
```
