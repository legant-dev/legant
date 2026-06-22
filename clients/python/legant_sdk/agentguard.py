"""Framework-agnostic tool authorization for AI agents.

Wrap any tool callable — a LangChain ``@tool``, a CrewAI / LlamaIndex / AutoGen
tool, or a plain function — so every invocation is authorized against a Legant
delegation token, offline, with no callback. The agent only ever wields the
scoped, attenuating, revocable slice of authority the token carries; a
prompt-injected or buggy agent physically cannot exceed it.

    guard = AgentGuard(verifier, token="<the agent's delegation token>")

    @guard.tool("expenses:submit", amount_arg="amount", category_arg="category")
    def submit_expense(amount: float, category: str) -> str:
        ...   # only runs if the token permits this scope, amount, and category

These wrappers are plain callables, so they drop into any framework that takes a
function as a tool. ``token`` may also be a zero-arg callable, so it can be
refreshed (re-exchanged) without rebuilding the guard.
"""

from __future__ import annotations

import functools
from datetime import datetime
from typing import Callable, Optional, Union

from .verifier import Action, Claims, Verifier

TokenSource = Union[str, Callable[[], str]]


class AgentGuard:
    """Authorizes an agent's tool calls against a Legant delegation token."""

    def __init__(self, verifier: Verifier, token: TokenSource):
        self._verifier = verifier
        self._token = token

    def _current_token(self) -> str:
        return self._token() if callable(self._token) else self._token

    def authorize(
        self,
        scope: str,
        *,
        amount: float = 0.0,
        category: str = "",
        tool: str = "",
        resource: str = "",
        at: Optional[datetime] = None,
    ) -> Claims:
        """Verify the current token and authorize one action.

        Raises ``VerifyError`` / ``RevokedError`` if the token is invalid or
        revoked, or ``AuthorizeError`` if the action exceeds the delegation.
        Returns the verified :class:`Claims` (whose ``provenance()`` you can log).
        """
        claims = self._verifier.verify(self._current_token())
        claims.authorize(
            Action(scope=scope, amount=amount, category=category, tool=tool, resource=resource, at=at)
        )
        return claims

    def allowed(self, scope: str, **kwargs) -> bool:
        """Non-raising check — True iff :meth:`authorize` would succeed."""
        try:
            self.authorize(scope, **kwargs)
            return True
        except Exception:
            return False

    def tool(
        self,
        scope: str,
        *,
        tool: str = "",
        resource: str = "",
        amount_arg: Optional[str] = None,
        category_arg: Optional[str] = None,
    ) -> Callable[[Callable], Callable]:
        """Decorator that authorizes the wrapped tool before it runs.

        ``amount_arg`` / ``category_arg`` name the wrapped function's keyword
        arguments to read the monetary amount / category from, so constraint
        checks (max-amount, category allow-list) use the real call values.
        ``tool`` / ``resource`` are the Legant tool-constraint and resource-audience
        values to check (each defaults to empty = not constrained by that
        dimension).
        """

        def deco(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                amount = float(kwargs.get(amount_arg, 0) or 0) if amount_arg else 0.0
                category = str(kwargs.get(category_arg, "") or "") if category_arg else ""
                self.authorize(scope, amount=amount, category=category, tool=tool, resource=resource)
                return fn(*args, **kwargs)

            wrapper.__legant_guarded__ = True  # type: ignore[attr-defined]
            return wrapper

        return deco
