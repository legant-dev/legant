"""Resource-server middleware for FastAPI and Flask.

A backend becomes a Legant-protected resource server in a few lines: verify the
Bearer token, expose the verified ``Claims``, and (optionally) authorize a
per-request ``Action``. This is the delegation-aware analog of a generic OIDC JWT
dependency — it understands the ``act`` chain, the constraint dimensions, RFC 8707
audience canonicalization, and the signed revocation feed.

FastAPI and Flask are NOT dependencies of this package; they are imported lazily
inside the factory functions, so ``import legant_sdk`` works without either.
"""

from __future__ import annotations

import json
from typing import Callable, Optional, Union

from .verifier import Action, AuthorizeError, Claims, Verifier, VerifyError

# An action can be a fixed Action, a callable deriving one from the request, or None.
ActionSpec = Union[Action, Callable[..., Action], None]


def bearer_token(authorization: Optional[str]) -> str:
    """Extract the token from an ``Authorization: Bearer <token>`` header value."""
    if not authorization:
        raise VerifyError("missing Authorization header")
    parts = authorization.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise VerifyError("Authorization header is not a Bearer token")
    return parts[1].strip()


def authenticate(verifier: Verifier, authorization: Optional[str]) -> Claims:
    """Verify the Bearer token from an Authorization header value (raises on failure)."""
    return verifier.verify(bearer_token(authorization))


def _resolve_action(spec: ActionSpec, scope: Optional[str], request) -> Optional[Action]:
    if scope is not None:
        return Action(scope=scope)
    if spec is None:
        return None
    if callable(spec):
        return spec(request)
    return spec


# ---- FastAPI ---------------------------------------------------------------


def fastapi_auth(
    verifier: Verifier,
    *,
    scope: Optional[str] = None,
    action: ActionSpec = None,
):
    """Return a FastAPI dependency that verifies the Bearer token (and optionally
    authorizes ``scope`` or ``action``), yielding the verified ``Claims``.

        claims_dep = fastapi_auth(verifier, scope="data:read")

        @app.get("/data")
        def read(claims: Claims = Depends(claims_dep)):
            ...

    ``action`` may be a fixed ``Action`` or ``callable(request) -> Action`` for
    per-request constraints (amount/resource/tool/time).
    """
    from fastapi import HTTPException, Request  # lazy import

    def dependency(request: Request) -> Claims:
        try:
            claims = authenticate(verifier, request.headers.get("authorization"))
        except VerifyError as e:
            raise HTTPException(
                status_code=401, detail=str(e), headers={"WWW-Authenticate": "Bearer"}
            )
        act = _resolve_action(action, scope, request)
        if act is not None:
            try:
                claims.authorize(act)
            except AuthorizeError as e:
                raise HTTPException(status_code=403, detail=str(e))
        return claims

    return dependency


# ---- Flask -----------------------------------------------------------------


def flask_require(
    verifier: Verifier,
    *,
    scope: Optional[str] = None,
    action: ActionSpec = None,
):
    """Return a Flask view decorator that verifies the Bearer token (and optionally
    authorizes ``scope``/``action``), storing the ``Claims`` on ``flask.g.legant``.

        @app.get("/data")
        @flask_require(verifier, scope="data:read")
        def read():
            claims = flask.g.legant
            ...
    """
    from functools import wraps

    from flask import Response, g, request  # lazy import

    def challenge(code: int, err: str, desc: str) -> "Response":
        resp = Response(f"{err}: {desc}", status=code)
        resp.headers["WWW-Authenticate"] = f'Bearer error="{err}", error_description="{desc}"'
        return resp

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                claims = authenticate(verifier, request.headers.get("Authorization"))
            except VerifyError as e:
                return challenge(401, "invalid_token", str(e))
            act = _resolve_action(action, scope, request)
            if act is not None:
                try:
                    claims.authorize(act)
                except AuthorizeError as e:
                    return challenge(403, "insufficient_scope", str(e))
            g.legant = claims
            return fn(*args, **kwargs)

        return wrapper

    return decorator


# ---- self-hosted MCP server helper -----------------------------------------


def mcp_tool_name(body: Union[bytes, str, dict]) -> str:
    """Extract the tool name from a JSON-RPC MCP ``tools/call`` request body, for
    resource servers that ARE an MCP server. Pair with ``claims.authorize``."""
    if isinstance(body, (bytes, str)):
        body = json.loads(body)
    if not isinstance(body, dict) or body.get("method") != "tools/call":
        raise ValueError(f"not a tools/call (method={body.get('method') if isinstance(body, dict) else None!r})")
    name = (body.get("params") or {}).get("name")
    if not name:
        raise ValueError("tools/call missing params.name")
    return name
