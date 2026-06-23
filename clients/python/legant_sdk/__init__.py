"""Legant SDK — offline verification and authorization of delegation tokens."""

from .agentguard import AgentGuard
from .middleware import (
    authenticate,
    bearer_token,
    fastapi_auth,
    flask_require,
    mcp_tool_name,
)
from .revocation import RevocationFeed, fetch_revocation_feed, parse_revocation_feed
from .verifier import (
    Action,
    AuthorizeError,
    Claims,
    RevokedError,
    Verifier,
    VerifyError,
    fetch_jwks,
    parse_jwks,
)

__all__ = [
    "Verifier",
    "Claims",
    "Action",
    "AgentGuard",
    "VerifyError",
    "AuthorizeError",
    "RevokedError",
    "parse_jwks",
    "fetch_jwks",
    "RevocationFeed",
    "fetch_revocation_feed",
    "parse_revocation_feed",
    "authenticate",
    "bearer_token",
    "fastapi_auth",
    "flask_require",
    "mcp_tool_name",
]
