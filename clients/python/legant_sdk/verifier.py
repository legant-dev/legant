"""Offline verifier + authorizer for Legant delegation tokens.

Verifies a composite sub/act token against the issuer's JWKS and authorizes a
request's scope and constraints, entirely offline (no callback to Legant). Its
only dependency is ``cryptography``.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Union
from zoneinfo import ZoneInfo

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Sentinel Legant puts in an allow-list that intersected to nothing during
# re-delegation. It matches no real value and denies the dimension entirely.
# Must match internal/delegation and the Go/TS SDKs.
_DENY_ALL = "\x00legant:deny-all"


class VerifyError(Exception):
    """Raised when a token fails verification."""


class AuthorizeError(Exception):
    """Raised when an action is not permitted by the token's scope/constraints."""


class RevokedError(VerifyError):
    """Raised by Verifier.verify when the token's jti is in the revocation feed."""

    def __init__(self) -> None:
        super().__init__("token revoked")


@dataclass
class Action:
    scope: str
    amount: float = 0.0
    category: str = ""
    tool: str = ""
    resource: str = ""
    at: Optional[datetime] = None  # instant of the action; None = now


@dataclass
class Claims:
    raw: dict

    @property
    def subject(self) -> str:
        return self.raw.get("sub", "")

    @property
    def jti(self) -> str:
        return self.raw.get("jti", "")

    @property
    def scope(self) -> str:
        return self.raw.get("scope", "")

    @property
    def constraints(self) -> Optional[dict]:
        return self.raw.get("cnst")

    def provenance(self) -> str:
        """Renders e.g. 'user:alice -> agent:assistant -> agent:ocr'."""
        parts = [self.raw.get("sub", "")]
        chain = []
        a = self.raw.get("act")
        while a:
            chain.append(a.get("sub", ""))
            a = a.get("act")
        parts.extend(reversed(chain))
        return " -> ".join(parts)

    def authorize(self, action: Action) -> None:
        """Raises AuthorizeError if the scope is missing or a constraint is violated."""
        if action.scope not in self.scope.split():
            raise AuthorizeError(f'missing required scope "{action.scope}"')
        k = self.constraints
        if not k:
            return
        max_amount = k.get("max_amount")
        if max_amount is not None and action.amount > max_amount:
            raise AuthorizeError(f"amount {action.amount} exceeds max_amount {max_amount}")
        _permit_list("category", k.get("categories"), action.category, canonical=False)
        _permit_list("tool", k.get("tools"), action.tool, canonical=False)
        _permit_list("resource", k.get("resources"), action.resource, canonical=True)
        tw = k.get("time_window")
        if tw:
            at = action.at or datetime.now(timezone.utc)
            if not _time_window_allows(tw, at):
                raise AuthorizeError("action is outside the delegated time window")


class Verifier:
    def __init__(
        self,
        issuer: str,
        audience: str,
        keys: dict,
        feed=None,
        feed_fail_closed_ms: Optional[int] = None,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._keys = keys
        self._feed = feed
        self._feed_fail_closed_ms = feed_fail_closed_ms

    def verify(self, token: str) -> Claims:
        """Verifies RS256 signature (by kid), issuer, expiry, not-before, and
        audience, and requires an act claim. Raises VerifyError on any failure."""
        parts = token.split(".")
        if len(parts) != 3:
            raise VerifyError("malformed token")
        h, p, s = parts
        header = json.loads(_b64url(h))
        if header.get("alg") != "RS256":
            raise VerifyError(f"unexpected alg {header.get('alg')}")
        kid = header.get("kid")
        if not kid:
            raise VerifyError("token missing kid header")
        key = self._keys.get(kid)
        if key is None:
            raise VerifyError(f'unknown signing key "{kid}"')
        try:
            key.verify(_b64url(s), f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            raise VerifyError("signature verification failed")
        c = json.loads(_b64url(p))
        if c.get("iss") != self._issuer:
            raise VerifyError("invalid issuer")
        now = time.time()
        exp = c.get("exp")
        if exp is None:
            raise VerifyError("token has no expiration")
        if now >= exp:
            raise VerifyError("token is expired")
        nbf = c.get("nbf")
        if nbf is not None and now < nbf:
            raise VerifyError("token is not valid yet")
        if not c.get("act"):
            raise VerifyError("not a delegation token (no act claim)")
        if not _audience_matches(c.get("aud"), self._audience):
            raise VerifyError("token audience does not include this resource server")
        if self._feed is not None:
            if self._feed_fail_closed_ms is not None and self._feed.staleness() > self._feed_fail_closed_ms:
                raise VerifyError("revocation feed is stale and fail-closed is set")
            jti = c.get("jti")
            if jti and self._feed.is_revoked(jti):
                raise RevokedError()
        return Claims(c)


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _permit_list(dim: str, allowed, value: str, canonical: bool) -> None:
    if not allowed:
        return
    if _DENY_ALL in allowed:
        raise AuthorizeError(f"{dim} access is fully restricted by the delegation")
    if value == "":
        return
    match = value in allowed
    if not match and canonical:
        cv = _canonicalize_audience(value)
        match = any(_canonicalize_audience(a) == cv for a in allowed)
    if not match:
        raise AuthorizeError(f'{dim} "{value}" not permitted')


def _audience_matches(aud: Union[str, list, None], want: str) -> bool:
    if aud is None:
        auds = []
    elif isinstance(aud, list):
        auds = aud
    else:
        auds = [aud]
    cw = _canonicalize_audience(want)
    return any(_canonicalize_audience(a) == cw for a in auds)


def _canonicalize_audience(raw: str) -> str:
    """Mirrors the issuer's RFC 8707 canonicalization: lowercase scheme+host,
    strip a default port, drop userinfo and fragment, empty path -> '/'.
    Non-absolute values are returned unchanged."""
    from urllib.parse import urlsplit, urlunsplit

    u = urlsplit(raw)
    if not u.scheme or not u.hostname:
        return raw
    scheme = u.scheme.lower()
    host = u.hostname.lower()
    port = u.port
    if not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80) or port is None):
        host = f"{host}:{port}"
    path = u.path if u.path else "/"
    return urlunsplit((scheme, host, path, u.query, ""))


_WEEKDAY_OFFSET = 1  # Python weekday(): Mon=0..Sun=6 -> Go/Legant: Sun=0..Sat=6


def _time_window_allows(tw: dict, at: datetime) -> bool:
    tz_name = tw.get("tz") or "UTC"
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        return False  # unknown timezone fails closed
    local = at.astimezone(tz)
    weekday = (local.weekday() + _WEEKDAY_OFFSET) % 7  # Sun=0 .. Sat=6
    weekdays = tw.get("weekdays")
    if weekdays and weekday not in weekdays:
        return False
    minutes = local.hour * 60 + local.minute
    return tw.get("start_min", 0) <= minutes <= tw.get("end_min", 0)


def parse_jwks(doc: dict) -> dict:
    """Parses a JWKS document into a kid -> RSA public key map (RSA keys only)."""
    out = {}
    for k in doc.get("keys", []):
        if k.get("kty") != "RSA" or not k.get("kid"):
            continue
        n = int.from_bytes(_b64url(k["n"]), "big")
        if n.bit_length() < 2048:
            raise ValueError(f"jwk {k['kid']}: modulus too small (want >= 2048 bits)")
        e = int.from_bytes(_b64url(k["e"]), "big")
        out[k["kid"]] = rsa.RSAPublicNumbers(e, n).public_key()
    return out


def fetch_jwks(jwks_url: str, timeout: float = 10.0) -> dict:
    """Fetches and parses an issuer's JWKS. Pass a trusted, configured URL."""
    with urllib.request.urlopen(jwks_url, timeout=timeout) as r:  # noqa: S310 (configured URL)
        return parse_jwks(json.loads(r.read()))
