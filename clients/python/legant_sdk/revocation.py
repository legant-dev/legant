"""Tier B offline revocation: a pull-based view of revoked tokens.

The resource server fetches a signed feed from the issuer on a timer and checks
token ids against an in-memory set, with no per-request callback. A stale or
missing feed can only ever MISS a revocation, never invent one, and a regressing
version is rejected as a rollback.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from typing import Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from .verifier import _b64url


class RevocationFeed:
    def __init__(self, url: Optional[str], issuer: str, keys: dict) -> None:
        self._url = url
        self._issuer = issuer
        self._keys = keys
        self._revoked: set[str] = set()
        self._version = 0
        self._fetched_at = 0.0

    def apply_feed(self, jws: str) -> None:
        """Verifies (RS256 under the issuer's kid, issuer + expiry), enforces a
        monotonic version, then atomically swaps the in-memory set."""
        h, p, s = jws.split(".")
        header = json.loads(_b64url(h))
        if header.get("alg") != "RS256":
            raise ValueError(f"unexpected alg {header.get('alg')}")
        key = self._keys.get(header.get("kid"))
        if key is None:
            raise ValueError(f'unknown feed signing key "{header.get("kid")}"')
        try:
            key.verify(_b64url(s), f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            raise ValueError("feed signature verification failed")
        c = json.loads(_b64url(p))
        if c.get("iss") != self._issuer:
            raise ValueError("feed issuer mismatch")
        exp = c.get("exp")
        if exp is None or time.time() >= exp:
            raise ValueError("feed is expired or missing exp")
        ver = int(c.get("ver", 0))
        if ver < self._version:
            raise ValueError(
                f"revocation feed version regressed ({ver} < {self._version}) — possible rollback, keeping current"
            )
        self._revoked = set(c.get("jtis") or [])
        self._version = ver
        self._fetched_at = time.time()

    def refresh(self, timeout: float = 10.0) -> None:
        if not self._url:
            raise ValueError("revocation feed has no URL")
        with urllib.request.urlopen(self._url, timeout=timeout) as r:  # noqa: S310 (configured URL)
            self.apply_feed(r.read().decode())

    def start_polling(self, interval_s: float, on_error: Optional[Callable[[Exception], None]] = None) -> Callable[[], None]:
        """Refreshes on an interval in a daemon thread until the returned stop
        function is called. Refresh errors are non-fatal."""
        stop = threading.Event()

        def loop() -> None:
            while not stop.wait(interval_s):
                try:
                    self.refresh()
                except Exception as e:  # noqa: BLE001 - non-fatal
                    if on_error:
                        on_error(e)

        threading.Thread(target=loop, daemon=True).start()
        return stop.set

    def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked

    def staleness(self) -> float:
        """Milliseconds since the feed was last successfully applied."""
        return (time.time() - self._fetched_at) * 1000.0


def fetch_revocation_feed(feed_url: str, issuer: str, keys: dict) -> RevocationFeed:
    f = RevocationFeed(feed_url, issuer, keys)
    f.refresh()
    return f


def parse_revocation_feed(feed_jwt: str | bytes, issuer: str, keys: dict) -> RevocationFeed:
    """Verify a signed revocation feed read from a string or bytes (for example a
    local feed.jwt file written by ``legant apply`` / ``legant revoke``), with no
    HTTP. The offline counterpart of ``fetch_revocation_feed``: same signature and
    version checks, no network. To pick up later revocations, parse the file again.
    """
    f = RevocationFeed(None, issuer, keys)
    f.apply_feed(feed_jwt.decode() if isinstance(feed_jwt, bytes) else feed_jwt)
    return f
