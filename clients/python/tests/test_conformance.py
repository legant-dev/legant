"""Runs the shared golden vectors (clients/conformance/vectors.json, minted by the
real Go signer) through the Python SDK. Identical assertions run against the Go
and TypeScript SDKs, so the three cannot drift. From clients/python:

    python3 -m unittest discover -s tests
"""

import json
import unittest
from datetime import datetime
from pathlib import Path

from legant_sdk import Action, RevocationFeed, RevokedError, Verifier, parse_jwks

_VECTORS = json.loads((Path(__file__).resolve().parents[2] / "conformance" / "vectors.json").read_text())
_KEYS = parse_jwks(_VECTORS["jwks"])


class TestConformance(unittest.TestCase):
    def test_verify_vectors(self):
        ver = Verifier(_VECTORS["issuer"], _VECTORS["audience"], _KEYS)
        for c in _VECTORS["verify"]:
            with self.subTest(c["name"]):
                if c["valid"]:
                    claims = ver.verify(c["token"])
                    if c.get("provenance"):
                        self.assertEqual(claims.provenance(), c["provenance"])
                else:
                    with self.assertRaises(Exception):
                        ver.verify(c["token"])

    def test_audience_vectors(self):
        for c in _VECTORS["audienceCanonicalization"]:
            with self.subTest(c["name"]):
                ver = Verifier(_VECTORS["issuer"], c["configuredAudience"], _KEYS)
                if c["valid"]:
                    ver.verify(c["token"])  # must not raise
                else:
                    with self.assertRaises(Exception):
                        ver.verify(c["token"])

    def test_authorize_vectors(self):
        ver = Verifier(_VECTORS["issuer"], _VECTORS["audience"], _KEYS)
        for c in _VECTORS["authorize"]:
            with self.subTest(c["name"]):
                claims = ver.verify(c["token"])
                a = c["action"]
                at = datetime.fromisoformat(a["at"].replace("Z", "+00:00")) if a.get("at") else None
                action = Action(
                    scope=a.get("scope", ""),
                    amount=a.get("amount", 0.0),
                    category=a.get("category", ""),
                    tool=a.get("tool", ""),
                    resource=a.get("resource", ""),
                    at=at,
                )
                allowed = True
                try:
                    claims.authorize(action)
                except Exception:
                    allowed = False
                self.assertEqual(allowed, c["allow"])

    def test_revocation_vectors(self):
        r = _VECTORS["revocation"]
        feed = RevocationFeed(None, _VECTORS["issuer"], _KEYS)
        feed.apply_feed(r["feed"])
        self.assertTrue(feed.is_revoked(r["revokedJti"]))
        self.assertFalse(feed.is_revoked(r["liveJti"]))

        ver = Verifier(_VECTORS["issuer"], _VECTORS["audience"], _KEYS, feed=feed)
        with self.assertRaises(RevokedError):
            ver.verify(r["revokedToken"])
        ver.verify(r["liveToken"])  # live token verifies

        # A rollback (lower version) is rejected; revocation persists.
        with self.assertRaises(ValueError):
            feed.apply_feed(r["feedRollback"])
        self.assertTrue(feed.is_revoked(r["revokedJti"]))

        # A newer feed dropping the jti clears the revocation.
        feed.apply_feed(r["feedNewer"])
        self.assertFalse(feed.is_revoked(r["revokedJti"]))


if __name__ == "__main__":
    unittest.main()
