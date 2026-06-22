"""AgentGuard runs the same conformance authorize vectors through the
framework-agnostic tool wrapper, so the agent-facing adapter can't drift from the
SDK's authorization. From clients/python:

    python3 -m unittest discover -s tests
"""

import json
import unittest
from datetime import datetime
from pathlib import Path

from legant_sdk import AgentGuard, AuthorizeError, Verifier, parse_jwks

_VECTORS = json.loads((Path(__file__).resolve().parents[2] / "conformance" / "vectors.json").read_text())
_KEYS = parse_jwks(_VECTORS["jwks"])


def _guard(token: str) -> AgentGuard:
    return AgentGuard(Verifier(_VECTORS["issuer"], _VECTORS["audience"], _KEYS), token)


class TestAgentGuard(unittest.TestCase):
    def test_authorize_vectors(self):
        for c in _VECTORS["authorize"]:
            with self.subTest(c["name"]):
                g = _guard(c["token"])
                a = c["action"]
                at = datetime.fromisoformat(a["at"].replace("Z", "+00:00")) if a.get("at") else None
                ok = g.allowed(
                    a["scope"],
                    amount=a.get("amount", 0),
                    category=a.get("category", ""),
                    tool=a.get("tool", ""),
                    resource=a.get("resource", ""),
                    at=at,
                )
                self.assertEqual(ok, c["allow"])

    def test_tool_decorator_enforces(self):
        # Find a vector that allows expenses:submit and one that denies on amount.
        allow = next(c for c in _VECTORS["authorize"] if c["allow"] and c["action"]["scope"] == "expenses:submit")
        deny = next(c for c in _VECTORS["authorize"] if not c["allow"] and "amount" in c["action"])
        calls = []

        def make_tool(guard):
            @guard.tool("expenses:submit", amount_arg="amount", category_arg="category")
            def submit_expense(amount=0.0, category=""):
                calls.append((amount, category))
                return "submitted"

            return submit_expense

        # Allowed call runs the underlying function.
        t = make_tool(_guard(allow["token"]))
        a = allow["action"]
        self.assertEqual(t(amount=a.get("amount", 0), category=a.get("category", "")), "submitted")
        self.assertEqual(len(calls), 1)

        # Denied call raises BEFORE the function body runs (no new entry in calls).
        t2 = make_tool(_guard(deny["token"]))
        d = deny["action"]
        with self.assertRaises(AuthorizeError):
            t2(amount=d.get("amount", 0), category=d.get("category", ""))
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
