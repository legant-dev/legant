"""Exercises the resource-server middleware against the shared golden vectors.
The framework-agnostic core always runs; the FastAPI/Flask adapters run only when
the framework is installed. From clients/python:

    python3 -m unittest discover -s tests
"""

import json
import unittest
from pathlib import Path

from legant_sdk import (
    Verifier,
    VerifyError,
    authenticate,
    bearer_token,
    mcp_tool_name,
    parse_jwks,
)

_VECTORS = json.loads((Path(__file__).resolve().parents[2] / "conformance" / "vectors.json").read_text())
_KEYS = parse_jwks(_VECTORS["jwks"])
_VALID = next(c["token"] for c in _VECTORS["verify"] if c["valid"])
_ALLOW = next(c for c in _VECTORS["authorize"] if c["allow"])
_DENY = next(c for c in _VECTORS["authorize"] if not c["allow"])


def _verifier() -> Verifier:
    return Verifier(_VECTORS["issuer"], _VECTORS["audience"], _KEYS)


class TestCore(unittest.TestCase):
    def test_bearer_token(self):
        self.assertEqual(bearer_token("Bearer abc.def.ghi"), "abc.def.ghi")
        with self.assertRaises(VerifyError):
            bearer_token(None)
        with self.assertRaises(VerifyError):
            bearer_token("Basic xyz")

    def test_authenticate(self):
        claims = authenticate(_verifier(), f"Bearer {_VALID}")
        self.assertTrue(claims.subject)
        with self.assertRaises(VerifyError):
            authenticate(_verifier(), "Bearer not-a-jwt")

    def test_mcp_tool_name(self):
        self.assertEqual(
            mcp_tool_name({"method": "tools/call", "params": {"name": "kubectl_scale"}}),
            "kubectl_scale",
        )
        self.assertEqual(mcp_tool_name('{"method":"tools/call","params":{"name":"x"}}'), "x")
        with self.assertRaises(ValueError):
            mcp_tool_name({"method": "tools/list"})


class TestFlask(unittest.TestCase):
    def setUp(self):
        try:
            from flask import Flask, g, jsonify
        except ImportError:  # pragma: no cover
            self.skipTest("flask not installed")
        from legant_sdk import flask_require

        app = Flask(__name__)

        def action_from(_req):
            from legant_sdk import Action

            a = _DENY["action"]
            return Action(scope=a["scope"], amount=a.get("amount", 0))

        @app.get("/scoped")
        @flask_require(_verifier())
        def scoped():
            return jsonify(sub=g.legant.subject)

        @app.get("/denied")
        @flask_require(_verifier(), action=action_from)
        def denied():
            return jsonify(ok=True)

        self.client = app.test_client()

    def test_no_token_401(self):
        r = self.client.get("/scoped")
        self.assertEqual(r.status_code, 401)
        self.assertIn("Bearer", r.headers.get("WWW-Authenticate", ""))

    def test_valid_token_ok(self):
        r = self.client.get("/scoped", headers={"Authorization": f"Bearer {_VALID}"})
        self.assertEqual(r.status_code, 200)

    def test_denied_action_403(self):
        r = self.client.get("/denied", headers={"Authorization": f"Bearer {_DENY['token']}"})
        self.assertEqual(r.status_code, 403)


class TestFastAPI(unittest.TestCase):
    def setUp(self):
        try:
            from fastapi import Depends, FastAPI
            from fastapi.testclient import TestClient
        except ImportError:
            self.skipTest("fastapi not installed")
        from legant_sdk import Claims, fastapi_auth

        app = FastAPI()

        @app.get("/scoped")
        def scoped(claims: Claims = Depends(fastapi_auth(_verifier()))):
            return {"sub": claims.subject}

        self.client = TestClient(app)

    def test_no_token_401(self):
        self.assertEqual(self.client.get("/scoped").status_code, 401)

    def test_valid_token_ok(self):
        r = self.client.get("/scoped", headers={"Authorization": f"Bearer {_VALID}"})
        self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    unittest.main()
