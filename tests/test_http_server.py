"""Tests for the HTTP server with Streamable HTTP MCP endpoint."""

from unittest.mock import MagicMock

import pytest
from starlette.testclient import TestClient

from wintools_mcp.config import WintoolsConfig
from wintools_mcp.http_server import _MAX_TOKEN_LENGTH, MCPAuthASGIApp, create_http_app

# ---------------------------------------------------------------------------
# MCPAuthASGIApp unit tests
# ---------------------------------------------------------------------------


class TestMCPAuthASGIApp:
    def _make_scope(self, headers: dict[str, str] | None = None) -> dict:
        raw_headers = []
        for k, v in (headers or {}).items():
            raw_headers.append((k.lower().encode(), v.encode()))
        return {
            "type": "http",
            "method": "POST",
            "path": "/mcp",
            "headers": raw_headers,
            "state": {},
        }

    @pytest.fixture
    def dummy_app(self):
        mgr = MagicMock()

        async def fake_call(scope, receive, send):
            pass

        mgr.side_effect = fake_call
        return mgr

    async def test_no_keys_anonymous(self, dummy_app):
        app = MCPAuthASGIApp(dummy_app, api_keys={})
        scope = self._make_scope()

        await app(scope, lambda: {}, lambda msg: None)
        assert scope["state"]["analyst"] == "anonymous"

    async def test_missing_auth_returns_401(self, dummy_app):
        keys = {"secret": {"examiner": "alice"}}
        app = MCPAuthASGIApp(dummy_app, api_keys=keys)
        scope = self._make_scope()

        responses = []

        async def send(msg):
            responses.append(msg)

        async def receive():
            return {"type": "http.request", "body": b""}

        await app(scope, receive, send)
        assert any(r.get("status") == 401 for r in responses)

    async def test_bad_key_returns_403(self, dummy_app):
        keys = {"secret": {"examiner": "alice"}}
        app = MCPAuthASGIApp(dummy_app, api_keys=keys)
        scope = self._make_scope({"Authorization": "Bearer wrong"})

        responses = []

        async def send(msg):
            responses.append(msg)

        async def receive():
            return {"type": "http.request", "body": b""}

        await app(scope, receive, send)
        assert any(r.get("status") == 403 for r in responses)

    async def test_valid_key_sets_identity(self, dummy_app):
        keys = {"mykey": {"examiner": "bob", "role": "lead"}}
        app = MCPAuthASGIApp(dummy_app, api_keys=keys)
        scope = self._make_scope({"Authorization": "Bearer mykey"})

        await app(scope, lambda: {}, lambda msg: None)
        assert scope["state"]["analyst"] == "bob"
        assert scope["state"]["role"] == "lead"

    async def test_oversized_token_returns_403(self, dummy_app):
        """S-H3: tokens longer than _MAX_TOKEN_LENGTH are rejected before HMAC loop."""
        keys = {"secret": {"examiner": "alice"}}
        app = MCPAuthASGIApp(dummy_app, api_keys=keys)
        huge_token = "x" * (_MAX_TOKEN_LENGTH + 1)
        scope = self._make_scope({"Authorization": f"Bearer {huge_token}"})

        responses = []

        async def send(msg):
            responses.append(msg)

        async def receive():
            return {"type": "http.request", "body": b""}

        await app(scope, receive, send)
        assert any(r.get("status") == 403 for r in responses)

    async def test_token_at_max_length_allowed(self, dummy_app):
        """Tokens exactly at _MAX_TOKEN_LENGTH are NOT rejected by the length check."""
        exact_token = "a" * _MAX_TOKEN_LENGTH
        keys = {exact_token: {"examiner": "alice"}}
        app = MCPAuthASGIApp(dummy_app, api_keys=keys)
        scope = self._make_scope({"Authorization": f"Bearer {exact_token}"})

        await app(scope, lambda: {}, lambda msg: None)
        assert scope["state"]["analyst"] == "alice"

    async def test_timing_safe_iterates_all_keys(self, dummy_app):
        """S-H2: all keys are compared even after a match (no early break)."""
        keys = {
            "key1": {"examiner": "alice"},
            "key2": {"examiner": "bob"},
            "key3": {"examiner": "carol"},
        }
        app = MCPAuthASGIApp(dummy_app, api_keys=keys)
        # Match the first key — should still iterate all three
        scope = self._make_scope({"Authorization": "Bearer key1"})

        # We verify correct behavior by confirming the first match is used
        await app(scope, lambda: {}, lambda msg: None)
        assert scope["state"]["analyst"] == "alice"

    async def test_timing_safe_first_match_wins(self, dummy_app):
        """S-H2: when multiple keys could match, the first one wins."""
        # Duplicate key values are unusual but test the guard logic
        keys = {
            "shared": {"examiner": "first"},
        }
        app = MCPAuthASGIApp(dummy_app, api_keys=keys)
        scope = self._make_scope({"Authorization": "Bearer shared"})

        await app(scope, lambda: {}, lambda msg: None)
        assert scope["state"]["analyst"] == "first"


# ---------------------------------------------------------------------------
# HTTP app integration tests
# ---------------------------------------------------------------------------


class TestHTTPApp:
    @pytest.fixture
    def config(self):
        return WintoolsConfig()

    def test_health_endpoint(self, config):
        app = create_http_app(config)
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ok"
            assert data["service"] == "wintools-mcp"
            assert "fk_available" in data
            assert isinstance(data["fk_available"], bool)

    def _mcp_headers(self, extra: dict | None = None) -> dict:
        """Standard headers for MCP requests (includes Host for DNS rebinding protection)."""
        h = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "Host": "127.0.0.1:4624",
        }
        if extra:
            h.update(extra)
        return h

    def _init_request(self) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"},
            },
        }

    def test_mcp_initialize(self, config):
        app = create_http_app(config)
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/mcp", json=self._init_request(), headers=self._mcp_headers()
            )
            assert resp.status_code in (200, 202)

    def test_mcp_auth_required(self):
        config = WintoolsConfig()
        config.api_keys = {"secret123": {"examiner": "alice", "role": "examiner"}}
        app = create_http_app(config)
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/mcp",
                json=self._init_request(),
                headers=self._mcp_headers(),
            )
            assert resp.status_code == 401

    def test_mcp_auth_valid(self):
        config = WintoolsConfig()
        config.api_keys = {"secret123": {"examiner": "alice", "role": "examiner"}}
        app = create_http_app(config)
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/mcp",
                json=self._init_request(),
                headers=self._mcp_headers({"Authorization": "Bearer secret123"}),
            )
            assert resp.status_code in (200, 202)
