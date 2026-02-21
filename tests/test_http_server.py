"""Tests for the HTTP server with Streamable HTTP MCP endpoint."""

import contextlib

import pytest
from unittest.mock import MagicMock
from starlette.testclient import TestClient

from wintools_mcp.config import WintoolsConfig
from wintools_mcp.http_server import MCPAuthASGIApp, create_http_app


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
            resp = client.post("/mcp", json=self._init_request(), headers=self._mcp_headers())
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
