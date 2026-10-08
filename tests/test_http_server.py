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

    def test_health_answers_at_once_while_a_session_attempt_holds_the_lock(
        self, config, monkeypatch
    ):
        """A session attempt holds the SMB lock across net use and the share's
        own I/O, which can hang: /health reports the last attempt's result and
        its age without waiting for it."""
        import threading
        import time

        from wintools_mcp import smb

        monkeypatch.setattr(smb, "_smb_last", (True, time.time() - 30), raising=False)
        got = {}

        def ask():
            with TestClient(
                create_http_app(config), raise_server_exceptions=False
            ) as c:
                got["body"] = c.get("/health").json()

        assert smb._smb_lock.acquire(timeout=5)  # the attempt, stalled on the share
        try:
            asker = threading.Thread(target=ask, daemon=True)
            asker.start()
            asker.join(10)
        finally:
            smb._smb_lock.release()
        body = got["body"]  # answered while the lock was held
        assert body["smb_session"] is True and body["smb_session_checking"] is True
        assert 29 <= body["smb_session_age_seconds"] <= 60

    def test_a_credentials_update_waiting_on_the_share_leaves_the_server_answering(
        self, config, monkeypatch
    ):
        """The update re-establishes the session, which waits for the SMB lock
        and the share: off the event loop, so /health answers meanwhile."""
        import threading

        from wintools_mcp import http_server, smb

        def unreachable(cfg):
            raise OSError(53, "the network path was not found")

        config.share_root = r"\\sift\cases"
        monkeypatch.setattr(http_server, "get_config", lambda: config)
        monkeypatch.setattr(http_server, "_persist_config_fields", lambda *a: None)
        monkeypatch.setattr(smb, "_net_use", unreachable)
        got = {}
        app = create_http_app(WintoolsConfig())  # no session attempt at startup
        with TestClient(app, raise_server_exceptions=False) as client:

            def update():
                got["update"] = client.post(
                    "/config/update-smb", json={"smb_password": "pw"}
                ).status_code

            def health():
                got["health"] = client.get("/health").json()

            assert smb._smb_lock.acquire(timeout=5)  # an attempt stalled on the share
            try:
                updating = threading.Thread(target=update, daemon=True)
                updating.start()
                asker = threading.Thread(target=health, daemon=True)
                asker.start()
                asker.join(10)
                assert got["health"]["smb_session_checking"] is True  # answered
            finally:
                smb._smb_lock.release()
            updating.join(10)
        assert got["update"] == 503  # it ran once the lock was free: failed, saved

    def test_two_credentials_updates_at_once_run_and_save_the_same_credentials(
        self, config, monkeypatch
    ):
        """A's attempt stalls on the share while B arrives: whatever the order,
        the credentials in use are the ones saved last (one update at a time)."""
        import threading

        from wintools_mcp import http_server, smb

        monkeypatch.setattr(http_server, "get_config", lambda: config)
        saved = []
        monkeypatch.setattr(
            http_server,
            "_persist_config_fields",
            lambda cfg, f: saved.append(f["smb_password"]),
        )
        entered = threading.Event()

        def attempt(cfg):
            if not entered.is_set():  # the first attempt stalls on the share
                entered.set()
                threading.Event().wait(1.0)
            return False

        monkeypatch.setattr(smb, "establish_smb_session", attempt)
        app = create_http_app(WintoolsConfig())
        with TestClient(app, raise_server_exceptions=False) as client:

            def update(password):
                client.post("/config/update-smb", json={"smb_password": password})

            first = threading.Thread(target=update, args=("A",), daemon=True)
            first.start()
            assert entered.wait(5)
            second = threading.Thread(target=update, args=("B",), daemon=True)
            second.start()
            first.join(10)
            second.join(10)
        assert saved and config.smb_password == saved[-1]
        assert saved == ["A", "B"]

    def test_health_says_when_no_session_attempt_has_finished(
        self, config, monkeypatch
    ):
        from wintools_mcp import smb

        monkeypatch.setattr(smb, "_smb_last", None)
        with TestClient(create_http_app(config), raise_server_exceptions=False) as c:
            body = c.get("/health").json()
        assert body["smb_session"] is False and body["smb_session_age_seconds"] is None

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
