"""HTTP server for wintools-mcp with Streamable HTTP MCP + auth + health."""

from __future__ import annotations

import contextlib
import hmac
import json
import logging
import os
import re
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from wintools_mcp.config import WintoolsConfig, get_config
from wintools_mcp.server import create_server

logger = logging.getLogger(__name__)

# Maximum length for bearer tokens (DoS protection)
_MAX_TOKEN_LENGTH = 1024

# Allowed characters in case_id (path traversal prevention)
_CASE_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


# ---------------------------------------------------------------------------
# ASGI-level auth wrapper (same pattern as sift-gateway)
# ---------------------------------------------------------------------------


class MCPAuthASGIApp:
    """ASGI wrapper: auth check then delegate to MCP session manager."""

    def __init__(self, mcp_asgi_app: Any, api_keys: dict[str, dict] | None = None):
        self.mcp_asgi_app = mcp_asgi_app
        self.api_keys = api_keys or {}

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        scope.setdefault("state", {})

        if not self.api_keys:
            scope["state"]["analyst"] = "anonymous"
            scope["state"]["role"] = "examiner"
            await self.mcp_asgi_app(scope, receive, send)
            return

        token = _extract_bearer_token(scope)

        if token is None:
            resp = JSONResponse(
                {"error": "Missing or invalid Authorization header"},
                status_code=401,
            )
            await resp(scope, receive, send)
            return

        # Length check: reject excessively long tokens before timing-safe comparison
        if len(token) > _MAX_TOKEN_LENGTH:
            logger.warning("Rejected oversized bearer token (%d bytes)", len(token))
            resp = JSONResponse(
                {"error": "Invalid API key"},
                status_code=403,
            )
            await resp(scope, receive, send)
            return

        # Timing-safe key lookup: iterate ALL keys to prevent timing leaks
        matched_key = None
        for candidate in self.api_keys:
            if hmac.compare_digest(token, candidate) and matched_key is None:
                matched_key = candidate

        if matched_key is None:
            resp = JSONResponse({"error": "Invalid API key"}, status_code=403)
            await resp(scope, receive, send)
            return

        key_info = self.api_keys[matched_key]
        scope["state"]["analyst"] = key_info.get(
            "examiner", key_info.get("analyst", "unknown")
        )
        scope["state"]["role"] = key_info.get("role", "examiner")
        await self.mcp_asgi_app(scope, receive, send)


def _extract_bearer_token(scope: dict) -> str | None:
    headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
    for name, value in headers:
        if name.lower() == b"authorization":
            decoded = value.decode("latin-1")
            if decoded.lower().startswith("bearer "):
                return decoded[7:].strip()
    return None


# ---------------------------------------------------------------------------
# SMB session establishment
# ---------------------------------------------------------------------------


def _establish_smb_session(config: WintoolsConfig) -> None:
    """Connect to the SIFT Samba share using stored credentials."""
    import subprocess

    if not config.smb_user or not config.smb_password:
        logger.warning("SMB credentials not configured, skipping share mount")
        return
    result = subprocess.run(
        [
            "net",
            "use",
            config.share_root,
            f"/user:{config.smb_user}",
            config.smb_password,
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        logger.warning("SMB session failed: %s", result.stderr.strip())
    else:
        logger.info("SMB session established: %s", config.share_root)


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "wintools-mcp"})


# ---------------------------------------------------------------------------
# Case activation endpoint
# ---------------------------------------------------------------------------


async def activate_case(request: Request) -> JSONResponse:
    """Activate a case — update config singleton and env vars."""
    token = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    cfg = get_config()
    if cfg.api_keys:
        if not token:
            return JSONResponse(
                {"error": "Missing or invalid Authorization header"}, status_code=401
            )
        if len(token) > _MAX_TOKEN_LENGTH:
            return JSONResponse({"error": "Invalid API key"}, status_code=403)
        matched = False
        for candidate in cfg.api_keys:
            if hmac.compare_digest(token, candidate):
                matched = True
        if not matched:
            return JSONResponse({"error": "Invalid API key"}, status_code=403)

    try:
        body = json.loads(await request.body())
    except (json.JSONDecodeError, ValueError):
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    if not isinstance(body, dict):
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    case_id = body.get("case_id", "")

    if not isinstance(case_id, str) or not case_id or not _CASE_ID_RE.match(case_id):
        return JSONResponse({"error": "Invalid case_id"}, status_code=400)

    if not cfg.share_root:
        return JSONResponse(
            {"error": "share_root not configured. Complete wintools setup first."},
            status_code=503,
        )

    windows_case_dir = cfg.share_root  # Per-case share — UNC path IS the case dir
    cfg.case_dir = windows_case_dir
    cfg.active_case = case_id
    os.environ["AIIR_CASE_DIR"] = windows_case_dir
    os.environ["AIIR_ACTIVE_CASE"] = case_id

    return JSONResponse(
        {
            "status": "activated",
            "case_id": case_id,
            "case_dir": windows_case_dir,
        }
    )


async def deactivate_case(request: Request) -> JSONResponse:
    """Deactivate current case — clear config and env vars."""
    token = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    cfg = get_config()
    if cfg.api_keys:
        if not token:
            return JSONResponse(
                {"error": "Missing or invalid Authorization header"}, status_code=401
            )
        if len(token) > _MAX_TOKEN_LENGTH:
            return JSONResponse({"error": "Invalid API key"}, status_code=403)
        matched = False
        for candidate in cfg.api_keys:
            if hmac.compare_digest(token, candidate):
                matched = True
        if not matched:
            return JSONResponse({"error": "Invalid API key"}, status_code=403)

    cfg.case_dir = ""
    cfg.active_case = ""
    os.environ.pop("AIIR_CASE_DIR", None)
    os.environ.pop("AIIR_ACTIVE_CASE", None)
    return JSONResponse({"status": "deactivated"})


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_http_app(config: WintoolsConfig) -> Starlette:
    """Build a Starlette app with /mcp (Streamable HTTP MCP) + /health + auth."""
    # Establish SMB session if share_root is a UNC path
    if config.share_root.startswith("\\\\"):
        _establish_smb_session(config)

    server = create_server(config)

    # DNS rebinding protection: FastMCP defaults to allowing only
    # 127.0.0.1/localhost Host headers. When binding to 0.0.0.0 the service
    # is intentionally network-accessible (isolated forensic network + bearer
    # auth), so disable the check. For a specific non-localhost IP, add it.
    host = config.http_host
    port = config.http_port
    if host == "0.0.0.0":
        server.settings.transport_security.enable_dns_rebinding_protection = False
    elif host not in ("127.0.0.1", "localhost", "::1", "[::1]"):
        existing = list(server.settings.transport_security.allowed_hosts)
        existing.append(f"{host}:{port}")
        server.settings.transport_security.allowed_hosts = existing

    mcp_starlette_app = server.streamable_http_app()

    # Extract the inner ASGI handler from the FastMCP-generated Starlette app.
    # The /mcp route inside that app is the actual MCP handler.
    inner_mcp_app = _extract_mcp_route(mcp_starlette_app)

    auth_wrapped = MCPAuthASGIApp(inner_mcp_app, api_keys=config.api_keys)

    @contextlib.asynccontextmanager
    async def lifespan(app):
        # Delegate to FastMCP's session manager lifespan
        async with server.session_manager.run():
            yield

    routes = [
        Route("/health", health, methods=["GET"]),
        Route("/cases/activate", activate_case, methods=["POST"]),
        Route("/cases/deactivate", deactivate_case, methods=["POST"]),
        Route("/mcp", endpoint=auth_wrapped),
    ]

    return Starlette(routes=routes, lifespan=lifespan)


def _extract_mcp_route(mcp_starlette_app: Starlette) -> Any:
    """Extract the MCP ASGI endpoint from FastMCP's generated Starlette app."""
    try:
        for route in mcp_starlette_app.routes:
            path = getattr(route, "path", "")
            if path == "/mcp":
                # Route.endpoint or Mount.app
                if hasattr(route, "app"):
                    logger.info("MCP route extracted via Mount.app")
                    return route.app
                if hasattr(route, "endpoint"):
                    logger.info("MCP route extracted via Route.endpoint")
                    return route.endpoint
    except Exception as e:
        logger.warning("Error extracting MCP route: %s", e)
    # Fallback: return the whole app (works but includes its own routing)
    logger.info("MCP route extraction: using full app fallback")
    return mcp_starlette_app
