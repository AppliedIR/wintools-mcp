"""HTTP server for wintools-mcp with Streamable HTTP MCP + auth + health."""

from __future__ import annotations

import contextlib
import hmac
import logging
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from wintools_mcp.config import WintoolsConfig
from wintools_mcp.server import create_server

logger = logging.getLogger(__name__)

# Maximum length for bearer tokens (DoS protection)
_MAX_TOKEN_LENGTH = 1024


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
# Health endpoint
# ---------------------------------------------------------------------------


async def health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "wintools-mcp"})


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_http_app(config: WintoolsConfig) -> Starlette:
    """Build a Starlette app with /mcp (Streamable HTTP MCP) + /health + auth."""
    server = create_server(config)

    # Add the configured host to allowed_hosts for DNS rebinding protection.
    # Default FastMCP only allows 127.0.0.1/localhost; if the user binds to
    # 0.0.0.0 or a specific IP, that host must be allowed too.
    host = config.http_host
    port = config.http_port
    extra_hosts = []
    if host not in ("127.0.0.1", "localhost", "::1", "[::1]"):
        extra_hosts.append(f"{host}:{port}")
    if host == "0.0.0.0":
        extra_hosts.append(f"*:{port}")
    if extra_hosts:
        existing = list(server.settings.transport_security.allowed_hosts)
        server.settings.transport_security.allowed_hosts = existing + extra_hosts

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
