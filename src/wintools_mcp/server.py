"""MCP server for Windows forensic tool execution."""

from __future__ import annotations

import logging
import time
from typing import Any

from mcp.server.fastmcp import FastMCP

from wintools_mcp.audit import AuditWriter
from wintools_mcp.catalog import get_tool_def, validate_command
from wintools_mcp.config import WintoolsConfig, get_config
from wintools_mcp.exceptions import WintoolsError
from wintools_mcp.response import build_response

logger = logging.getLogger(__name__)


def create_server(config: WintoolsConfig | None = None) -> FastMCP:
    """Create and configure the wintools MCP server with all tools."""
    if config is None:
        config = get_config()

    server = FastMCP("wintools-mcp")
    audit = AuditWriter(mcp_name="wintools-mcp", audit_dir=config.audit_dir or None)

    # --- Discovery ---
    @server.tool()
    def scan_tools() -> dict:
        """Scan for all cataloged forensic tools. Reports availability and install guidance."""
        from wintools_mcp.inventory import scan_tools as _scan
        result = _scan(extra_paths=config.tool_paths or None)
        audit.log(tool="scan_tools", params={}, result_summary=result["summary"])
        return result

    @server.tool()
    def list_available_tools(category: str = "") -> list[dict]:
        """List forensic tools available on this Windows system."""
        from wintools_mcp.tools.discovery import list_available_tools as _list
        return _list(category=category or None)

    @server.tool()
    def list_missing_tools() -> list[dict]:
        """List tools that are not installed, with installation guidance."""
        from wintools_mcp.tools.discovery import list_missing_tools as _list
        return _list()

    @server.tool()
    def check_tools(tool_names: list[str] | None = None) -> dict:
        """Check which tools are installed and available."""
        from wintools_mcp.tools.discovery import check_tools as _check
        return _check(tool_names=tool_names)

    @server.tool()
    def get_tool_help(tool_name: str) -> dict:
        """Get usage information, flags, and caveats for a specific tool."""
        from wintools_mcp.tools.discovery import get_tool_help as _help
        result = _help(tool_name)
        audit.log(
            tool="get_tool_help",
            params={"tool_name": tool_name},
            result_summary=result,
        )
        return result

    @server.tool()
    def suggest_tools(artifact_type: str, question: str = "") -> dict:
        """Suggest tools for analyzing a specific artifact type."""
        from wintools_mcp.tools.discovery import suggest_tools as _suggest
        result = _suggest(artifact_type, question)
        audit.log(
            tool="suggest_tools",
            params={"artifact_type": artifact_type},
            result_summary=result,
        )
        return result

    # --- Generic Execution ---
    @server.tool()
    def run_command(
        command: list[str],
        purpose: str,
        timeout: int = 0,
        save_output: bool = False,
    ) -> dict:
        """Execute a catalog-approved forensic tool. Rejects unknown and denylisted binaries."""
        from wintools_mcp.tools.generic import run_command as _run
        from pathlib import Path

        start = time.monotonic()
        evidence_id = audit._next_evidence_id()

        try:
            exec_result = _run(
                command, purpose=purpose,
                timeout=timeout or None,
                save_output=save_output,
            )
            elapsed = time.monotonic() - start

            binary = Path(command[0]).name
            td = get_tool_def(binary)
            fk_name = td.knowledge_name if td else binary

            response = build_response(
                tool_name="run_command",
                success=exec_result["exit_code"] == 0,
                data=exec_result,
                evidence_id=evidence_id,
                output_format="text",
                elapsed_seconds=elapsed,
                exit_code=exec_result["exit_code"],
                command=command,
                fk_tool_name=fk_name,
                extractions=exec_result.get("extractions"),
            )
            audit.log(
                tool="run_command",
                params={"command": command, "purpose": purpose},
                result_summary={"exit_code": exec_result["exit_code"]},
                evidence_id=evidence_id,
                elapsed_ms=elapsed * 1000,
            )
            return response

        except (WintoolsError, ValueError) as e:
            elapsed = time.monotonic() - start
            response = build_response(
                tool_name="run_command",
                success=False,
                data=None,
                evidence_id=evidence_id,
                error=str(e),
            )
            audit.log(
                tool="run_command",
                params={"command": command, "purpose": purpose},
                result_summary={"error": str(e)},
                evidence_id=evidence_id,
                elapsed_ms=elapsed * 1000,
            )
            return response
        except Exception as e:
            elapsed = time.monotonic() - start
            logger.error("Unexpected error in run_command(%s): %s", command, e, exc_info=True)
            response = build_response(
                tool_name="run_command",
                success=False,
                data=None,
                evidence_id=evidence_id,
                error=f"Unexpected error: {e}",
            )
            audit.log(
                tool="run_command",
                params={"command": command, "purpose": purpose},
                result_summary={"error": f"Unexpected: {e}"},
                evidence_id=evidence_id,
                elapsed_ms=elapsed * 1000,
            )
            return response

    # Per-tool wrappers removed in FU-3 consolidation.
    # All tool execution goes through run_command() which validates
    # against the catalog and sanitizes arguments.

    return server
