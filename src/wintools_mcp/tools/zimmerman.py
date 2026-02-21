"""Zimmerman CLI tool wrappers — 14 tools for Windows artifact parsing."""

from __future__ import annotations

import csv
import logging
import tempfile
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from wintools_mcp.audit import AuditWriter
from wintools_mcp.catalog import get_tool_def
from wintools_mcp.environment import find_binary
from wintools_mcp.exceptions import ToolNotFoundError
from wintools_mcp.executor import execute
from wintools_mcp.output import get_output_dir, build_manifest
from wintools_mcp.parsers.csv_parser import parse_csv_file
from wintools_mcp.response import build_response
from wintools_mcp.security import sanitize_extra_args

logger = logging.getLogger(__name__)


def _run_zimmerman_tool(
    tool_name: str,
    input_file: str,
    audit: AuditWriter,
    *,
    extra_flags: list[str] | None = None,
    output_dir: str | None = None,
    max_rows: int = 1000,
    working_dir: str = "",
) -> dict:
    """Shared execution pattern for all Zimmerman tools."""
    td = get_tool_def(tool_name)
    if not td:
        raise ValueError(f"Tool '{tool_name}' not in catalog")

    binary_path = find_binary(td.binary)
    if not binary_path:
        guidance = []
        for im in td.install_methods:
            if im.command:
                guidance.append({"method": im.method, "command": im.command})
            elif im.url:
                guidance.append({"method": im.method, "url": im.url})
        raise ToolNotFoundError(
            f"{td.name} ({td.binary}) is not installed. "
            f"Install guidance: {guidance}"
        )

    evidence_id = audit._next_evidence_id()

    # Sanitize extra flags before building command
    if extra_flags:
        extra_flags = sanitize_extra_args(extra_flags, tool_name)

    # Determine output directory
    _temp_cleanup = None
    if output_dir:
        csv_dir = output_dir
    elif working_dir:
        csv_dir = str(get_output_dir(working_dir, evidence_id))
    else:
        _temp_cleanup = tempfile.TemporaryDirectory(prefix=f"wintools_{tool_name.lower()}_")
        csv_dir = _temp_cleanup.name

    try:
        cmd = [binary_path, td.input_flag, input_file, "--csv", csv_dir]
        if extra_flags:
            cmd.extend(extra_flags)

        start = time.monotonic()
        exec_result = execute(cmd, timeout=td.timeout_seconds)
        elapsed = time.monotonic() - start

        # Parse all CSV files produced
        parsed_data: dict[str, Any] = {}
        try:
            csv_files = sorted(Path(csv_dir).glob("*.csv"))
        except OSError as e:
            logger.warning("Failed to list CSV files in %s: %s", csv_dir, e)
            csv_files = []
        for csv_file in csv_files:
            try:
                parsed_data[csv_file.stem] = parse_csv_file(str(csv_file), max_rows=max_rows)
            except FileNotFoundError:
                logger.warning("CSV file disappeared before parsing: %s", csv_file)
            except (csv.Error, UnicodeDecodeError) as e:
                logger.warning("Failed to parse CSV file %s: %s", csv_file.name, e)
                parsed_data[csv_file.stem] = {"error": f"Parse failed: {e}"}

        # Build output manifest
        output_files = None
        if csv_files and working_dir:
            output_files = build_manifest(Path(csv_dir))

        response = build_response(
            tool_name=f"run_{tool_name.lower()}",
            success=exec_result["exit_code"] == 0,
            data=parsed_data if parsed_data else exec_result.get("stdout", ""),
            evidence_id=evidence_id,
            output_format="parsed_csv" if parsed_data else "text",
            elapsed_seconds=elapsed,
            exit_code=exec_result["exit_code"],
            command=cmd,
            fk_tool_name=td.knowledge_name,
            output_files=output_files,
        )

        audit.log(
            tool=f"run_{tool_name.lower()}",
            params={"input_file": input_file, "output_dir": csv_dir},
            result_summary={
                "exit_code": exec_result["exit_code"],
                "csv_files": len(csv_files),
            },
            evidence_id=evidence_id,
            elapsed_ms=elapsed * 1000,
        )

        return response
    finally:
        if _temp_cleanup:
            _temp_cleanup.cleanup()


def register_zimmerman_tools(server: FastMCP, audit: AuditWriter) -> None:
    """Register all 14 Zimmerman tool wrappers."""

    @server.tool()
    def run_amcacheparser(
        input_file: str, extra_flags: list[str] = [], max_rows: int = 1000
    ) -> dict:
        """Parse Amcache.hve for program execution evidence."""
        return _run_zimmerman_tool(
            "AmcacheParser", input_file, audit,
            extra_flags=extra_flags, max_rows=max_rows,
        )

    @server.tool()
    def run_appcompatcacheparser(
        input_file: str, extra_flags: list[str] = [], max_rows: int = 1000
    ) -> dict:
        """Parse Application Compatibility Cache (ShimCache) from SYSTEM hive."""
        return _run_zimmerman_tool(
            "AppCompatCacheParser", input_file, audit,
            extra_flags=extra_flags, max_rows=max_rows,
        )

    @server.tool()
    def run_evtxecmd(
        input_file: str, extra_flags: list[str] = [], max_rows: int = 1000
    ) -> dict:
        """Parse Windows Event Log (EVTX) files."""
        return _run_zimmerman_tool(
            "EvtxECmd", input_file, audit,
            extra_flags=extra_flags, max_rows=max_rows,
        )

    @server.tool()
    def run_jlecmd(
        input_file: str, extra_flags: list[str] = [], max_rows: int = 1000
    ) -> dict:
        """Parse Jump List files for recent file access."""
        return _run_zimmerman_tool(
            "JLECmd", input_file, audit,
            extra_flags=extra_flags, max_rows=max_rows,
        )

    @server.tool()
    def run_lecmd(
        input_file: str, extra_flags: list[str] = [], max_rows: int = 1000
    ) -> dict:
        """Parse LNK (shortcut) files."""
        return _run_zimmerman_tool(
            "LECmd", input_file, audit,
            extra_flags=extra_flags, max_rows=max_rows,
        )

    @server.tool()
    def run_mftecmd(
        input_file: str, extra_flags: list[str] = [], max_rows: int = 1000
    ) -> dict:
        """Parse MFT ($MFT, $J, $SDS, $Boot) files."""
        return _run_zimmerman_tool(
            "MFTECmd", input_file, audit,
            extra_flags=extra_flags, max_rows=max_rows,
        )

    @server.tool()
    def run_pecmd(
        input_file: str, extra_flags: list[str] = [], max_rows: int = 1000
    ) -> dict:
        """Parse Prefetch files for program execution history."""
        return _run_zimmerman_tool(
            "PECmd", input_file, audit,
            extra_flags=extra_flags, max_rows=max_rows,
        )

    @server.tool()
    def run_rbcmd(
        input_file: str, extra_flags: list[str] = [], max_rows: int = 1000
    ) -> dict:
        """Parse Recycle Bin ($I) files."""
        return _run_zimmerman_tool(
            "RBCmd", input_file, audit,
            extra_flags=extra_flags, max_rows=max_rows,
        )

    @server.tool()
    def run_recmd(
        input_file: str, extra_flags: list[str] = [], max_rows: int = 1000
    ) -> dict:
        """Parse Windows Registry hive files."""
        return _run_zimmerman_tool(
            "RECmd", input_file, audit,
            extra_flags=extra_flags, max_rows=max_rows,
        )

    @server.tool()
    def run_sbecmd(
        input_file: str, extra_flags: list[str] = [], max_rows: int = 1000
    ) -> dict:
        """Parse ShellBags for folder access history."""
        return _run_zimmerman_tool(
            "SBECmd", input_file, audit,
            extra_flags=extra_flags, max_rows=max_rows,
        )

    @server.tool()
    def run_sqlecmd(
        input_file: str, extra_flags: list[str] = [], max_rows: int = 1000
    ) -> dict:
        """Parse SQLite databases (browser history, etc.)."""
        return _run_zimmerman_tool(
            "SQLECmd", input_file, audit,
            extra_flags=extra_flags, max_rows=max_rows,
        )

    @server.tool()
    def run_srumecmd(
        input_file: str, extra_flags: list[str] = [], max_rows: int = 1000
    ) -> dict:
        """Parse SRUM database for resource usage monitoring."""
        return _run_zimmerman_tool(
            "SrumECmd", input_file, audit,
            extra_flags=extra_flags, max_rows=max_rows,
        )

    @server.tool()
    def run_wxtcmd(
        input_file: str, extra_flags: list[str] = [], max_rows: int = 1000
    ) -> dict:
        """Parse Windows Timeline (ActivitiesCache.db) database."""
        return _run_zimmerman_tool(
            "WxTCmd", input_file, audit,
            extra_flags=extra_flags, max_rows=max_rows,
        )

    @server.tool()
    def run_bstrings(
        input_file: str, extra_flags: list[str] = [], max_rows: int = 1000
    ) -> dict:
        """Extract strings with regex pattern matching."""
        return _run_zimmerman_tool(
            "bstrings", input_file, audit,
            extra_flags=extra_flags, max_rows=max_rows,
        )
