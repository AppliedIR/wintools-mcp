"""Timeline tools: Hayabusa, mactime."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from wintools_mcp.audit import AuditWriter
from wintools_mcp.catalog import get_tool_def
from wintools_mcp.environment import find_binary
from wintools_mcp.exceptions import ToolNotFoundError
from wintools_mcp.executor import execute
from wintools_mcp.parsers.json_parser import parse_json, parse_jsonl
from wintools_mcp.parsers.text_parser import parse_text
from wintools_mcp.response import build_response
from wintools_mcp.security import sanitize_extra_args

logger = logging.getLogger(__name__)


def register_timeline_tools(server: FastMCP, audit: AuditWriter) -> None:
    """Register timeline tool wrappers."""

    @server.tool()
    def run_hayabusa(
        evtx_dir: str,
        min_level: str = "medium",
        output_file: str = "",
        extra_args: list[str] = [],
    ) -> dict:
        """Run Hayabusa for Sigma-based Windows event log analysis.

        Args:
            evtx_dir: Directory containing EVTX files or a single EVTX file
            min_level: Minimum alert level (informational, low, medium, high, critical)
            output_file: Optional output file path (JSONL format)
            extra_args: Additional Hayabusa arguments
        """
        td = get_tool_def("hayabusa")
        if not td:
            raise ValueError("hayabusa not in catalog")

        binary_path = find_binary(td.binary)
        if not binary_path:
            raise ToolNotFoundError(
                f"Hayabusa is not installed. "
                f"Download from https://github.com/Yamato-Security/hayabusa/releases"
            )

        evidence_id = audit._next_evidence_id()
        sanitize_extra_args(extra_args, tool_name="hayabusa")

        cmd = [binary_path, "csv-timeline"]

        # Input can be a directory or file
        input_path = Path(evtx_dir)
        if input_path.is_dir():
            cmd.extend(["-d", str(input_path)])
        else:
            cmd.extend(["-f", str(input_path)])

        cmd.extend(["--min-level", min_level])

        if output_file:
            cmd.extend(["-o", output_file])

        cmd.extend(extra_args)

        start = time.monotonic()
        exec_result = execute(cmd, timeout=td.timeout_seconds)
        elapsed = time.monotonic() - start

        # Parse output
        stdout = exec_result.get("stdout", "")
        if output_file:
            try:
                with open(output_file, "r", encoding="utf-8") as f:
                    content = f.read()
                try:
                    data = parse_jsonl(content)
                except (ValueError, KeyError) as e:
                    logger.warning("Failed to parse Hayabusa JSONL output: %s", e)
                    data = parse_text(content)
            except FileNotFoundError:
                logger.warning("Hayabusa output file not found: %s", output_file)
                data = parse_text(stdout)
            except OSError as e:
                logger.warning("Failed to read Hayabusa output file %s: %s", output_file, e)
                data = parse_text(stdout)
        else:
            data = parse_text(stdout)

        response = build_response(
            tool_name="run_hayabusa",
            success=exec_result["exit_code"] == 0,
            data=data,
            evidence_id=evidence_id,
            output_format="parsed_jsonl" if output_file else "text",
            elapsed_seconds=elapsed,
            exit_code=exec_result["exit_code"],
            command=cmd,
            fk_tool_name=td.knowledge_name,
        )

        audit.log(
            tool="run_hayabusa",
            params={"evtx_dir": evtx_dir, "min_level": min_level},
            result_summary={"exit_code": exec_result["exit_code"]},
            evidence_id=evidence_id,
            elapsed_ms=elapsed * 1000,
        )

        return response

    @server.tool()
    def run_mactime(
        body_file: str,
        date_range: str = "",
        extra_args: list[str] = [],
    ) -> dict:
        """Generate timeline from bodyfile (TSK mactime format).

        Args:
            body_file: Path to bodyfile (from fls -m output)
            date_range: Optional date range filter (e.g., "2026-01-01..2026-02-01")
            extra_args: Additional mactime arguments
        """
        td = get_tool_def("mactime")
        if not td:
            raise ValueError("mactime not in catalog")

        binary_path = find_binary(td.binary)
        if not binary_path:
            raise ToolNotFoundError(
                "mactime is not installed. Requires Perl runtime (strawberryperl.com)"
            )

        evidence_id = audit._next_evidence_id()
        sanitize_extra_args(extra_args, tool_name="mactime")

        cmd = [binary_path, "-b", body_file]
        if date_range:
            cmd.extend(["-d", date_range])
        cmd.extend(extra_args)

        start = time.monotonic()
        exec_result = execute(cmd, timeout=td.timeout_seconds)
        elapsed = time.monotonic() - start

        data = parse_text(exec_result.get("stdout", ""))

        response = build_response(
            tool_name="run_mactime",
            success=exec_result["exit_code"] == 0,
            data=data,
            evidence_id=evidence_id,
            output_format="text",
            elapsed_seconds=elapsed,
            exit_code=exec_result["exit_code"],
            command=cmd,
            fk_tool_name=td.knowledge_name,
        )

        audit.log(
            tool="run_mactime",
            params={"body_file": body_file, "date_range": date_range},
            result_summary={"exit_code": exec_result["exit_code"]},
            evidence_id=evidence_id,
            elapsed_ms=elapsed * 1000,
        )

        return response
