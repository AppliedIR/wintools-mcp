"""Generic run_command: catalog-gated execution of any approved tool."""

import logging
from pathlib import Path

from wintools_mcp.catalog import get_tool_def, validate_command
from wintools_mcp.config import get_config
from wintools_mcp.environment import find_tool
from wintools_mcp.exceptions import DenylistError, ToolNotInCatalogError
from wintools_mcp.executor import execute
from wintools_mcp.security import sanitize_extra_args, validate_input_path

logger = logging.getLogger(__name__)


def run_command(
    command: list[str],
    *,
    purpose: str = "",
    timeout: int | None = None,
    save_output: bool = False,
    save_dir: str | None = None,
    cwd: str | None = None,
) -> dict:
    """Execute a catalog-approved command with denylist enforcement."""
    if not command:
        raise ValueError("Empty command")

    # Denylist + allowlist validation
    error = validate_command(command)
    if error:
        if "blocked" in error.lower():
            raise DenylistError(error)
        raise ToolNotInCatalogError(error)

    # Resolve binary path — refuse to proceed if binary is not found
    binary_name = Path(command[0]).name
    resolved = find_tool(binary_name)
    if not resolved:
        raise ToolNotInCatalogError(
            f"Tool '{binary_name}' is in the catalog but not installed on this system. "
            f"Use list_missing_tools() for installation guidance."
        )
    command = [resolved] + command[1:]

    # Sanitize extra args
    sanitize_extra_args(command[1:], tool_name=binary_name)

    # Validate file path arguments against blocked system directories
    for arg in command[1:]:
        if arg.startswith("-"):
            continue  # Skip flags (e.g. -o, --format=csv)
        if arg.startswith("/") and "=" in arg:
            continue  # Skip Windows-style flags (e.g. /format:csv)
        # Validate anything that looks like a path: drive-letter, relative, or UNC
        if (
            (len(arg) >= 3 and arg[1] == ":" and arg[2] in ("/", "\\"))
            or arg.startswith("\\\\")
            or ".." in arg
        ):
            validate_input_path(arg)
    if cwd:
        validate_input_path(cwd)

    exec_result = execute(
        command,
        timeout=timeout,
        cwd=cwd,
        save_output=save_output,
        save_dir=save_dir,
    )

    # Parse output based on catalog format when output exceeds byte budget
    cfg = get_config()
    stdout = exec_result.get("stdout", "")
    stdout_bytes = exec_result.get("stdout_total_bytes", len(stdout.encode("utf-8")))

    td = get_tool_def(binary_name)
    output_format = td.output_format if td else "text"

    # Small output — return as-is
    if stdout_bytes <= cfg.response_byte_budget:
        exec_result["_output_format"] = output_format
        return exec_result

    # Large output — parse with byte budget
    from wintools_mcp.parsers import csv_parser, json_parser, text_parser

    if output_format == "csv":
        parsed = csv_parser.parse_csv(stdout, byte_budget=cfg.response_byte_budget)
        exec_result["_parsed"] = parsed
        exec_result["_output_format"] = "parsed_csv"
    elif output_format == "json":
        parsed = json_parser.parse_json(stdout, byte_budget=cfg.response_byte_budget)
        if parsed.get("parse_error"):
            parsed = json_parser.parse_jsonl(
                stdout, byte_budget=cfg.response_byte_budget
            )
        exec_result["_parsed"] = parsed
        exec_result["_output_format"] = "parsed_json"
    else:
        parsed = text_parser.parse_text(stdout, byte_budget=cfg.response_byte_budget)
        exec_result["_parsed"] = parsed
        exec_result["_output_format"] = "parsed_text"

    exec_result["stdout"] = None
    return exec_result
