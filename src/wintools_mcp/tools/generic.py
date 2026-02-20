"""Generic run_command: catalog-gated execution of any approved tool."""

from pathlib import Path

from wintools_mcp.catalog import validate_command, get_tool_def
from wintools_mcp.environment import find_binary
from wintools_mcp.executor import execute
from wintools_mcp.exceptions import ToolNotInCatalogError, DenylistError
from wintools_mcp.security import sanitize_extra_args


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

    # Resolve binary path
    binary_name = Path(command[0]).name
    resolved = find_binary(binary_name)
    if resolved:
        command = [resolved] + command[1:]

    # Sanitize extra args
    sanitize_extra_args(command[1:], tool_name=binary_name)

    return execute(
        command,
        timeout=timeout,
        cwd=cwd,
        save_output=save_output,
        save_dir=save_dir,
    )
