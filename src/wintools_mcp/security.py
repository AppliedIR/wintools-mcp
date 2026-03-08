"""Security utilities — argument sanitization, binary validation, path validation."""

from __future__ import annotations

from pathlib import Path

from wintools_mcp.catalog import is_in_catalog

# Flags that could be abused for code execution
_DANGEROUS_FLAGS = {
    "-e",
    "--exec",
    "--command",
    "-enc",
    "-encodedcommand",
    "--script",
    "--invoke",
}

# Output flags are NOT dangerous — they control output format/path.
# sift-mcp validates the output path; wintools-mcp runs shell=False so
# these cannot be chained into exfiltration.  Blocking them broke every
# Zimmerman tool (--csv), Hayabusa (--csv/--json/-o), and winpmem (-o).
_OUTPUT_FLAGS = {
    "-o",
    "--output",
    "-O",
    "--output-file",
    "/out",
    "--csv",
    "--json",
}

_DANGEROUS_PATTERNS = [";", "&&", "||", "`", "$(", "${", "@"]

# Per-tool blocked flags: flags that are dangerous for specific tools
_TOOL_BLOCKED_FLAGS: dict[str, set[str]] = {
    "powershell": {"-command", "-c", "-encodedcommand", "-enc"},
}

# Windows system directories that should never be used as input paths
_BLOCKED_DIRECTORIES = (
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\security",
    r"C:\Windows\servicing",
)


def sanitize_extra_args(extra_args: list[str], tool_name: str = "") -> list[str]:
    """Validate extra_args to block dangerous flags and shell metacharacters.

    Checks each argument against a global dangerous flag list, per-tool blocked
    flags, and shell metacharacter patterns. Raises ValueError if any dangerous
    input is detected.
    """
    if not extra_args:
        return []

    tool_blocked = _TOOL_BLOCKED_FLAGS.get(tool_name, set())

    sanitized = []
    for arg in extra_args:
        if not isinstance(arg, str):
            raise ValueError(
                f"Non-string argument {arg!r} in extra_args for {tool_name}"
            )
        # Split on both = and : to catch Windows-style flags (/out:path)
        flag = arg.lower().split("=")[0].split(":")[0]
        if flag in tool_blocked:
            raise ValueError(f"Blocked dangerous flag '{arg}' for {tool_name}")
        if flag in _DANGEROUS_FLAGS:
            raise ValueError(
                f"Blocked dangerous flag '{arg}' in extra_args for {tool_name}"
            )
        for pattern in _DANGEROUS_PATTERNS:
            if pattern in arg:
                raise ValueError(
                    f"Blocked shell metacharacter in extra_args for {tool_name}"
                )
        sanitized.append(arg)
    return sanitized


def validate_input_path(path: str) -> str:
    """Validate that an input file path is not in a blocked Windows system directory.

    Resolves the path, normalizes separators and case, then checks against a
    blocklist of sensitive Windows system directories. Raises ValueError if the
    resolved path falls within a blocked directory. Returns the resolved path
    string if valid.
    """
    resolved = str(Path(path).resolve())
    # Normalize: lowercase + canonical backslash separator (Windows convention)
    norm = resolved.replace("/", "\\").lower()
    for blocked in _BLOCKED_DIRECTORIES:
        blocked_lower = blocked.replace("/", "\\").lower()
        if norm == blocked_lower or norm.startswith(blocked_lower + "\\"):
            raise ValueError(
                f"Access denied: path '{path}' resolves to '{resolved}' "
                f"which is inside blocked system directory '{blocked}'"
            )
    return resolved


def verify_catalog(binary_name: str) -> None:
    """Verify a binary is in the approved catalog. Raises ValueError if not."""
    name = Path(binary_name).name
    if not is_in_catalog(name):
        raise ValueError(f"Binary '{name}' is not in the approved catalog")
