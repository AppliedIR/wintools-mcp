"""Security utilities — argument sanitization, binary validation, path validation."""

from __future__ import annotations

import os
from pathlib import Path

from wintools_mcp.catalog import is_in_catalog

# Flags that could be abused for code execution.
# NOTE: -e is NOT here — it means "execute" for PowerShell but "scan
# executables only" for sigcheck. Per-tool blocking handles it below.
_DANGEROUS_FLAGS = {
    "--exec",
    "--command",
    "-enc",
    "-encodedcommand",
    "--script",
    "--invoke",
}

_DANGEROUS_PATTERNS = [";", "&&", "||", "`", "$(", "${", "@"]

# Per-tool blocked flags: flags that are dangerous for specific tools.
# Keys must match binary_name as returned by Path(command[0]).name.
_TOOL_BLOCKED_FLAGS: dict[str, set[str]] = {
    "powershell.exe": {"-command", "-c", "-e", "-encodedcommand", "-enc"},
}

# Protect Valhuntir config directory (tokens, credentials) from being read as
# input to forensic tools. System directories are NOT blocked — the catalog
# allowlist controls what binaries can run, making input path blocking
# redundant for system dirs and harmful for forensic use cases like
# sigcheck C:\Windows\System32\svchost.exe.
_BLOCKED_DIRECTORIES = (os.path.join(os.path.expanduser("~"), ".vhir"),)


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
