"""Input sanitization for extra_args passed to tool wrappers."""

from wintools_mcp.catalog import is_in_catalog

_DANGEROUS_FLAGS = {
    "-e", "--exec", "--command", "-enc", "-encodedcommand",
    "--script", "--invoke",
}

_DANGEROUS_PATTERNS = [";", "&&", "||", "`", "$(", "${"]


def sanitize_extra_args(extra_args: list[str], tool_name: str = "") -> list[str]:
    if not extra_args:
        return []
    sanitized = []
    for arg in extra_args:
        if not isinstance(arg, str):
            raise ValueError(
                f"Non-string argument {arg!r} in extra_args for {tool_name}"
            )
        flag = arg.lower().split("=")[0]
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


def verify_catalog(binary_name: str) -> None:
    from pathlib import Path
    name = Path(binary_name).name
    if not is_in_catalog(name):
        raise ValueError(f"Binary '{name}' is not in the approved catalog")
