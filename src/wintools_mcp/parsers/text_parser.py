"""Plain text output parser with truncation."""


def parse_text(stdout: str, *, max_lines: int = 500) -> dict:
    lines = stdout.split("\n")
    truncated = len(lines) > max_lines
    return {
        "lines": lines[:max_lines],
        "total_lines": len(lines),
        "truncated": truncated,
    }


def extract_lines(stdout: str, *, start: int = 0, count: int = 50) -> list[str]:
    lines = stdout.split("\n")
    return lines[start : start + count]
