"""Subprocess executor — Windows-adapted, shell=False, timeout, output capture."""

from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wintools_mcp.config import get_config
from wintools_mcp.exceptions import ExecutionError, ExecutionTimeoutError
from wintools_mcp.output import to_share_relative

logger = logging.getLogger(__name__)

# Blocked output directories — system paths that should never be used as
# save_dir targets.  Windows paths use case-insensitive backslash comparison.
# Linux paths included for test/dev environments where wintools runs on Linux.
_BLOCKED_OUTPUT_DIRS_WIN = (
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
)
_BLOCKED_OUTPUT_DIRS_POSIX = (
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/boot", "/proc", "/sys", "/dev",
)


def _validate_output_dir(resolved_path: Path) -> None:
    """Raise ValueError if resolved_path is inside a blocked system directory."""
    path_str = str(resolved_path)
    # Windows check: case-insensitive backslash comparison.
    norm_win = path_str.replace("/", "\\").lower()
    for blocked in _BLOCKED_OUTPUT_DIRS_WIN:
        blocked_lower = blocked.replace("/", "\\").lower()
        if norm_win == blocked_lower or norm_win.startswith(blocked_lower + "\\"):
            raise ValueError(
                f"Output directory blocked: '{resolved_path}' is inside "
                f"protected system directory '{blocked}'"
            )
    # POSIX check: for Linux/test environments.
    norm_posix = path_str
    for blocked in _BLOCKED_OUTPUT_DIRS_POSIX:
        if norm_posix == blocked or norm_posix.startswith(blocked + "/"):
            raise ValueError(
                f"Output directory blocked: '{resolved_path}' is inside "
                f"protected system directory '{blocked}'"
            )


def execute(
    cmd_list: list[str],
    *,
    timeout: int | None = None,
    cwd: str | None = None,
    save_output: bool = False,
    save_dir: str | None = None,
) -> dict[str, Any]:
    """Execute a command with safety controls.

    Windows-specific behaviors:
    - Forces UTF-8 encoding (prevents cp1252 mojibake)
    - Handles long paths via \\\\?\\ prefix when needed
    - Sets CREATE_NO_WINDOW flag to suppress console popups
    - Never uses shell=True
    - Normalizes \\r\\n -> \\n in output
    """
    config = get_config()
    timeout = timeout or config.default_timeout

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["DOTNET_CLI_UI_LANGUAGE"] = "en"

    creation_flags = 0
    if os.name == "nt":
        creation_flags = subprocess.CREATE_NO_WINDOW

    start = time.monotonic()
    try:
        kwargs: dict[str, Any] = {
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "timeout": timeout,
            "shell": False,
            "env": env,
        }
        if cwd:
            kwargs["cwd"] = cwd
        if creation_flags:
            kwargs["creationflags"] = creation_flags

        result = subprocess.run(cmd_list, **kwargs)
        elapsed = time.monotonic() - start

        stdout = result.stdout.replace("\r\n", "\n") if result.stdout else ""
        stderr = result.stderr.replace("\r\n", "\n") if result.stderr else ""

        stdout_bytes = len(stdout.encode("utf-8"))

        response: dict[str, Any] = {
            "exit_code": result.returncode,
            "stdout": stdout,
            "stderr": _truncate(stderr, config.max_output_bytes // 10),
            "elapsed_seconds": round(elapsed, 2),
            "command": cmd_list,
            "stdout_total_bytes": stdout_bytes,
        }

        # Threshold-based save: auto-save when output exceeds response budget
        case_dir = config.case_dir
        exceeds_budget = stdout_bytes > config.response_byte_budget

        if exceeds_budget and case_dir:
            _save_output(
                cmd_list, stdout, stderr,
                save_dir or os.path.join(case_dir, "extractions"),
                response,
            )
        elif save_output and (stdout or stderr):
            _save_output(cmd_list, stdout, stderr, save_dir, response)

        return response

    except subprocess.TimeoutExpired:
        raise ExecutionTimeoutError(
            f"Command timed out after {timeout}s: {' '.join(cmd_list)}"
        )
    except FileNotFoundError:
        raise ExecutionError(f"Binary not found: {cmd_list[0]}")
    except PermissionError:
        raise ExecutionError(f"Permission denied: {cmd_list[0]}")


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n... [truncated at {max_chars} chars]"


def _save_output(
    cmd_list: list[str],
    stdout: str,
    stderr: str,
    save_dir: str | None,
    response: dict,
) -> None:
    if not save_dir:
        return
    try:
        out_dir = Path(save_dir).resolve()
        _validate_output_dir(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
    except ValueError:
        raise
    except OSError as e:
        logger.warning("Failed to create output directory %s: %s", save_dir, e)
        return

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_cmd = "".join(
        c if c.isalnum() or c in "-_" else "_" for c in Path(cmd_list[0]).name
    )[:40]
    prefix = f"{ts}_{safe_cmd}"

    saved_paths: list[str] = []

    if stdout:
        try:
            stdout_path = out_dir / f"{prefix}_stdout.txt"
            stdout_bytes = stdout.encode("utf-8", errors="replace")
            with open(stdout_path, "wb") as f:
                f.write(stdout_bytes)
                f.flush()
                os.fsync(f.fileno())
            response["output_file"] = str(stdout_path).replace("\\", "/")
            response["output_sha256"] = hashlib.sha256(stdout_bytes).hexdigest()
            saved_paths.append(str(stdout_path))
        except OSError as e:
            logger.warning("Failed to save stdout output to %s: %s", out_dir, e)

    if stderr:
        try:
            stderr_path = out_dir / f"{prefix}_stderr.txt"
            stderr_bytes = stderr.encode("utf-8", errors="replace")
            with open(stderr_path, "wb") as f:
                f.write(stderr_bytes)
                f.flush()
                os.fsync(f.fileno())
            response["stderr_file"] = str(stderr_path).replace("\\", "/")
            response["stderr_sha256"] = hashlib.sha256(stderr_bytes).hexdigest()
            saved_paths.append(str(stderr_path))
        except OSError as e:
            logger.warning("Failed to save stderr output to %s: %s", out_dir, e)

    # Build share-relative extraction paths for cross-MCP consumption
    if saved_paths:
        config = get_config()
        response["extractions"] = [
            to_share_relative(p, config.share_root) for p in saved_paths
        ]
