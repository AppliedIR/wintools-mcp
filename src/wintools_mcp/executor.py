"""Subprocess executor — Windows-adapted, shell=False, timeout, output capture."""

from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import threading
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
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/boot",
    "/proc",
    "/sys",
    "/dev",
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


def _read_pipe(pipe, chunks: list[bytes], limit: int, total: list[int]) -> None:
    """Read from a pipe incrementally, respecting byte limit."""
    while True:
        remaining = limit - total[0]
        if remaining <= 0:
            break
        data = pipe.read(min(65536, remaining))
        if not data:
            break
        chunks.append(data)
        total[0] += len(data)


def execute(
    cmd_list: list[str],
    *,
    timeout: int | None = None,
    cwd: str | None = None,
    save_output: bool = False,
    save_dir: str | None = None,
) -> dict[str, Any]:
    """Execute a command with safety controls.

    Uses Popen with incremental pipe reading to enforce max_output_bytes
    at capture time, preventing OOM from runaway processes.

    Windows-specific behaviors:
    - Forces UTF-8 encoding (prevents cp1252 mojibake)
    - Sets CREATE_NO_WINDOW flag to suppress console popups
    - Never uses shell=True
    - Normalizes \\r\\n -> \\n in output
    """
    config = get_config()
    timeout = timeout or config.default_timeout
    max_bytes = config.max_output_bytes

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["DOTNET_CLI_UI_LANGUAGE"] = "en"

    creation_flags = 0
    if os.name == "nt":
        creation_flags = subprocess.CREATE_NO_WINDOW

    start = time.monotonic()
    truncated = False
    try:
        kwargs: dict[str, Any] = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "shell": False,
            "env": env,
        }
        if cwd:
            kwargs["cwd"] = cwd
        if creation_flags:
            kwargs["creationflags"] = creation_flags

        proc = subprocess.Popen(cmd_list, **kwargs)

        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        total = [0]  # shared mutable counter across both pipes

        # Read stderr in a thread to avoid deadlock
        stderr_thread = threading.Thread(
            target=_read_pipe,
            args=(proc.stderr, stderr_chunks, max_bytes, total),
        )
        stderr_thread.start()

        # Read stdout in main thread
        _read_pipe(proc.stdout, stdout_chunks, max_bytes, total)

        # If limit reached, kill the process
        if total[0] >= max_bytes:
            truncated = True
            proc.kill()

        stderr_thread.join(timeout=5)

        try:
            proc.wait(timeout=max(0, timeout - (time.monotonic() - start)))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
            raise

        elapsed = time.monotonic() - start

        stdout_raw = b"".join(stdout_chunks)
        stderr_raw = b"".join(stderr_chunks)
        stdout = stdout_raw.decode("utf-8", errors="replace").replace("\r\n", "\n")
        stderr = stderr_raw.decode("utf-8", errors="replace").replace("\r\n", "\n")
        stdout_byte_count = len(stdout_raw)

        response: dict[str, Any] = {
            "exit_code": proc.returncode,
            "stdout": stdout,
            "stderr": _truncate(stderr, config.max_output_bytes // 10),
            "elapsed_seconds": round(elapsed, 2),
            "command": cmd_list,
            "stdout_total_bytes": stdout_byte_count,
        }
        if truncated:
            response["truncated"] = True

        # Threshold-based save: auto-save when output exceeds response budget
        case_dir = config.case_dir
        exceeds_budget = stdout_byte_count > config.response_byte_budget

        if exceeds_budget and case_dir:
            _save_output(
                cmd_list,
                stdout,
                stderr,
                save_dir or os.path.join(case_dir, "extractions"),
                response,
            )
        elif save_output and (stdout or stderr):
            _save_output(cmd_list, stdout, stderr, save_dir, response)

        return response

    except subprocess.TimeoutExpired as exc:
        raise ExecutionTimeoutError(
            f"Command timed out after {timeout}s: {' '.join(cmd_list)}"
        ) from exc
    except FileNotFoundError as exc:
        raise ExecutionError(f"Binary not found: {cmd_list[0]}") from exc
    except PermissionError as exc:
        raise ExecutionError(f"Permission denied: {cmd_list[0]}") from exc
    except OSError as e:
        raise ExecutionError(f"OS error executing {cmd_list[0]}: {e}") from e


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
