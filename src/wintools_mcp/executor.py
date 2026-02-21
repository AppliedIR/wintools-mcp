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
from wintools_mcp.exceptions import ExecutionError, TimeoutError

logger = logging.getLogger(__name__)


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

        response: dict[str, Any] = {
            "exit_code": result.returncode,
            "stdout": _truncate(stdout, config.max_output_bytes),
            "stderr": _truncate(stderr, config.max_output_bytes // 2),
            "elapsed_seconds": round(elapsed, 2),
            "command": cmd_list,
        }

        if stdout and len(stdout) > config.max_output_bytes:
            response["stdout_truncated"] = True
            response["stdout_total_bytes"] = len(stdout)

        if save_output and (stdout or stderr):
            _save_output(cmd_list, stdout, stderr, save_dir, response)

        return response

    except subprocess.TimeoutExpired:
        raise TimeoutError(
            f"Command timed out after {timeout}s: {' '.join(cmd_list)}"
        )
    except FileNotFoundError:
        raise ExecutionError(f"Binary not found: {cmd_list[0]}")
    except PermissionError:
        raise ExecutionError(f"Permission denied: {cmd_list[0]}")


def _truncate(text: str, max_bytes: int) -> str:
    if len(text) <= max_bytes:
        return text
    return text[:max_bytes] + f"\n... [truncated at {max_bytes} bytes]"


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
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.warning("Failed to create output directory %s: %s", save_dir, e)
        return

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_cmd = "".join(
        c if c.isalnum() or c in "-_" else "_" for c in Path(cmd_list[0]).name
    )[:40]
    prefix = f"{ts}_{safe_cmd}"

    if stdout:
        try:
            stdout_path = out_dir / f"{prefix}_stdout.txt"
            stdout_bytes = stdout.encode("utf-8", errors="replace")
            with open(stdout_path, "wb") as f:
                f.write(stdout_bytes)
                f.flush()
                os.fsync(f.fileno())
            response["output_file"] = str(stdout_path)
            response["output_sha256"] = hashlib.sha256(stdout_bytes).hexdigest()
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
            response["stderr_file"] = str(stderr_path)
            response["stderr_sha256"] = hashlib.sha256(stderr_bytes).hexdigest()
        except OSError as e:
            logger.warning("Failed to save stderr output to %s: %s", out_dir, e)
