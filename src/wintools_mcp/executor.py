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


def _decode_output(raw: bytes) -> str:
    """Decode process output, detecting UTF-16LE from Sysinternals tools."""
    if raw[:2] == b"\xff\xfe":
        # BOM present — utf-16 auto-detects endianness and strips BOM
        text = raw.decode("utf-16", errors="replace")
    elif _looks_like_utf16le(raw):
        # Likely UTF-16LE without BOM (common on Windows)
        try:
            text = raw.decode("utf-16-le", errors="replace")
        except ValueError:
            # Odd-length byte sequence
            text = raw.decode("utf-8", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")
    return text.replace("\r\n", "\n")


def _looks_like_utf16le(raw: bytes) -> bool:
    """Check if raw bytes look like UTF-16LE ASCII (alternating null pattern).

    UTF-16LE encoding of ASCII text has a null byte at every odd index.
    Check that >50% of odd-indexed bytes in the first 100 bytes are null.
    """
    if len(raw) < 10:
        return False
    sample = raw[:100]
    odd_bytes = sample[1::2]
    if not odd_bytes:
        return False
    null_ratio = odd_bytes.count(0) / len(odd_bytes)
    return null_ratio > 0.5


def _close_pipes(proc) -> None:
    """Close process pipes to unblock reader threads after kill."""
    for pipe in (proc.stdout, proc.stderr):
        if pipe:
            try:
                pipe.close()
            except OSError:
                pass


def _read_pipe(pipe, chunks: list[bytes], limit: int, total: list[int]) -> None:
    """Read from a pipe incrementally, respecting byte limit."""
    try:
        while True:
            remaining = limit - total[0]
            if remaining <= 0:
                break
            data = pipe.read(min(65536, remaining))
            if not data:
                break
            chunks.append(data)
            total[0] += len(data)
    except (OSError, ValueError):
        pass  # Pipe closed after proc.kill() -- expected


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

        # Read both pipes in threads to avoid deadlock and allow
        # proc.wait() in the main thread to enforce the timeout.
        stdout_thread = threading.Thread(
            target=_read_pipe,
            args=(proc.stdout, stdout_chunks, max_bytes, total),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=_read_pipe,
            args=(proc.stderr, stderr_chunks, max_bytes, total),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()

        # Poll for completion, checking byte limit periodically
        deadline = start + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                _close_pipes(proc)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                raise subprocess.TimeoutExpired(cmd_list, timeout)
            if total[0] >= max_bytes:
                truncated = True
                proc.kill()
                _close_pipes(proc)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                break
            try:
                proc.wait(timeout=min(0.1, remaining))
                break
            except subprocess.TimeoutExpired:
                continue

        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)

        # Check truncation after threads finish (process may have
        # exited before the polling loop detected the byte limit)
        if total[0] >= max_bytes:
            truncated = True

        elapsed = time.monotonic() - start

        stdout_raw = b"".join(stdout_chunks)
        stderr_raw = b"".join(stderr_chunks)
        stdout = _decode_output(stdout_raw)
        stderr = _decode_output(stderr_raw)
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
                save_dir or os.path.join(case_dir, "extractions", "wintools"),
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
        if "Access is denied" in str(e) or "WinError 5" in str(e):
            # SMB session may have expired — try re-establishing
            from wintools_mcp.smb import establish_smb_session

            cfg = get_config()
            if establish_smb_session(cfg):
                try:
                    out_dir.mkdir(parents=True, exist_ok=True)
                except OSError as retry_err:
                    logger.error("SMB retry failed for %s: %s", save_dir, retry_err)
                    response["save_error"] = (
                        f"Output lost: SMB retry failed ({retry_err})"
                    )
                    return
            else:
                logger.error(
                    "SMB session failed -- cannot write to %s. "
                    "Check credentials or re-run 'vhir setup join'.",
                    save_dir,
                )
                response["save_error"] = (
                    "Output lost: SMB session failed. "
                    "Check health endpoint for smb_session status."
                )
                return
        else:
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
