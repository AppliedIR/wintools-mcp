"""Generic run_command: catalog-gated execution of any approved tool."""

import copy
import hashlib
import logging
import threading
import time as _time
from collections import OrderedDict
from pathlib import Path

from wintools_mcp.catalog import PS_SCRIPT_EXCEPTIONS, get_tool_def, validate_command
from wintools_mcp.config import get_config
from wintools_mcp.environment import find_tool
from wintools_mcp.exceptions import DenylistError, ToolNotInCatalogError
from wintools_mcp.executor import execute
from wintools_mcp.security import sanitize_extra_args, validate_input_path

logger = logging.getLogger(__name__)

# --- Result caching (Feature 4) ---
_CACHE_TTL = 86400  # 24 hours
_CACHE_MAX = 256
_cache_lock = threading.Lock()
_result_cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()


def _cache_key(
    command: list[str],
    input_files: list[str] | None = None,
    cwd: str | None = None,
) -> str:
    """Build cache key from command + input file hashes + cwd."""
    h = hashlib.sha256()
    h.update("|".join(command).encode())
    if cwd:
        h.update(f"cwd:{cwd}".encode())
    for path in sorted(input_files or []):
        try:
            p = Path(path)
            if p.is_file():
                st = p.stat()
                with open(p, "rb") as f:
                    h.update(f.read(65536))
                h.update(f"{st.st_size}:{st.st_mtime_ns}".encode())
        except OSError:
            h.update(path.encode())
    return h.hexdigest()


def _cache_get(key: str) -> dict | None:
    """Return cached result if still valid, else None."""
    with _cache_lock:
        entry = _result_cache.get(key)
        if entry is None:
            logger.debug("Cache miss for key %s", key[:12])
            return None
        ts, result = entry
        if _time.monotonic() - ts > _CACHE_TTL:
            del _result_cache[key]
            logger.debug("Cache expired for key %s", key[:12])
            return None
        _result_cache.move_to_end(key)  # LRU touch
        result = copy.deepcopy(result)
    result["_cached"] = True
    return result


def _cache_put(key: str, result: dict) -> None:
    """Store result in cache with LRU eviction."""
    with _cache_lock:
        _result_cache[key] = (_time.monotonic(), copy.deepcopy(result))
        while len(_result_cache) > _CACHE_MAX:
            _result_cache.popitem(last=False)  # evict oldest


def _expand_script_command(command: list[str]) -> list[str]:
    """Auto-expand script-type tools into PowerShell invocations.

    Transforms ["Get-InjectedThreadEx", ...args] into
    ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
     "-File", "<resolved_path>", ...args].
    """
    td = get_tool_def(command[0])
    if not td or td.exec_type != "script":
        return command

    # Find the .ps1 script file from install_paths
    # Use only the filename stem -- strip any path traversal from user input
    script_name = Path(command[0]).name
    script_file = f"{script_name}.ps1"
    # Check if it's a known PS exception (case-insensitive)
    if script_file.lower() not in PS_SCRIPT_EXCEPTIONS:
        return command

    script_path = None
    for search_dir in td.install_paths or []:
        search_resolved = Path(search_dir).resolve()
        candidate = (search_resolved / script_file).resolve()
        # Verify resolved path stays within the search directory
        try:
            candidate.relative_to(search_resolved)
        except ValueError:
            continue  # candidate is outside search_dir
        if candidate.exists():
            script_path = str(candidate)
            break

    if not script_path:
        searched_display = (
            ", ".join(Path(p).name for p in td.install_paths)
            if td.install_paths
            else "no install_paths"
        )
        raise ToolNotInCatalogError(
            f"Script not found: {script_file} (searched: {searched_display}). "
            f"Use list_missing_windows_tools() for install guidance."
        )

    return [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        script_path,
    ] + command[1:]


def run_command(
    command: list[str],
    *,
    purpose: str = "",
    timeout: int | None = None,
    save_output: bool = False,
    save_dir: str | None = None,
    cwd: str | None = None,
    no_cache: bool = False,
    input_files: list[str] | None = None,
) -> dict:
    """Execute a catalog-approved command with denylist enforcement."""
    if not command:
        raise ValueError("Empty command")

    # Script auto-expansion -- must happen BEFORE validate_command()
    # so the expanded PowerShell invocation passes the PS exception check
    command = _expand_script_command(command)

    # Denylist + allowlist validation (always runs, even on cache hits)
    error = validate_command(command)
    if error:
        if "blocked" in error.lower():
            raise DenylistError(error)
        raise ToolNotInCatalogError(error)

    # Resolve binary path -- refuse to proceed if binary is not found
    binary_name = Path(command[0]).name
    resolved = find_tool(binary_name)
    if not resolved:
        raise ToolNotInCatalogError(
            f"Tool '{binary_name}' is in the catalog but not installed on this system. "
            f"Use list_missing_windows_tools() for installation guidance."
        )
    command = [resolved] + command[1:]

    # Cache lookup (Feature 4) -- after validation + resolution
    cache_key = None
    if not no_cache and not save_output:
        cache_key = _cache_key(command, input_files, cwd=cwd)
        cached = _cache_get(cache_key)
        if cached is not None:
            logger.info("Cache hit for %s", command[0])
            return cached

    # Sanitize extra args
    sanitize_extra_args(command[1:], tool_name=binary_name)

    # Validate file path arguments against blocked system directories
    for arg in command[1:]:
        if arg.startswith("-"):
            continue  # Skip flags (e.g. -o, --format=csv)
        # Windows-style flags: /flag:value or /flag=value -- extract and validate path
        if arg.startswith("/"):
            for sep in ("=", ":"):
                if sep in arg:
                    value = arg.split(sep, 1)[1]
                    if value and (
                        (
                            len(value) >= 3
                            and value[1] == ":"
                            and value[2] in ("/", "\\")
                        )
                        or value.startswith("\\\\")
                    ):
                        validate_input_path(value)
                    break
            continue
        # Validate anything that looks like a path: drive-letter, relative, or UNC
        if (
            (len(arg) >= 3 and arg[1] == ":" and arg[2] in ("/", "\\"))
            or arg.startswith("\\\\")
            or ".." in arg
        ):
            validate_input_path(arg)
    if cwd:
        validate_input_path(cwd)

    # Auto-inject output directory when catalog specifies output_flag
    # and user didn't provide one (e.g., --csv, --json, -o)
    td = get_tool_def(binary_name)
    if td and td.output_flag:
        user_has_output = any(
            a.lower() in ("--csv", "--json", "-o", "--output") for a in command[1:]
        )
        if not user_has_output:
            cfg = get_config()
            if cfg.case_dir:
                import os

                output_dir = os.path.join(cfg.case_dir, "extractions", td.name.lower())
                try:
                    os.makedirs(output_dir, exist_ok=True)
                except OSError as e:
                    if "Access is denied" in str(e) or "WinError 5" in str(e):
                        from wintools_mcp.smb import establish_smb_session

                        if not establish_smb_session(cfg):
                            return {
                                "error": (
                                    "SMB session expired -- cannot write to case directory. "
                                    "Check health endpoint for smb_session status."
                                )
                            }
                        os.makedirs(output_dir, exist_ok=True)
                    else:
                        raise
                command.extend([td.output_flag, output_dir])
                logger.info("Auto-injected output: %s %s", td.output_flag, output_dir)

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

    # Small output -- return as-is
    if stdout_bytes <= cfg.response_byte_budget:
        exec_result["_output_format"] = output_format
        if cache_key and exec_result.get("exit_code", 1) == 0:
            _cache_put(cache_key, exec_result)
        return exec_result

    # Large output -- parse with byte budget
    from wintools_mcp.parsers import csv_parser, json_parser, text_parser

    if output_format == "csv":
        parsed = csv_parser.parse_csv(stdout, byte_budget=cfg.response_byte_budget)
        if parsed.get("parse_error"):
            # CSV parse failed -- fall back to text instead of losing data
            parsed = text_parser.parse_text(
                stdout, byte_budget=cfg.response_byte_budget
            )
            exec_result["_parsed"] = parsed
            exec_result["_output_format"] = "parsed_text"
        else:
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

    # Cache store (Feature 4)
    if cache_key and exec_result.get("exit_code", 1) == 0:
        _cache_put(cache_key, exec_result)

    return exec_result
