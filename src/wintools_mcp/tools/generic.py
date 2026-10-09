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


# Flags that name where a tool writes (a folder or a file)
OUTPUT_FLAGS = ("--csv", "--json", "-o", "--output", "--tdest", "--mdest")


def _make_dir(path: str) -> str | None:
    """Make ``path`` (a folder in the case), mapping the share again once if
    Windows refuses it. Returns why it couldn't, or None."""
    import os

    try:
        os.makedirs(path, exist_ok=True)
    except OSError as e:
        if "Access is denied" not in str(e) and "WinError 5" not in str(e):
            raise
        from wintools_mcp.smb import establish_smb_session

        if not establish_smb_session(get_config()):
            return (
                "SMB session expired -- cannot write to case directory. "
                "Check health endpoint for smb_session status."
            )
        os.makedirs(path, exist_ok=True)
    return None


def _names(path: str):
    return (path if n == 1 else f"{path}-{n}" for n in range(1, 1000))


def free_folder(path: str) -> str:
    """The folder ``_new_folder`` makes for ``path`` now, before it is made."""
    import os

    return next((c for c in _names(path) if not os.path.lexists(c)), path)


def _new_folder(path: str) -> str:
    """Make ``path`` as a new, empty folder and return it. A folder already
    there (a run that stopped before its audit entry, whose id is then
    used again) is never taken over: ``<path>-2``, ``-3`` … instead."""
    import os

    for candidate in _names(path):
        try:
            os.mkdir(candidate)
            return candidate
        except FileExistsError:
            continue
    raise OSError(f"no free folder name for {path}")


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
    op_dir: str | None = None,
) -> dict:
    """Execute a catalog-approved command with denylist enforcement.

    With ``op_dir`` (a run in a case) the tool runs in that folder, made
    empty first, its injected output goes there, and so does its stdout as
    the bytes it wrote. The result names the tool's file (``tool_path``).
    """
    if not command:
        raise ValueError("Empty command")

    # Script auto-expansion -- must happen BEFORE validate_command()
    # so the expanded PowerShell invocation passes the PS exception check
    requested = command[0]
    command = _expand_script_command(command)
    script_path = command[5] if command[0] != requested else None

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
    tool_path = script_path or resolved

    # Nothing runs into a share that isn't the active case: checked here,
    # after the caller's own pre-work, right before anything is created
    from wintools_mcp.share_guard import before_write

    before_write()

    # Cache lookup (Feature 4) -- after validation + resolution. Never in a
    # case: a cached reply isn't a run, and every run is recorded
    cache_key = None
    if not no_cache and not save_output and not get_config().case_dir:
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
    if op_dir:
        validate_input_path(op_dir)
        error = _make_dir(str(Path(op_dir).parent))
        if error:
            return {"error": error}
        op_dir = _new_folder(op_dir)
        cwd = cwd or op_dir
    if cwd:
        validate_input_path(cwd)

    # Auto-inject output directory when catalog specifies output_flag
    # and user didn't provide one (e.g., --csv, --json, -o)
    _csv_output_rel = None
    td = get_tool_def(binary_name)
    if td and td.output_flag:
        user_has_output = any(
            a.lower() in (*OUTPUT_FLAGS, td.output_flag.lower()) for a in command[1:]
        )
        if not user_has_output:
            cfg = get_config()
            if cfg.case_dir:
                import os

                output_dir = op_dir or os.path.join(
                    cfg.case_dir, "extractions", td.name.lower()
                )
                if not op_dir:
                    error = _make_dir(output_dir)
                    if error:
                        return {"error": error}
                command.extend([td.output_flag, output_dir])
                logger.info("Auto-injected output: %s %s", td.output_flag, output_dir)
                from wintools_mcp.output import to_share_relative

                _csv_output_rel = to_share_relative(output_dir, cfg.share_root)

    exec_result = execute(
        command,
        timeout=timeout,
        cwd=cwd,
        save_output=save_output,
        save_dir=op_dir or save_dir,
        keep_raw=bool(op_dir),
    )
    exec_result["tool_path"] = tool_path
    if op_dir:
        exec_result["op_dir"] = op_dir

    # Attach share-relative CSV output dir (for cross-MCP consumption)
    if _csv_output_rel:
        exec_result["csv_output_dir"] = _csv_output_rel

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
