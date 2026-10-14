"""The version of the tool file that runs.

Read from the file itself: a Windows executable's VERSIONINFO (its fixed
file version), which needs no run and so never meets a EULA screen. A file
with none is asked by its catalog probe (``version_probe``: the argv and a
pattern whose first group is the version), when it has one. Kept per file:
a new size or modification time (an update in place) is read again on the
next run. A version that can't be read is "unknown", never an error.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import threading

logger = logging.getLogger(__name__)

UNKNOWN = "unknown"
PROBE_SECONDS = 15
PROBE_BYTES = 65536

_lock = threading.Lock()
_versions: dict[tuple[str, int, int], dict] = {}


def file_version(path: str) -> str | None:
    """The file's fixed version from its VERSIONINFO ("1.5.0.0"), or None
    when it has none or it can't be read (and on any system but Windows)."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        api = ctypes.WinDLL("version")
        api.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, wintypes.LPDWORD]
        api.GetFileVersionInfoSizeW.restype = wintypes.DWORD
        api.GetFileVersionInfoW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]  # fmt: skip
        api.GetFileVersionInfoW.restype = wintypes.BOOL
        api.VerQueryValueW.argtypes = [
            ctypes.c_void_p, wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT)]  # fmt: skip
        api.VerQueryValueW.restype = wintypes.BOOL

        size = api.GetFileVersionInfoSizeW(path, None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not api.GetFileVersionInfoW(path, 0, size, buf):
            return None
        ptr, length = ctypes.c_void_p(), wintypes.UINT()
        if not api.VerQueryValueW(buf, "\\", ctypes.byref(ptr), ctypes.byref(length)):
            return None
        if length.value < 16 or not ptr.value:
            return None
        # VS_FIXEDFILEINFO: signature, struct version, file version MS and LS
        sig, _struct, ms, ls = (ctypes.c_uint32 * 4).from_address(ptr.value)
        if sig != 0xFEEF04BD:
            return None
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
    except (OSError, AttributeError, ValueError) as e:
        logger.debug("VERSIONINFO of %s not read: %s", path, e)
        return None


def run_probe(argv: list[str]) -> str:
    """The probe's output (stdout, then stderr), run outside any case: it
    goes through no op folder and nothing is saved."""
    r = subprocess.run(
        argv,
        capture_output=True,
        timeout=PROBE_SECONDS,
        stdin=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return (r.stdout[:PROBE_BYTES] + b"\n" + r.stderr[:PROBE_BYTES]).decode(
        "utf-8", "replace"
    )


def _probe(path: str, probe: dict) -> dict:
    """Ask the file with the catalog's version probe. Its pattern's first
    group is the version; otherwise unknown, with the output's first line."""
    try:
        text = run_probe([path, *probe.get("argv", ["--version"])])
    except (OSError, subprocess.SubprocessError) as e:
        return {"tool_version": UNKNOWN, "version_probe_output": str(e)[:200]}
    m = re.search(probe.get("pattern", r"(\d+(?:\.\d+)+)"), text)
    if m:
        return {"tool_version": m.group(1)}
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    return {"tool_version": UNKNOWN, "version_probe_output": first[:200]}


HELP_INLINE = 8192
DEFAULT_HELP = [["--help"], ["-h"]]
_USAGE = re.compile(r"(?im)(^\s*(usage|options|arguments|commands)\s*:|\busage:)")


def _shown(text: str, argv: list[str]) -> dict:
    """The help as the reply carries it: at most HELP_INLINE characters, and
    when cut, how to read the rest."""
    text = text.strip("\n")
    out = {"help": text[:HELP_INLINE], "help_argv": argv,
           "help_source": "the installed tool's own output, as text"}  # fmt: skip
    if len(text) > HELP_INLINE:
        out["help_cut"] = (
            f"The help is cut at {HELP_INLINE:,} of {len(text):,} characters: run "
            f"the tool with {' '.join(argv)} through run_windows_command for all of it"
        )
    return out


def tool_help(path: str | None, td) -> dict:
    """The installed tool's own help, asked with its catalog `help_argv` (the
    first that prints usage wins; else the first that prints anything). Run
    on every call, outside any case. Never for an acquisition tool or a
    script; a EULA screen in place of the help is said, never accepted."""
    if not path:
        return {}
    if td.acquisition:
        return {"help_not_run": "An acquisition tool isn't run to read its help."}
    if td.exec_type == "script":
        return {"help_not_run": "A script isn't run to read its help."}
    from wintools_mcp.tools.generic import eula_screen

    first, errors = None, []
    for argv in td.help_argv or DEFAULT_HELP:
        try:
            text = run_probe([path, *argv])
        except (OSError, subprocess.SubprocessError) as e:
            errors.append(f"{' '.join(argv)}: {e}")
            continue
        if eula_screen(text):
            return {"help_not_run": (
                f"{td.binary} showed its license (EULA) screen: the account running "
                "wintools hasn't accepted it. A run accepts it and says so."
            )}  # fmt: skip
        if _USAGE.search(text):
            return _shown(text, argv)
        if first is None and text.strip():
            first = (text, argv)
    if first:
        return _shown(*first)
    return {"help_error": "; ".join(errors) or "the tool printed no help"}


def clear() -> None:
    """Forget every version read."""
    with _lock:
        _versions.clear()


def tool_version(path: str | None, td=None) -> dict:
    """{"tool_version", "resolved_path"} for the file that runs, plus the
    probe's first line when a probe couldn't name the version. {} without a
    path."""
    if not path:
        return {}
    try:
        st = os.stat(path)
    except OSError:
        return {"tool_version": UNKNOWN, "resolved_path": str(path)}
    key = (str(path), st.st_size, st.st_mtime_ns)
    with _lock:
        if key in _versions:
            return dict(_versions[key])
    version = file_version(str(path))
    if version:
        found = {"tool_version": version}
    elif td is not None and getattr(td, "version_probe", None):
        found = _probe(str(path), td.version_probe)
    else:
        found = {"tool_version": UNKNOWN}
    found["resolved_path"] = str(path)
    with _lock:
        _versions[key] = found
    return dict(found)
