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
import time

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


def bounded_output(argv: list[str]) -> tuple[int | None, str, str]:
    """The process's exit code, stdout and stderr, at most PROBE_BYTES of
    each: read as it comes, and the process ended once both are read or
    PROBE_SECONDS pass, so a tool that writes megabytes never fills memory.
    The exit code is None when the process hadn't ended by itself: one
    stopped here at a cap has only the kill's code (-9, or 1 on Windows).
    Run outside any case: no op folder, nothing saved."""
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    got: dict[str, bytearray] = {"out": bytearray(), "err": bytearray()}
    full = threading.Event()  # a stream reached its cap: the rest isn't read

    def read(pipe, key: str) -> None:
        buf = got[key]  # kept as read, even if this reader never ends
        try:
            while len(buf) < PROBE_BYTES:
                chunk = pipe.read1(PROBE_BYTES - len(buf))
                if not chunk:
                    break
                buf += chunk
            else:
                full.set()
        except (OSError, ValueError):  # the pipe closed under us
            pass

    readers = [
        threading.Thread(target=read, args=(proc.stdout, "out"), daemon=True),
        threading.Thread(target=read, args=(proc.stderr, "err"), daemon=True),
    ]
    for t in readers:
        t.start()
    deadline = time.monotonic() + PROBE_SECONDS
    while any(t.is_alive() for t in readers) and not full.is_set():
        if time.monotonic() > deadline:
            break
        for t in readers:
            t.join(0.05)
    out_of_time = any(t.is_alive() for t in readers) and not full.is_set()
    if not out_of_time and not full.is_set():  # both pipes closed: it is ending
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    ended = proc.poll() is not None  # the tool itself ended
    if not ended:  # still writing (past a cap) or past the deadline
        proc.kill()
    for t in readers:
        t.join(1)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # a pipe a child of the tool still holds is left to its reader (a daemon):
    # closing it would wait for that child
    for t, pipe in zip(readers, (proc.stdout, proc.stderr), strict=True):
        if not t.is_alive():
            pipe.close()
    if out_of_time and not ended:
        raise subprocess.TimeoutExpired(argv, PROBE_SECONDS)
    from wintools_mcp.executor import _decode_output, signed_exit

    # each stream in its own encoding: Sysinternals tools write UTF-16LE
    out, err = bytes(got["out"]), bytes(got["err"])
    code = signed_exit(proc.returncode) if ended else None
    return code, _decode_output(out), _decode_output(err)


def run_probe(argv: list[str]) -> str:
    """A version probe's output, stdout then stderr (tests replace this)."""
    _, out, err = bounded_output(argv)
    return out + "\n" + err


def run_help(argv: list[str]) -> tuple[int | None, str, str]:
    """A help probe's exit code, stdout and stderr (tests replace this)."""
    return bounded_output(argv)


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
STDERR_INLINE = 1024  # of stderr, kept inline however long stdout is
DEFAULT_HELP = [["--help"], ["-h"]]
STDERR_LABEL = "# --- stderr ---"


def as_shown(out: str, err: str) -> str:
    """Both streams, stdout first, stderr under its label."""
    return f"{out}\n{STDERR_LABEL}\n{err}\n"


def _cut_mark(stream: str) -> str:
    """No length: a stream read up to PROBE_BYTES may have been longer."""
    return f"\n[{stream} cut here]"


def _inline(out: str, err: str) -> str:
    """Both streams as shown, at most HELP_INLINE characters. When they don't
    fit and the tool wrote to stderr, stdout is cut so that the stderr label
    and at least STDERR_INLINE characters of stderr stay: a long usage text
    never hides the error. Each cut stream is marked where it is cut."""
    text = as_shown(out, err).strip("\n")
    if len(text) <= HELP_INLINE or not err.strip():
        return text[:HELP_INLINE]
    out, err = out.strip("\n"), err.strip("\n")
    label = f"\n{STDERR_LABEL}\n"
    err_room = max(STDERR_INLINE, HELP_INLINE - len(label) - len(out))
    if len(err) > err_room:
        mark = _cut_mark("stderr")
        err = err[: err_room - len(mark)] + mark
    out_room = HELP_INLINE - len(label) - len(err)
    if len(out) > out_room:
        mark = _cut_mark("stdout")
        out = out[: out_room - len(mark)] + mark
    return f"{out}{label}{err}".strip("\n")


def _shown(out: str, err: str, argv: list[str], code: int | None) -> dict:
    """The help as the reply carries it, with its exit code: at most
    HELP_INLINE characters, and when cut, how to read the rest. A tool
    stopped at the probe's cap has no exit code of its own. The help's full
    length is never claimed: a stream may be longer than the probe read, and
    the characters read aren't the bytes written."""
    text = as_shown(out, err).strip("\n")
    shown = {"help": _inline(out, err), "help_argv": argv, "help_exit_code": code,
             "help_source": "the installed tool's own output, as text"}  # fmt: skip
    if len(text) > HELP_INLINE:
        shown["help_cut"] = (
            f"The help is cut at {HELP_INLINE:,} characters: run the tool with "
            f"{' '.join(argv)} through run_windows_command for all of it"
        )
    return shown


def tool_help(path: str | None, td) -> dict:
    """The installed tool's own help, asked with its catalog `help_argv`: what
    it printed, stdout then stderr under STDERR_LABEL, with its exit code.
    Nothing here judges whether it is help (an "invalid option" with exit 1
    is shown as printed). The next argv is tried only when the tool printed
    nothing at all. Run on every call, outside any case. Never for an
    acquisition tool or a script; a EULA screen in place of the help is
    said, never accepted."""
    if not path:
        return {}
    if td.acquisition:
        return {"help_not_run": "An acquisition tool isn't run to read its help."}
    if td.exec_type == "script":
        return {"help_not_run": "A script isn't run to read its help."}
    from wintools_mcp.tools.generic import eula_screen

    errors = []
    for argv in td.help_argv or DEFAULT_HELP:
        try:
            code, out, err = run_help([path, *argv])
        except (OSError, subprocess.SubprocessError) as e:
            errors.append(f"{' '.join(argv)}: {e}")
            continue
        if eula_screen(out) or eula_screen(err):
            return {"help_not_run": (
                f"{td.binary} showed its license (EULA) screen: the account running "
                "wintools hasn't accepted it. A run accepts it and says so."
            )}  # fmt: skip
        if out.strip() or err.strip():
            return _shown(out, err, argv, code)
        errors.append(f"{' '.join(argv)}: printed nothing (exit code {code})")
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
