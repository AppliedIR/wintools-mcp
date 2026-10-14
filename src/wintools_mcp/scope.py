"""What wintools won't run: a command that reaches another system, or one
that puts a tool in its own live mode on the Windows host.

wintools runs Windows forensic tools on data already in the case. These
checks read the command's arguments only, so they touch no file and no
network before refusing. Each tool's switches are as its own help names
them (tests/fixtures/tool_help). A file the tool reads (a KAPE module that
collects, a rules file) is not checked.
"""

from __future__ import annotations

import os
import re

from wintools_mcp.catalog import get_tool_def

_ON_THE_CASE = "wintools runs tools on data already in the case"


def _real(path: str) -> str:
    """``path`` resolved, or as given when it can't be."""
    from pathlib import Path

    try:
        return str(Path(path).resolve())
    except OSError:
        return path


def _host(unc: str) -> str:
    """The host of a ``\\\\host\\…`` path (backslashes only), lowercased."""
    return unc[2:].split("\\", 1)[0].lower()


def _share_hosts(share_root: str) -> set[str]:
    """The case share's host: as configured, and as its root resolves (a
    mapped drive resolves to the share's UNC path)."""
    hosts = set()
    for root in (share_root, _real(share_root)) if share_root else ():
        root = root.replace("/", "\\")
        if root.startswith("\\\\") and not root.startswith(("\\\\?\\", "\\\\.\\")):
            hosts.add(_host(root))
        elif root.lower().startswith("\\\\?\\unc\\"):
            hosts.add(_host("\\\\" + root[8:]))
    return hosts - {""}


def _network(arg: str, share_root: str) -> str:
    """Why ``arg`` names another system or a device, or "" when it doesn't.

    Every ``\\\\`` in it is read as the start of a path, wherever it is (the
    value of ``--x=\\\\h\\s``, an item of a list), with ``/`` read as ``\\``
    as Windows reads it. ``\\\\?\\UNC\\host`` and ``\\??\\UNC\\host`` name that
    host; ``\\\\?\\X:\\`` and ``\\??\\X:\\`` are local. Any other ``\\\\?\\``
    or ``\\??\\`` path, and ``\\\\.\\`` (a device, such as a raw volume), is
    refused."""
    n = arg.replace("/", "\\")
    starts = [(m.start(), m.start() + 2) for m in re.finditer(r"(?=\\\\)", n)]
    starts += [(m.start(), m.start() + 1) for m in re.finditer(r"(?=\\\?\?\\)", n)]
    hosts: set[str] | None = None
    for at, rest in starts:
        tail = n[rest:]
        if tail.startswith(("?\\", "??\\", ".\\")):
            if tail.startswith(".\\"):
                return (
                    f"{arg} names a device ({n[at : at + 4]}…), not a file in the case"
                )
            tail = tail[tail.index("\\") + 1 :]
            if re.match(r"[A-Za-z]:(\\|$)", tail):
                continue  # a local drive's path
            if not tail.lower().startswith("unc\\"):
                return f"{arg} names a device or volume, not a file in the case"
            host = _host("\\\\" + tail[4:])
        else:
            host = _host(n[at:])
        if hosts is None:
            hosts = _share_hosts(share_root)
        if host not in hosts:
            share = ", ".join(sorted(hosts)) or "none: no case share is set"
            return (
                f"{arg} names another system ({host or 'no host'}): {_ON_THE_CASE}, "
                f"and reaches no system but the case share's host ({share})"
            )
    return ""


def unc_refusal(paths: list[str], share_root: str) -> str:
    """Why one of ``paths`` names another system, or ""."""
    for p in paths:
        why = _network(p, share_root)
        if why:
            return why
    return ""


def _switch(arg: str) -> str | None:
    """A switch's name, lowercased: its leading ``-`` (or one ``/``, when no
    other separator follows) and any ``=value`` or ``:value`` removed. None
    for an argument that isn't a switch."""
    if arg.startswith("-"):
        body = arg.lstrip("-")
    elif arg.startswith("/") and not re.search(r"[\\/]", arg[1:]):
        body = arg[1:]
    else:
        return None
    return re.split(r"[=:]", body, maxsplit=1)[0].lower()


def _cluster_has(arg: str, flag: str, takes_value: str) -> bool:
    """A short-option cluster (``-wl``) holds ``flag``: read up to the first
    option that takes a value (the rest is that value) or an ``=``/``:``."""
    if not arg.startswith("-") or arg.startswith("--"):
        return False
    for c in arg[1:]:
        if c in "=:":
            return False
        if c == flag:
            return True
        if c in takes_value:
            return False
    return False


def _inside(path: str, case_dir: str) -> bool:
    root = os.path.realpath(case_dir)
    try:
        return os.path.commonpath([os.path.realpath(path), root]) == root
    except ValueError:  # another drive
        return False


def _sigcheck(args, case_dir, op_dir) -> str:
    for a in args:
        s = _switch(a)
        if s is None:
            continue
        if s.startswith("v") or s == "o":
            return f"sigcheck {a} queries VirusTotal: {_ON_THE_CASE}"
        if s.startswith("t"):
            return (
                f"sigcheck {a} reads the Windows host's own certificate stores: "
                f"{_ON_THE_CASE}"
            )
    return ""


def _autorunsc(args, case_dir, op_dir) -> str:
    for a in args:
        if (_switch(a) or "").startswith("v"):
            return f"autorunsc {a} queries VirusTotal: {_ON_THE_CASE}"
    offline = "-z <systemroot> <userprofile>, both folders of a system in the case"
    zs = [i for i, a in enumerate(args) if _switch(a) == "z"]
    if not zs:
        return (
            "autorunsc without -z lists the Windows host's own autostart "
            f"entries: {_ON_THE_CASE}. Give {offline}"
        )
    if not case_dir:
        return f"autorunsc needs an active case: give {offline}"
    for i in zs:
        given = args[i + 1 : i + 3]
        if len(given) < 2:
            return f"autorunsc -z takes two folders: give {offline}"
        for p in given:
            full = p if os.path.isabs(p) or not op_dir else os.path.join(op_dir, p)
            if not os.path.isabs(full) or not _inside(full, case_dir):
                return f"autorunsc -z {p} isn't in the case: give {offline}"
    return ""


# Hayabusa's short options that take a value (dfir-timeline's help, 4.1.0):
# in a cluster, what follows one of them is its value
_HAYABUSA_VALUES = "dfrcemGHotp"


def _hayabusa(args, case_dir, op_dir) -> str:
    for a in args:
        if a.lower() == "update-rules":
            return f"hayabusa update-rules downloads rules from GitHub: {_ON_THE_CASE}"
        long = a[2:].split("=", 1)[0].lower() if a.startswith("--") else ""
        if (long and "live-analysis".startswith(long)) or _cluster_has(
            a, "l", _HAYABUSA_VALUES
        ):
            return (
                f"hayabusa {a} (--live-analysis) reads the Windows host's own "
                f"event logs: {_ON_THE_CASE}"
            )
    return ""


def _sync(tool):
    def check(args, case_dir, op_dir) -> str:
        for a in args:
            if _switch(a) == "sync":
                return f"{tool} {a} downloads from GitHub: {_ON_THE_CASE}"
        return ""

    return check


def _sbecmd(args, case_dir, op_dir) -> str:
    for a in args:
        if _switch(a) is None:
            continue  # a value, such as a path
        body = "-" + a[1:] if a.startswith("/") else a
        if _switch(a) == "l" or _cluster_has(body, "l", "d"):
            return f"SBECmd {a} reads the Windows host's live registry: {_ON_THE_CASE}"
    return ""


def _appcompatcacheparser(args, case_dir, op_dir) -> str:
    hive = any(
        (a == "-f" and i + 1 < len(args) and args[i + 1])
        or (a[:3] in ("-f:", "-f=") and a[3:])
        for i, a in enumerate(args)
    )
    if not hive:
        return (
            "AppCompatCacheParser without -f <SYSTEM hive> reads the Windows "
            f"host's live registry: {_ON_THE_CASE}. Give -f with a SYSTEM hive "
            "in the case"
        )
    return ""


def _yara(args, case_dir, op_dir) -> str:
    if args and re.fullmatch(r"-?[0-9]+", args[-1].strip()):
        return (
            f"yara's target {args[-1]} is a process id: yara would scan a live "
            f"process. {_ON_THE_CASE}"
        )
    return ""


# KAPE 1.3.0.2's help: target mode collects from a drive, --sync downloads,
# and these upload (SFTP, S3, Azure)
_KAPE_REFUSED = {"tsource", "target", "tdest", "sync", "rlc"}
_KAPE_UPLOAD = ("sc", "s3", "as", "sftp")


def _kape(args, case_dir, op_dir) -> str:
    for a in args:
        s = _switch(a)
        if s is None:
            continue
        if s in ("tsource", "target", "tdest"):
            return (
                f"kape {a}: target mode collects from a drive. {_ON_THE_CASE}: "
                "run modules over collected files (--msource, --module, --mdest)"
            )
        if s in _KAPE_REFUSED or s.startswith(_KAPE_UPLOAD):
            return f"kape {a} reaches another system: {_ON_THE_CASE}"
    return ""


_CHECKS = {
    "sigcheck": _sigcheck,
    "autorunsc": _autorunsc,
    "hayabusa": _hayabusa,
    "evtxecmd": _sync("EvtxECmd"),
    "sqlecmd": _sync("SQLECmd"),
    "recmd": _sync("RECmd"),
    "sbecmd": _sbecmd,
    "appcompatcacheparser": _appcompatcacheparser,
    "yara": _yara,
    "kape": _kape,
}


def refusal(
    command: list[str],
    case_dir: str,
    share_root: str,
    op_dir: str | None = None,
    paths: list[str] | None = None,
) -> str:
    """Why ``command`` won't run, or "". ``paths`` are other paths the run
    names (its declared input files): checked for another system too."""
    why = unc_refusal([*command[1:], *(paths or [])], share_root)
    if why or not command:
        return why
    td = get_tool_def(command[0])
    check = _CHECKS.get(td.name.lower()) if td else None
    return check(list(command[1:]), case_dir, op_dir) if check else ""
