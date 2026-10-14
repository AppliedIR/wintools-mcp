"""Windows environment detection and binary discovery."""

from __future__ import annotations

import logging
import os
import platform
import shutil
import time
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_TOOL_PATHS = [
    Path(os.environ.get("ProgramFiles", "C:\\Program Files")),
    Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")),
    Path(os.environ.get("LOCALAPPDATA", "") or "C:\\Users\\Default\\AppData\\Local")
    / "Programs",
    Path("C:\\Tools"),
    Path("C:\\Tools\\ZimmermanTools"),
    Path("C:\\Tools\\Hayabusa"),
    Path("C:\\Tools\\SleuthKit\\bin"),
    Path("C:\\Tools\\Volatility3"),
    Path("C:\\Tools\\KAPE"),
    Path("C:\\Tools\\MemProcFS"),
    Path("C:\\Tools\\Moneta"),
    Path("C:\\Tools\\HollowsHunter"),
    Path("C:\\Tools\\CAPA"),
    Path("C:\\Tools\\SysinternalsSuite"),
    Path("C:\\Tools\\Chainsaw"),
    Path("C:\\Tools\\YARA"),
    Path("C:\\Tools\\DensityScout"),
    # SANS FOR508 default
    Path("C:\\Forensic_Program_Files"),
    Path(os.environ.get("USERPROFILE", "") or "C:\\Users\\Default")
    / "Desktop"
    / "ZimmermanTools",
    # Chocolatey
    Path("C:\\ProgramData\\chocolatey\\bin"),
    # Scoop
    Path(os.environ.get("USERPROFILE", "") or "C:\\Users\\Default") / "scoop" / "shims",
]


_binary_cache: dict[str, str | None] = {}

# A tool not found is looked for again after this long (a search of the tool
# folders costs about 0.25 s a list call on a real box), or at once by a scan
NOT_FOUND_SECONDS = 60
_not_found: dict[str, float] = {}


def clear_binary_cache() -> None:
    """Forget every lookup, found or not. Called from scan_tools()."""
    _binary_cache.clear()
    _not_found.clear()


def _search(name: str, extra_paths: list[Path] | None = None):
    """Every copy of ``name``, in the order a run looks: (path, the one PATH
    resolves).

    1. shutil.which() (checks PATH), then any other PATH folder's copy
    2. Each tool folder's direct children (with .exe tried)
    3. Each tool folder's subfolders, at most 4 levels deep (catches
       arbitrary layouts like ZimmermanTools/net9/RECmd/RECmd.exe)
    """
    wanted = {name.lower()}
    if not name.lower().endswith(".exe"):
        wanted.add(f"{name}.exe".lower())
    found = shutil.which(name)
    if found:
        yield found, True
        # every other PATH folder's copy too: listed, never the one run
        for d in filter(None, os.environ.get("PATH", "").split(os.pathsep)):
            for candidate in (Path(d) / name, Path(d) / f"{name}.exe"):
                if candidate.name.lower() in wanted and candidate.is_file():
                    yield str(candidate), False

    search = list(DEFAULT_TOOL_PATHS)
    if extra_paths:
        search.extend(extra_paths)

    for d in search:
        if not d.is_dir():
            continue
        candidate = d / name
        if candidate.is_file():
            yield str(candidate), False
        if not name.lower().endswith(".exe"):
            candidate_exe = d / f"{name}.exe"
            if candidate_exe.is_file():
                yield str(candidate_exe), False
        try:
            d_depth = str(d).count(os.sep)
            for root, dirs, files in os.walk(d):
                if root.count(os.sep) - d_depth >= 4:
                    dirs.clear()
                    continue
                for f in files:
                    if f.lower() in wanted:
                        yield str(Path(root) / f), False
        except OSError:
            continue


def find_binary(name: str, extra_paths: list[Path] | None = None) -> str | None:
    """The copy of ``name`` a run uses: the first that _search() finds. A PATH
    hit is kept, and checked again on each call: a copy since removed is
    looked for afresh."""
    cache_key = f"{name}|{'|'.join(str(p) for p in (extra_paths or []))}"
    cached = _binary_cache.get(cache_key)
    if cached is not None:
        if os.path.isfile(cached):
            return cached
        del _binary_cache[cache_key]  # gone since: look again
    looked = _not_found.get(cache_key)
    if looked is not None and time.monotonic() - looked < NOT_FOUND_SECONDS:
        return None

    for path, on_path in _search(name, extra_paths):
        if on_path:
            _binary_cache[cache_key] = path
        return path

    _not_found[cache_key] = time.monotonic()  # a tool installed later is found soon
    return None


def find_all(name: str, extra_paths: list[Path] | None = None) -> list[str]:
    """Every copy of ``name``, in the order a run looks (the first is the one
    that runs), each once."""
    seen: dict[str, str] = {}
    for path, _ in _search(name, extra_paths):
        seen.setdefault(os.path.normcase(os.path.abspath(path)), path)
    return list(seen.values())


def find_tool(binary_name: str) -> str | None:
    """Find a cataloged tool binary, merging config and catalog paths.

    Combines config.tool_paths with the tool's catalog install_paths
    so every call site searches the same locations. Looks up catalog
    entries by binary name (not tool name).
    """
    from wintools_mcp.catalog import load_catalog
    from wintools_mcp.config import get_config

    extra: list[Path] = []
    cfg = get_config()
    if cfg.tool_paths:
        extra.extend(cfg.tool_paths)

    # Look up by binary name — catalog keys are tool names, not binaries
    catalog = load_catalog()
    bn = binary_name.lower()
    td = next((t for t in catalog.values() if t.binary.lower() == bn), None)
    if td:
        for ip in td.install_paths:
            p = Path(ip)
            if p not in extra:
                extra.append(p)

    return find_binary(binary_name, extra or None)


def tool_copies(binary_name: str) -> list[str]:
    """Every copy of a cataloged binary, searched where find_tool searches;
    the first is the one that runs."""
    from wintools_mcp.catalog import load_catalog
    from wintools_mcp.config import get_config

    extra: list[Path] = list(get_config().tool_paths or [])
    bn = binary_name.lower()
    td = next((t for t in load_catalog().values() if t.binary.lower() == bn), None)
    for ip in td.install_paths if td else []:
        if Path(ip) not in extra:
            extra.append(Path(ip))
    return find_all(binary_name, extra or None)


def get_windows_version() -> dict:
    """Get Windows version info."""
    info = {
        "platform": platform.system(),
        "version": platform.version(),
        "release": platform.release(),
        "machine": platform.machine(),
    }
    if os.name == "nt":
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            )
            try:
                info["edition"] = winreg.QueryValueEx(key, "EditionID")[0]
                info["build"] = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
            finally:
                winreg.CloseKey(key)
        except ImportError:
            logger.warning("winreg module not available on this platform")
        except PermissionError:
            logger.warning("Permission denied reading Windows registry version info")
        except OSError as e:
            logger.warning("Failed to read Windows registry: %s", e)
    return info


def get_environment_info() -> dict:
    return {
        "windows": get_windows_version(),
        "python": platform.python_version(),
        "is_windows": os.name == "nt",
    }


def tool_path(td) -> str | None:
    """Where a cataloged tool runs from, or None when it can't run here. An
    executable is its binary, found. A script is there only when its file and
    its interpreter both are: a PowerShell script is `<name>.ps1` in its
    install paths (where it's run from), with Windows PowerShell; a Perl
    script is its binary, found, with perl.exe."""
    if td.exec_type != "script":
        return find_tool(td.binary)
    extra = [Path(p) for p in td.install_paths or []]
    if td.binary.lower().endswith(".pl"):
        script = find_tool(td.binary)
        return script if script and find_binary("perl.exe", extra) else None
    script = next(
        (str(d / f"{td.name}.ps1") for d in extra if (d / f"{td.name}.ps1").is_file()),
        None,
    )
    return (
        script if script and find_tool("powershell.exe") else None
    )  # as the run finds it
