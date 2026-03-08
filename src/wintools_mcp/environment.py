"""Windows environment detection and binary discovery."""

from __future__ import annotations

import logging
import os
import platform
import shutil
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


def find_binary(name: str, extra_paths: list[Path] | None = None) -> str | None:
    """Find a binary on the system.

    Search order:
    1. shutil.which() (checks PATH)
    2. Default tool paths
    3. Extra paths from config
    """
    found = shutil.which(name)
    if found:
        return found

    search = list(DEFAULT_TOOL_PATHS)
    if extra_paths:
        search.extend(extra_paths)

    for d in search:
        if not d.is_dir():
            continue
        candidate = d / name
        if candidate.is_file():
            return str(candidate)
        # Also check without .exe if not already included
        if not name.lower().endswith(".exe"):
            candidate_exe = d / f"{name}.exe"
            if candidate_exe.is_file():
                return str(candidate_exe)
        # One-level subdirectory walk (catches version dirs like net9/, x64/)
        try:
            for sub in d.iterdir():
                if not sub.is_dir():
                    continue
                candidate = sub / name
                if candidate.is_file():
                    return str(candidate)
                if not name.lower().endswith(".exe"):
                    candidate_exe = sub / f"{name}.exe"
                    if candidate_exe.is_file():
                        return str(candidate_exe)
        except OSError:
            continue

    return None


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
