"""Tool catalog: YAML-backed registry with denylist, install methods, and alternatives."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from wintools_mcp.exceptions import DenylistError, ToolNotInCatalogError

_CATALOG_DIR: Path | None = None
_catalog_cache: dict[str, Any] = {}

BLOCKED_BINARIES = frozenset({
    "cmd", "cmd.exe",
    "powershell", "powershell.exe",
    "pwsh", "pwsh.exe",
    "wscript", "wscript.exe",
    "cscript", "cscript.exe",
    "mshta", "mshta.exe",
    "rundll32", "rundll32.exe",
    "regsvr32", "regsvr32.exe",
    "certutil", "certutil.exe",
    "bitsadmin", "bitsadmin.exe",
    "msiexec", "msiexec.exe",
    "bash", "bash.exe",
    "wsl", "wsl.exe",
    "sh", "sh.exe",
})

PS_SCRIPT_EXCEPTIONS = frozenset({
    "Get-InjectedThreadEx.ps1",
})

_PS_BANNED_FLAGS = frozenset({
    "-command", "-c",
    "-encodedcommand", "-e", "-enc",
    "-invoke-expression",
})


def _find_catalog_dir() -> Path:
    global _CATALOG_DIR
    if _CATALOG_DIR is not None:
        return _CATALOG_DIR

    env = os.environ.get("WINTOOLS_CATALOG_DIR")
    if env:
        p = Path(env)
        if p.is_dir():
            _CATALOG_DIR = p
            return p

    # Relative: src/wintools_mcp/catalog.py -> ../../data/catalog/
    source = Path(__file__).resolve().parent.parent.parent / "data" / "catalog"
    if source.is_dir():
        _CATALOG_DIR = source
        return source

    raise FileNotFoundError("Cannot find wintools-mcp catalog directory.")


@dataclass
class InstallMethod:
    method: str          # "chocolatey", "scoop", "pip", "dotnet", "direct", "github"
    command: str = ""    # e.g., "choco install hayabusa"
    url: str = ""        # direct download URL
    notes: str = ""


@dataclass
class ToolDefinition:
    name: str
    binary: str
    category: str
    exec_type: str = "binary"   # binary, python_module, script, ps_script
    input_style: str = "flag"
    input_flag: str = ""
    output_format: str = "text"
    timeout_seconds: int = 600
    description: str = ""
    common_flags: list[dict] = field(default_factory=list)
    fk_tool_name: str = ""
    version_flag: str = "--version"
    install_methods: list[InstallMethod] = field(default_factory=list)
    install_paths: list[str] = field(default_factory=list)
    alternatives: list[str] = field(default_factory=list)

    @property
    def knowledge_name(self) -> str:
        return self.fk_tool_name or self.name


def load_catalog() -> dict[str, ToolDefinition]:
    if _catalog_cache:
        return _catalog_cache

    catalog_dir = _find_catalog_dir()
    for yaml_file in sorted(catalog_dir.glob("*.yaml")):
        with open(yaml_file, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        if not doc:
            continue
        category = doc.get("category", yaml_file.stem)
        for tool_entry in doc.get("tools", []):
            name = tool_entry["name"]
            install_methods = []
            for im in tool_entry.get("install_methods", []):
                install_methods.append(InstallMethod(
                    method=im.get("method", ""),
                    command=im.get("command", ""),
                    url=im.get("url", ""),
                    notes=im.get("notes", ""),
                ))

            td = ToolDefinition(
                name=name,
                binary=tool_entry.get("binary", name),
                category=category,
                exec_type=tool_entry.get("exec_type", "binary"),
                input_style=tool_entry.get("input_style", "flag"),
                input_flag=tool_entry.get("input_flag", ""),
                output_format=tool_entry.get("output_format", "text"),
                timeout_seconds=tool_entry.get("timeout_seconds", 600),
                description=tool_entry.get("description", ""),
                common_flags=tool_entry.get("common_flags", []),
                fk_tool_name=tool_entry.get("fk_tool_name", ""),
                version_flag=tool_entry.get("version_flag", "--version"),
                install_methods=install_methods,
                install_paths=tool_entry.get("install_paths", []),
                alternatives=tool_entry.get("alternatives", []),
            )
            _catalog_cache[name.lower()] = td

    return _catalog_cache


def get_tool_def(name: str) -> ToolDefinition | None:
    return load_catalog().get(name.lower())


def list_tools_in_catalog(category: str | None = None) -> list[dict]:
    catalog = load_catalog()
    results = []
    for td in catalog.values():
        if category and td.category != category:
            continue
        results.append({
            "name": td.name,
            "binary": td.binary,
            "category": td.category,
            "description": td.description,
        })
    return results


def is_in_catalog(binary_name: str) -> bool:
    catalog = load_catalog()
    bn = binary_name.lower()
    return any(td.binary.lower() == bn for td in catalog.values())


def validate_command(cmd: list[str]) -> str | None:
    """Validate command against denylist then allowlist.
    Returns None if valid, error message if blocked.
    """
    if not cmd:
        return "Empty command"

    binary = Path(cmd[0]).name.lower()

    # Check if this is a controlled PS script exception
    if binary in ("powershell.exe", "pwsh.exe"):
        if _is_valid_ps_exception(cmd):
            return None
        return "Arbitrary PowerShell execution is blocked"

    # Check denylist (hardcoded)
    if binary in BLOCKED_BINARIES:
        return f"Binary '{binary}' is blocked for security reasons"

    # Check allowlist (catalog)
    if not is_in_catalog(binary):
        return f"Binary '{binary}' is not in the approved tool catalog"

    return None


def _is_valid_ps_exception(cmd: list[str]) -> bool:
    """Validate a PowerShell command matches the controlled exception pattern."""
    flags = [f.lower() for f in cmd[1:]]

    for flag in flags:
        if flag in _PS_BANNED_FLAGS:
            return False

    if "-noprofile" not in flags:
        return False

    try:
        ep_idx = next(i for i, f in enumerate(flags) if f == "-executionpolicy")
        if flags[ep_idx + 1] != "bypass":
            return False
    except (StopIteration, IndexError):
        return False

    try:
        file_idx = next(i for i, f in enumerate(flags) if f == "-file")
        script_path = cmd[file_idx + 2]  # +2 because flags is offset by 1 from cmd
        # Handle both / and \ separators (cross-platform)
        script_name = script_path.replace("\\", "/").split("/")[-1]
        if script_name not in PS_SCRIPT_EXCEPTIONS:
            return False
    except (StopIteration, IndexError):
        return False

    return True


def clear_catalog_cache() -> None:
    global _CATALOG_DIR
    _catalog_cache.clear()
    _CATALOG_DIR = None
