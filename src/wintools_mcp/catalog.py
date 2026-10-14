"""Tool catalog: YAML-backed registry with denylist, install methods, and alternatives."""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_CATALOG_DIR: Path | None = None
_catalog_cache: dict[str, Any] = {}

BLOCKED_BINARIES = frozenset(
    {
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "wscript",
        "wscript.exe",
        "cscript",
        "cscript.exe",
        "mshta",
        "mshta.exe",
        "rundll32",
        "rundll32.exe",
        "regsvr32",
        "regsvr32.exe",
        "certutil",
        "certutil.exe",
        "bitsadmin",
        "bitsadmin.exe",
        "msiexec",
        "msiexec.exe",
        "bash",
        "bash.exe",
        "wsl",
        "wsl.exe",
        "sh",
        "sh.exe",
        # LOLBins: code execution proxies (LOLBAS)
        "msbuild",
        "msbuild.exe",
        "installutil",
        "installutil.exe",
        "regasm",
        "regasm.exe",
        "regsvcs",
        "regsvcs.exe",
        "cmstp",
        "cmstp.exe",
        "control",
        "control.exe",
    }
)


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
    method: str  # "chocolatey", "scoop", "pip", "dotnet", "direct", "github"
    command: str = ""  # e.g., "choco install hayabusa"
    url: str = ""  # direct download URL
    notes: str = ""


@dataclass
class ToolDefinition:
    name: str
    binary: str
    category: str
    exec_type: str = "binary"  # binary, python_module, script, ps_script
    input_style: str = "flag"
    input_flag: str = ""
    output_format: str = "text"
    output_flag: str = ""  # e.g. "--csv" — server auto-injects output dir if user omits
    timeout_seconds: int = 600
    description: str = ""
    # Tested calls, each tagged with the versions it was checked on:
    # [{task, versions (">=14.3,<15"), argv, notes}]
    recipes: list[dict] = field(default_factory=list)
    fk_tool_name: str = ""
    # Asked only when the file has no VERSIONINFO: {"argv": [...], "pattern":
    # a regex whose first group is the version}
    version_probe: dict = field(default_factory=dict)
    # The argv that print the tool's own help, tried in order (default
    # --help, then -h)
    help_argv: list[list[str]] = field(default_factory=list)
    install_methods: list[InstallMethod] = field(default_factory=list)
    install_paths: list[str] = field(default_factory=list)
    alternatives: list[str] = field(default_factory=list)
    # Settings the tool reads beside its binary (folders, relative to it):
    # their hashes are recorded with each run
    settings_paths: list[str] = field(default_factory=list)
    # A Sysinternals tool's key under HKCU\Software\Sysinternals: its
    # EulaAccepted value says whether the account running wintools has
    # accepted the tool's EULA. Not accepted, the run passes -accepteula and
    # its reply says the EULA was accepted on the examiner's behalf
    eula_key: str = ""

    @property
    def knowledge_name(self) -> str:
        return self.fk_tool_name or self.name


def _release(version: str) -> tuple[tuple[int, ...], int] | None:
    """A version's numbers and whether it is a release ("v4.2.0" -> ((4, 2,
    0), 1); "4.0.0-rc1" -> ((4, 0, 0), 0): a pre-release comes before its
    release). None when it has no numbers."""
    base = version.split("+")[0]
    nums = re.findall(r"\d+", base.split("-")[0])
    if not nums:
        return None
    return tuple(int(n) for n in nums), 0 if "-" in base else 1


def version_in(version: str, versions: str) -> bool:
    """Whether ``version`` is in a range such as ">=4.0,<5" (every comma
    clause must hold; >=, >, <=, <, ==). An unreadable version is in none,
    and a blank or unreadable range holds none."""
    have = _release(version or "")
    clauses = [c.strip() for c in versions.split(",") if c.strip()]
    if have is None or not clauses:
        return False
    for clause in clauses:
        m = re.match(r"(>=|<=|==|>|<)\s*(.+)", clause)
        want = _release(m.group(2)) if m else None
        if want is None:
            return False
        n = max(len(have[0]), len(want[0]))
        a = (have[0] + (0,) * (n - len(have[0])), have[1])
        b = (want[0] + (0,) * (n - len(want[0])), want[1])
        holds = {">=": a >= b, "<=": a <= b, "==": a == b, ">": a > b, "<": a < b}
        if not holds[m.group(1)]:
            return False
    return True


_catalog_loaded = False


def load_catalog() -> dict[str, ToolDefinition]:
    global _catalog_loaded
    if _catalog_loaded:
        return _catalog_cache

    catalog_dir = _find_catalog_dir()
    try:
        yaml_files = sorted(catalog_dir.glob("*.yaml"))
    except PermissionError as e:
        logger.warning(
            "Permission denied reading catalog directory %s: %s", catalog_dir, e
        )
        return _catalog_cache

    for yaml_file in yaml_files:
        try:
            with open(yaml_file, encoding="utf-8") as f:
                doc = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.warning(
                "Failed to parse YAML catalog file %s: %s", yaml_file.name, e
            )
            continue
        except OSError as e:
            logger.warning("Failed to read catalog file %s: %s", yaml_file.name, e)
            continue
        if not doc or not isinstance(doc, dict):
            logger.warning("Empty or invalid catalog file %s, skipping", yaml_file.name)
            continue
        category = doc.get("category", yaml_file.stem)
        for tool_entry in doc.get("tools", []):
            if not isinstance(tool_entry, dict) or "name" not in tool_entry:
                logger.warning("Invalid tool entry in %s, skipping", yaml_file.name)
                continue
            name = tool_entry["name"]
            install_methods = []
            for im in tool_entry.get("install_methods", []):
                install_methods.append(
                    InstallMethod(
                        method=im.get("method", ""),
                        command=im.get("command", ""),
                        url=im.get("url", ""),
                        notes=im.get("notes", ""),
                    )
                )

            td = ToolDefinition(
                name=name,
                binary=tool_entry.get("binary", name),
                category=category,
                exec_type=tool_entry.get("exec_type", "binary"),
                input_style=tool_entry.get("input_style", "flag"),
                input_flag=tool_entry.get("input_flag", ""),
                output_format=tool_entry.get("output_format", "text"),
                output_flag=tool_entry.get("output_flag", ""),
                timeout_seconds=tool_entry.get("timeout_seconds", 600),
                description=tool_entry.get("description", ""),
                recipes=[dict(r) for r in tool_entry.get("recipes") or []],
                fk_tool_name=tool_entry.get("fk_tool_name", ""),
                version_probe=dict(tool_entry.get("version_probe") or {}),
                help_argv=[
                    [str(a) for a in argv] for argv in tool_entry.get("help_argv") or []
                ],
                install_methods=install_methods,
                install_paths=tool_entry.get("install_paths", []),
                alternatives=tool_entry.get("alternatives", []),
                settings_paths=list(tool_entry.get("settings_paths", [])),
                eula_key=str(tool_entry.get("eula_key", "")),
            )
            _catalog_cache[name.lower()] = td

    _catalog_loaded = True
    return _catalog_cache


def get_tool_def(name: str) -> ToolDefinition | None:
    """A tool by its catalog name, or by its binary (with or without .exe, in
    any folder): callers name either. A script's interpreter is never its key."""
    catalog = load_catalog()
    key = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    stem = key.removesuffix(".exe")
    return (
        catalog.get(key)
        or catalog.get(stem)
        or next(
            (
                td
                for td in catalog.values()
                if td.exec_type != "script"
                and td.binary.lower().removesuffix(".exe") == stem
            ),
            None,
        )
    )


def list_tools_in_catalog(category: str | None = None) -> list[dict]:
    catalog = load_catalog()
    results = []
    for td in catalog.values():
        if category and td.category != category:
            continue
        results.append(
            {
                "name": td.name,
                "binary": td.binary,
                "category": td.category,
                "description": td.description,
            }
        )
    return results


def is_in_catalog(binary_name: str) -> bool:
    catalog = load_catalog()
    bn = binary_name.lower().removesuffix(".exe")
    return any(td.binary.lower().removesuffix(".exe") == bn for td in catalog.values())


def validate_command(cmd: list[str]) -> str | None:
    """Validate command against denylist then allowlist.
    Returns None if valid, error message if blocked.
    """
    if not cmd:
        return "Empty command"

    binary = Path(cmd[0]).name.lower()

    if binary in ("powershell.exe", "pwsh.exe"):
        return "Arbitrary PowerShell execution is blocked"

    # Check denylist (hardcoded)
    if binary in BLOCKED_BINARIES:
        return f"Binary '{binary}' is blocked for security reasons"

    # Check allowlist (catalog)
    if not is_in_catalog(binary):
        return f"Binary '{binary}' is not in the approved tool catalog"

    return None


def clear_catalog_cache() -> None:
    global _CATALOG_DIR, _catalog_loaded
    _catalog_cache.clear()
    _CATALOG_DIR = None
    _catalog_loaded = False
