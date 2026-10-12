"""A run's input is what its command names, and a script tool is available
wherever its interpreter would be found for the run.

- Only KAPE's --tsource reads a bare drive letter as that drive. Another
  tool's input flag given "C" names a file C in the run's folder, so a run
  whose file is missing is refused naming that file, never the drive root.
- A PowerShell script tool is available when powershell.exe is only in the
  configured tool paths: the run finds it there, and so does the check.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from test_names_and_binaries import _call
from test_run_records import case  # noqa: F401  (fixture)

from wintools_mcp import catalog, environment
from wintools_mcp import config as config_mod
from wintools_mcp.config import WintoolsConfig


def test_another_tools_input_flag_names_a_file_not_a_drive(case, tmp_path):  # noqa: F811
    resp, _, ran = _call(tmp_path, ["bstrings.exe", "-f", "C"])
    assert resp["success"] is False and ran == []
    named = Path(resp["error"].removeprefix("Evidence path not accessible: "))
    assert (named.name, named.parent.parent) == (
        "C",
        case / "extractions",
    )  # its op folder's C


def test_kape_still_reads_a_bare_drive_letter_as_the_drive(case, tmp_path):  # noqa: F811
    args = ["--tsource", "C", "--target", "KapeTriage", "--tdest", str(case / "out")]
    resp, _, ran = _call(tmp_path, ["kape.exe", *args])
    assert resp["success"] is False and ran == [] and "C:\\" in resp["error"]


@pytest.fixture
def interpreters(tmp_path, monkeypatch):
    """Nothing on PATH or in the default folders; `tool_paths` is the config's."""
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: None)
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", [])
    environment._binary_cache.clear()
    environment._not_found.clear()

    def exe(folder: Path, name: str) -> Path:
        folder.mkdir(parents=True, exist_ok=True)
        (folder / name).write_bytes(b"MZ")
        (folder / name).chmod(0o755)
        return folder

    def configure(tool_paths):
        cfg = WintoolsConfig()
        cfg.tool_paths = list(tool_paths)
        monkeypatch.setattr(config_mod, "_config", cfg)
        environment._binary_cache.clear()
        environment._not_found.clear()

    yield exe, configure
    environment._binary_cache.clear()
    environment._not_found.clear()


def _script(kind: str):
    return next(t for t in catalog.load_catalog().values() if t.exec_type == "script"
                and t.binary.lower().endswith(".pl") == (kind == "perl"))  # fmt: skip


def test_a_powershell_script_is_available_with_powershell_only_in_tool_paths(
    interpreters, tmp_path, monkeypatch
):
    exe, configure = interpreters
    td = _script("powershell")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / f"{td.name}.ps1").write_text("# ps1\n")
    monkeypatch.setattr(td, "install_paths", [str(scripts)])
    configure([exe(tmp_path / "tools", "powershell.exe")])
    assert environment.tool_path(td) == str(scripts / f"{td.name}.ps1")


def test_a_perl_scripts_availability_is_as_before(interpreters, tmp_path, monkeypatch):
    """perl.exe is looked for in the script's own install folder (Strawberry's),
    as before; the run starts the .pl directly."""
    exe, configure = interpreters
    td = _script("perl")
    home = exe(tmp_path / "strawberry", td.binary)
    exe(home, "perl.exe")
    monkeypatch.setattr(td, "install_paths", [str(home)])
    configure([])
    assert environment.tool_path(td) == str(home / td.binary)
    (home / "perl.exe").unlink()
    environment._binary_cache.clear()
    environment._not_found.clear()
    configure([exe(tmp_path / "elsewhere", "perl.exe")])
    # only in tool_paths, perl.exe isn't looked for: the run starts the .pl itself
    assert environment.tool_path(td) is None
