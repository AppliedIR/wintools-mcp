"""What the tool lists say is available is what can run here, now.

A tool installed after setup is found once the not-found window has passed
(NOT_FOUND_SECONDS; a search of the tool folders costs about 0.25 s a list
call on a real box), or at once by scan_tools, which looks afresh, so a tool
removed since is seen as gone too. A script tool is available only when its script and
its interpreter are both there. Real lookups over a temporary tools folder.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from wintools_mcp import environment
from wintools_mcp.inventory import scan_tools
from wintools_mcp.tools.discovery import list_available_tools

WINDOW = getattr(environment, "NOT_FOUND_SECONDS", 60)  # how long "not found" holds

CATALOG = """
category: test
tools:
  - name: densityscout
    binary: densityscout.exe
    description: "entropy"
    output_format: text
  - name: Get-InjectedThreadEx
    binary: powershell.exe
    description: "injected threads"
    exec_type: script
    output_format: text
    install_paths:
      - "{scripts}"
  - name: mactime
    binary: mactime.pl
    description: "bodyfile timeline"
    exec_type: script
    output_format: text
    install_paths:
      - "{perl}"
"""


@pytest.fixture
def box(tmp_path, monkeypatch):
    """A catalog of an executable and two scripts, and empty tool folders."""
    tools, scripts, perl, cat = (
        tmp_path / n for n in ("tools", "scripts", "perl", "cat")
    )
    for d in (tools, scripts, perl, cat):
        d.mkdir()
    (cat / "test.yaml").write_text(CATALOG.format(scripts=scripts, perl=perl))
    monkeypatch.setenv("WINTOOLS_CATALOG_DIR", str(cat))
    monkeypatch.setenv("PATH", str(tmp_path / "nothing-on-path"))
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", [tools])
    clock = [1000.0]
    fake_time = SimpleNamespace(monotonic=lambda: clock[0])  # environment's clock
    monkeypatch.setattr(environment, "time", fake_time, raising=False)
    environment.clear_binary_cache()
    yield tools, scripts, perl, clock
    environment.clear_binary_cache()


def _available(name: str) -> bool:
    return next(t for t in list_available_tools() if t["name"] == name)["available"]


def test_a_tool_installed_later_is_found_once_the_window_passes(box):
    tools, _, _, clock = box
    assert _available("densityscout") is False
    (tools / "densityscout.exe").write_bytes(b"MZ")
    assert _available("densityscout") is False  # not looked for again yet
    clock[0] += WINDOW
    assert _available("densityscout") is True  # no restart, no scan


def test_a_scan_finds_a_tool_installed_later_at_once(box):
    tools, _, _, _ = box
    assert _available("densityscout") is False
    (tools / "densityscout.exe").write_bytes(b"MZ")
    names = [t["name"] for t in scan_tools()["available_tools"]]
    assert "densityscout" in names


def test_a_scan_looks_afresh_for_a_tool_removed_since(box, tmp_path, monkeypatch):
    on_path = tmp_path / "bin"
    on_path.mkdir()
    exe = on_path / "densityscout.exe"
    exe.write_bytes(b"MZ")
    exe.chmod(0o755)
    monkeypatch.setenv("PATH", str(on_path))
    assert _available("densityscout") is True  # found on PATH, remembered
    exe.unlink()
    names = [t["name"] for t in scan_tools()["missing_tools"]]
    assert "densityscout" in names


def test_a_powershell_script_is_available_only_with_its_script(box):
    tools, scripts, _, clock = box
    (scripts / "Get-InjectedThreadEx.ps1").write_text("function Get-InjectedThread {}")
    # the script with no PowerShell to run it isn't the tool
    assert _available("Get-InjectedThreadEx") is False
    (scripts / "Get-InjectedThreadEx.ps1").unlink()
    (tools / "powershell.exe").write_bytes(b"MZ")
    clock[0] += WINDOW
    # nor is PowerShell alone
    assert _available("Get-InjectedThreadEx") is False
    (scripts / "Get-InjectedThreadEx.ps1").write_text("function Get-InjectedThread {}")
    tool = next(
        t for t in list_available_tools() if t["name"] == "Get-InjectedThreadEx"
    )
    assert tool["available"] is True and tool["path"].endswith(
        "Get-InjectedThreadEx.ps1"
    )


def test_a_perl_script_is_available_only_with_perl(box):
    _, _, perl, clock = box
    (perl / "mactime.pl").write_text("#!/usr/bin/perl\n")
    assert _available("mactime") is False  # the script alone can't run
    (perl / "perl.exe").write_bytes(b"MZ")
    clock[0] += WINDOW
    assert _available("mactime") is True
