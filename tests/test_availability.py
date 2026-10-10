"""What the tool lists say is available is what can run here, now.

A tool installed after setup is found on the next call (a lookup that found
nothing isn't remembered), and scan_tools looks afresh, so a tool removed
since is seen as gone. A script tool is available only when its script and
its interpreter are both there. Real lookups over a temporary tools folder.
"""

from __future__ import annotations

import pytest

from wintools_mcp import environment
from wintools_mcp.inventory import scan_tools
from wintools_mcp.tools.discovery import list_available_tools

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
    environment.clear_binary_cache()
    yield tools, scripts, perl
    environment.clear_binary_cache()


def _available(name: str) -> bool:
    return next(t for t in list_available_tools() if t["name"] == name)["available"]


def test_a_tool_installed_later_is_found_on_the_next_call(box):
    tools, _, _ = box
    assert _available("densityscout") is False
    (tools / "densityscout.exe").write_bytes(b"MZ")
    assert _available("densityscout") is True  # no restart, no scan


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
    tools, scripts, _ = box
    (tools / "powershell.exe").write_bytes(b"MZ")
    # PowerShell alone isn't the tool
    assert _available("Get-InjectedThreadEx") is False
    (scripts / "Get-InjectedThreadEx.ps1").write_text("function Get-InjectedThread {}")
    environment.clear_binary_cache()
    tool = next(
        t for t in list_available_tools() if t["name"] == "Get-InjectedThreadEx"
    )
    assert tool["available"] is True and tool["path"].endswith(
        "Get-InjectedThreadEx.ps1"
    )


def test_a_perl_script_is_available_only_with_perl(box):
    _, _, perl = box
    (perl / "mactime.pl").write_text("#!/usr/bin/perl\n")
    assert _available("mactime") is False  # the script alone can't run
    (perl / "perl.exe").write_bytes(b"MZ")
    assert _available("mactime") is True
