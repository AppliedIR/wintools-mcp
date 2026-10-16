"""-Update on an install made without git (no .git, git not installed)
downloads wintools-mcp as a ZIP, the same download the install uses, and
mirrors it over the installed tree: the install's .venv and config.yaml stay.
A download that fails, or isn't wintools-mcp, changes nothing and says so. A
git checkout without git still stops, with what to do. The installer's own
lines run under PowerShell; the download and robocopy are stand-ins that
record what they are given.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "setup-windows.ps1"
TEXT = SCRIPT.read_text(encoding="utf-8")

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="PowerShell isn't installed"
)


def _between(start: str, end: str) -> str:
    i = TEXT.index(start)
    return TEXT[i : TEXT.index(end, i)]


STUBS = r"""
$ErrorActionPreference = "Stop"
function Write-Info { param($m) Write-Host "INFO $m" }
function Write-Ok { param($m) Write-Host "OK $m" }
function Write-Warn { param($m) Write-Host "WARN $m" }
function Write-Err { param($m) Write-Host "ERR $m" }
function Get-Command { param([Parameter(Position=0)]$Name)
    if ($Name -eq "git" -and $env:STUB_GIT) { return [pscustomobject]@{ Name = "git" } } }
function git { Write-Host "GIT $args"; $global:LASTEXITCODE = 1 }
function Invoke-WebRequest { param($Uri, $OutFile, [switch]$UseBasicParsing, $TimeoutSec, $ErrorAction)
    Write-Host "DOWNLOAD $Uri"
    if (-not $env:STUB_ZIP) { throw "The remote name could not be resolved" }
    Copy-Item -LiteralPath $env:STUB_ZIP -Destination $OutFile }
# robocopy SRC DST /MIR /XD dir /XF file ...: a mirror that keeps what /XD
# and /XF name, then the exit code the test asks for
function robocopy {
    Write-Host "ROBOCOPY $($args -join ' | ')"
    $src, $dst = $args[0], $args[1]
    $keep = @($args[$args.IndexOf("/XD") + 1], $args[$args.IndexOf("/XF") + 1])
    Write-Host "STAGED $(Test-Path (Join-Path $src 'pyproject.toml'))"
    Get-ChildItem -LiteralPath $dst -Force | Where-Object { $keep -notcontains $_.FullName } |
        Remove-Item -Recurse -Force
    Get-ChildItem -LiteralPath $src -Force | Copy-Item -Destination $dst -Recurse -Force
    "  ERROR 5 (0x00000005) Copying File $dst\scripts\setup-windows.ps1"
    "Access is denied."
    $global:LASTEXITCODE = [int]$env:STUB_ROBOCOPY_RC
}
$wintoolsDir = $env:STUB_DIR
"""


def _update_source() -> str:
    return _between(
        "    # 1. Update source", "    # The installed setup-windows.ps1 does the rest"
    )


def _run(tmp_path: Path, env: dict) -> tuple[int, str]:
    run = tmp_path / "update.ps1"
    run.write_text(
        STUBS + _update_source() + '"reached the update check"\n', encoding="utf-8"
    )
    temp = tmp_path / "temp"
    temp.mkdir(exist_ok=True)
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(run)],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "STUB_ROBOCOPY_RC": "1",
            "TMPDIR": str(temp),
            "WINTOOLS_SETUP_RERUN": "",
            **env,
        },
        timeout=120,
    )
    return r.returncode, r.stdout + r.stderr


def _installed(tmp_path: Path, git_dir: bool = False) -> Path:
    tree = tmp_path / "C" / "Tools" / "vhir" / "wintools-mcp"
    (tree / ".venv" / "Scripts").mkdir(parents=True)
    (tree / ".venv" / "Scripts" / "python.exe").write_text("venv\n")
    (tree / "config.yaml").write_text("api_keys:\n  KEEP-THIS-KEY: {}\n")
    (tree / "pyproject.toml").write_text("old\n")
    (tree / "gone.py").write_text("only in the old tree\n")
    if git_dir:
        (tree / ".git").mkdir()
    return tree


def _zip(tmp_path: Path, top: str = "wintools-mcp-main") -> Path:
    path = tmp_path / "main.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"{top}/pyproject.toml", "new\n")
        z.writestr(f"{top}/scripts/setup-windows.ps1", "# new\n")
    return path


def test_an_update_without_git_downloads_the_zip_and_keeps_venv_and_config(
    tmp_path,
):
    tree = _installed(tmp_path)
    rc, out = _run(tmp_path, {"STUB_DIR": str(tree), "STUB_ZIP": str(_zip(tmp_path))})
    assert rc == 0, out
    assert "Git is required" not in out and "GIT " not in out
    assert (
        "DOWNLOAD https://github.com/AppliedIR/wintools-mcp/archive/refs/heads/main.zip"
        in out
    )
    copy = next(x for x in out.splitlines() if x.startswith("ROBOCOPY "))
    args = copy[len("ROBOCOPY ") :].split(" | ")
    assert args[1] == str(tree) and args[2] == "/MIR"
    assert args[args.index("/XD") + 1] == str(tree / ".venv")
    assert args[args.index("/XF") + 1] == str(tree / "config.yaml")
    assert "STAGED True" in out
    assert "OK Source updated" in out and "reached the update check" in out
    assert (tree / "pyproject.toml").read_text() == "new\n"
    assert (tree / "scripts" / "setup-windows.ps1").read_text() == "# new\n"
    assert not (tree / "gone.py").exists()
    assert (tree / "config.yaml").read_text() == "api_keys:\n  KEEP-THIS-KEY: {}\n"
    assert (tree / ".venv" / "Scripts" / "python.exe").read_text() == "venv\n"
    assert list((tmp_path / "temp").iterdir()) == []  # the download is cleaned up


@pytest.mark.parametrize(
    "zip_top", [None, "something-else"], ids=["download-fails", "not-wintools-mcp"]
)
def test_a_failed_download_changes_nothing_and_says_so(tmp_path, zip_top):
    tree = _installed(tmp_path)
    env = {"STUB_DIR": str(tree)}
    if zip_top:
        env["STUB_ZIP"] = str(_zip(tmp_path, zip_top))
    rc, out = _run(tmp_path, env)
    assert rc == 1, out
    assert "ERR Could not download wintools-mcp from https://github.com/" in out
    assert "INFO Nothing was changed: the installed wintools-mcp is as it was." in out
    assert "ROBOCOPY" not in out and "reached the update check" not in out
    assert (tree / "pyproject.toml").read_text() == "old\n"
    assert (tree / "gone.py").exists()
    assert list((tmp_path / "temp").iterdir()) == []


@pytest.mark.parametrize(("code", "rc"), [("7", 0), ("8", 1), ("16", 1)])
def test_a_robocopy_failure_stops_the_update_with_its_lines(tmp_path, code, rc):
    """robocopy's 0-7 are success (1 = files copied), 8 and up a failure."""
    tree = _installed(tmp_path)
    got, out = _run(
        tmp_path,
        {
            "STUB_DIR": str(tree),
            "STUB_ZIP": str(_zip(tmp_path)),
            "STUB_ROBOCOPY_RC": code,
        },
    )
    assert got == rc, out
    assert ("reached the update check" in out) == (rc == 0)
    assert (
        f"ERR Could not copy the update into {tree} (robocopy exit {code}):" in out
    ) == (rc == 1)
    assert ("  Access is denied." in out) == (rc == 1)
    assert list((tmp_path / "temp").iterdir()) == []


def test_a_re_run_does_not_download_again(tmp_path):
    """The run that started it updated the source and found a new script."""
    tree = _installed(tmp_path)
    rc, out = _run(
        tmp_path,
        {
            "STUB_DIR": str(tree),
            "STUB_ZIP": str(_zip(tmp_path)),
            "WINTOOLS_SETUP_RERUN": "1",
        },
    )
    assert rc == 0, out
    assert "DOWNLOAD" not in out and "ROBOCOPY" not in out
    assert "OK Source updated by the run that started this one" in out
    assert (tree / "pyproject.toml").read_text() == "old\n"


def test_a_git_checkout_without_git_says_what_to_do(tmp_path):
    tree = _installed(tmp_path, git_dir=True)
    rc, out = _run(tmp_path, {"STUB_DIR": str(tree), "STUB_ZIP": str(_zip(tmp_path))})
    assert rc == 1, out
    assert f"ERR {tree} is a git checkout, and git isn't installed." in out
    assert "winget install Git.Git" in out
    assert "DOWNLOAD" not in out and (tree / "pyproject.toml").read_text() == "old\n"


def test_with_git_the_update_still_uses_git(tmp_path):
    tree = _installed(tmp_path)
    rc, out = _run(
        tmp_path,
        {"STUB_DIR": str(tree), "STUB_ZIP": str(_zip(tmp_path)), "STUB_GIT": "1"},
    )
    assert "DOWNLOAD" not in out and "ROBOCOPY" not in out
    assert "GIT init" in out and "ERR Could not reach GitHub." in out
    assert rc == 1, out
