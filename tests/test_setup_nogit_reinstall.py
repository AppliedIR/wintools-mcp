"""Re-running the installer without git replaces wintools-mcp's folder with a
fresh download: the user's config.yaml (its API key) survives, also when the
replace fails partway, and the running server is stopped before its files
are touched. The installer's own lines run under PowerShell; the download,
the archive, the scheduled tasks and the processes are stand-ins that record
what happens, in order.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "setup-windows.ps1"
TEXT = SCRIPT.read_text(encoding="utf-8")
CONFIG = "api_keys:\n  KEEP-THIS-KEY:\n    examiner: gateway\n"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="PowerShell isn't installed"
)


def _block() -> str:
    """The installer's stop functions, its download, and the no-git path."""
    start = TEXT.index("function Stop-WintoolsProcesses {")
    return TEXT[start : TEXT.index("# Create venv and install", start)]


STUBS = r"""
$events = [System.Collections.Generic.List[string]]::new()
function Write-Ok { param($m) Write-Host "OK $m" }
function Write-Info { param($m) Write-Host "INFO $m" }
function Write-Warn { param($m) Write-Host "WARN $m" }
function Write-Err { param($m) Write-Host "ERR $m" }
function Get-ScheduledTask { param($TaskName, $ErrorAction) if ($TaskName -like "Valhuntir*") { "task" } }
function Stop-ScheduledTask { param($TaskName, $ErrorAction) $events.Add("stop-task:$TaskName") }
function Get-Process { $events.Add("find-processes"); @([pscustomobject]@{ Path = "C:\Tools\vhir\wintools-mcp\.venv\Scripts\python.exe" }) }
function Stop-Process { param([Parameter(ValueFromPipeline=$true)]$InputObject, [switch]$Force) process { $events.Add("stop-process") } }
function Start-Sleep { param($Seconds) }
function Invoke-WebRequest { param($Uri, $OutFile, [switch]$UseBasicParsing, $TimeoutSec) $events.Add("download"); Set-Content -Path $OutFile -Value "zip" }
function Expand-Archive { param($Path, $DestinationPath, [switch]$Force)
    $events.Add("extract")
    if ($env:FAIL_AT -eq "extract") { throw "the archive is damaged" }
    $d = Join-Path $DestinationPath "wintools-mcp-main"; New-Item -ItemType Directory -Force -Path $d | Out-Null
    Set-Content -Path (Join-Path $d "pyproject.toml") -Value "fresh" }
function Rename-Item { param($Path, $NewName)
    $events.Add("rename")
    if ($env:FAIL_AT -eq "rename") { throw "the folder is in use" }
    Microsoft.PowerShell.Management\Rename-Item -Path $Path -NewName $NewName }
"""


def _run(tmp_path, fail_at=""):
    install = tmp_path / "vhir"
    folder = install / "wintools-mcp"
    folder.mkdir(parents=True)
    (folder / "config.yaml").write_text(CONFIG)
    (folder / "pyproject.toml").write_text("old")
    script = tmp_path / "rerun.ps1"
    script.write_text(
        STUBS
        + f"$InstallDir = '{install}'\n$wintoolsDir = '{folder}'\n"
        + "$wintoolsConfigPath = Join-Path $wintoolsDir 'config.yaml'\n"
        + "$githubOrg = 'https://github.example.test/AppliedIR'\n$hasGit = $false\n"
        + "try {\n"
        + _block()
        + "\n} finally { Write-Host (\"EVENTS \" + ($events -join ',')) }\n",
        encoding="utf-8",
    )
    p = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True, text=True, timeout=120,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "FAIL_AT": fail_at},
    )  # fmt: skip
    events = next(
        (
            ln.split(" ", 1)[1].split(",")
            for ln in p.stdout.splitlines()
            if ln.startswith("EVENTS ")
        ),
        [],
    )
    return p, folder, events


def test_a_rerun_without_git_keeps_the_users_config(tmp_path):
    p, folder, events = _run(tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert (folder / "pyproject.toml").read_text().strip() == "fresh"
    assert (folder / "config.yaml").read_text() == CONFIG
    assert not (tmp_path / "vhir" / "config.yaml.keep").exists()


@pytest.mark.parametrize("fail_at", ["extract", "rename"])
def test_a_replace_that_fails_partway_puts_the_config_back_and_stops(tmp_path, fail_at):
    p, folder, _ = _run(tmp_path, fail_at)
    assert p.returncode == 1, p.stdout + p.stderr
    assert (folder / "config.yaml").read_text() == CONFIG
    assert "ERR Failed to download wintools-mcp" in p.stdout
    assert "Your config.yaml was put back" in p.stdout
    assert not (tmp_path / "vhir" / "config.yaml.keep").exists()


def test_the_server_is_stopped_before_its_folder_is_replaced(tmp_path):
    _, _, events = _run(tmp_path)
    stops = [i for i, e in enumerate(events) if e.startswith("stop-")]
    assert "stop-task:Valhuntir wintools-mcp" in events
    assert "stop-task:Valhuntir wintools-mcp watchdog" in events
    assert "stop-process" in events
    assert stops and max(stops) < events.index("download") < events.index("rename"), (
        events
    )


def test_the_help_no_longer_offers_an_air_gapped_install():
    assert "Air-gapped lab" not in TEXT and "pre-staged directory" not in TEXT
    assert "needs\n    # internet access to both" in TEXT
