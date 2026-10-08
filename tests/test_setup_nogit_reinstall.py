"""Re-running the installer without git replaces wintools-mcp's folder with a
fresh download: the user's config.yaml (its API key) survives, also when the
replace fails partway, and its saved copy is removed only once it's back. The
running server is stopped only once the new tree is extracted, right before
the replace, with its tasks disabled meanwhile; a failure after the stop
starts it again. The installer's own lines run under PowerShell; the
download, the archive, the scheduled tasks and the processes are stand-ins
that record what happens, in order.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "setup-windows.ps1"
TEXT = SCRIPT.read_text(encoding="utf-8")
CONFIG = "api_keys:\n  KEEP-THIS-KEY:\n    examiner: gateway\n"
SERVER = "Valhuntir wintools-mcp"
WATCHDOG = "Valhuntir wintools-mcp watchdog"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="PowerShell isn't installed"
)


def _block() -> str:
    """The installer's stop, restore and download helpers, and the clone or
    download step."""
    start = TEXT.index('$keptConfigPath = Join-Path $InstallDir "config.yaml.keep"')
    return TEXT[start : TEXT.index("# Create venv and install", start)]


STUBS = r"""
$events = [System.Collections.Generic.List[string]]::new()
function Write-Ok { param($m) Write-Host "OK $m" }
function Write-Info { param($m) Write-Host "INFO $m" }
function Write-Warn { param($m) Write-Host "WARN $m" }
function Write-Err { param($m) Write-Host "ERR $m" }
function Get-ScheduledTask { param($TaskName, $ErrorAction)
    if ($env:NO_TASKS) { return }
    if ($TaskName -eq "Valhuntir wintools-mcp") { return [pscustomobject]@{ State = "Running" } }
    if ($TaskName -eq "Valhuntir wintools-mcp watchdog") {
        return [pscustomobject]@{ State = $(if ($env:WATCHDOG_RUNNING) { "Running" } else { "Ready" }) } } }
function Disable-ScheduledTask { param($TaskName, $ErrorAction) $events.Add("disable-task:$TaskName") }
function Enable-ScheduledTask { param($TaskName, $ErrorAction) $events.Add("enable-task:$TaskName") }
function Stop-ScheduledTask { param($TaskName, $ErrorAction) $events.Add("stop-task:$TaskName") }
function Start-ScheduledTask { param($TaskName, $ErrorAction) $events.Add("start-task:$TaskName") }
function Start-Process { param($FilePath, $ArgumentList, $WindowStyle) $events.Add("start-process") }
function Get-Process { $events.Add("find-processes"); @([pscustomobject]@{ Path = "C:\Tools\vhir\wintools-mcp\.venv\Scripts\python.exe" }) }
function Stop-Process { param([Parameter(ValueFromPipeline=$true)]$InputObject, [switch]$Force) process { $events.Add("stop-process") } }
function Start-Sleep { param($Seconds) }
function Invoke-WebRequest { param($Uri, $OutFile, [switch]$UseBasicParsing, $TimeoutSec)
    $events.Add("download")
    if ($env:FAIL_AT -eq "download") { throw "GitHub can't be reached" }
    Set-Content -Path $OutFile -Value "zip" }
function Expand-Archive { param($Path, $DestinationPath, [switch]$Force)
    $events.Add("extract")
    if ($env:FAIL_AT -eq "extract") { throw "the archive is damaged" }
    $d = Join-Path $DestinationPath "wintools-mcp-main"; New-Item -ItemType Directory -Force -Path $d | Out-Null
    Set-Content -Path (Join-Path $d "pyproject.toml") -Value "fresh" }
function Rename-Item { param($Path, $NewName)
    $events.Add("rename")
    if ($env:FAIL_AT -eq "rename") { throw "the folder is in use" }
    Microsoft.PowerShell.Management\Rename-Item -Path $Path -NewName $NewName }
function Copy-Item { param($Path, $Destination, [switch]$Force, $ErrorAction)
    if ($env:FAIL_AT -eq "copy-back" -and $Destination -eq $wintoolsConfigPath) {
        $events.Add("copy-back-failed"); throw "access denied" }
    Microsoft.PowerShell.Management\Copy-Item -Path $Path -Destination $Destination -Force }
"""


def _install(tmp_path, config=CONFIG) -> Path:
    folder = tmp_path / "vhir" / "wintools-mcp"
    folder.mkdir(parents=True)
    if config is not None:
        (folder / "config.yaml").write_text(config)
    (folder / "pyproject.toml").write_text("old")
    return folder


def _run(tmp_path, fail_at="", no_tasks=False, watchdog_running=False):
    install = tmp_path / "vhir"
    folder = install / "wintools-mcp"
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
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "FAIL_AT": fail_at}
    if no_tasks:
        env["NO_TASKS"] = "1"
    if watchdog_running:
        env["WATCHDOG_RUNNING"] = "1"
    p = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True, text=True, timeout=120, env=env,
    )  # fmt: skip
    events = next(
        (
            [e for e in ln.split(" ", 1)[1].split(",") if e]
            for ln in p.stdout.splitlines()
            if ln.startswith("EVENTS ")
        ),
        [],
    )
    return p, folder, events


def _keep(tmp_path) -> Path:
    return tmp_path / "vhir" / "config.yaml.keep"


def test_a_rerun_without_git_keeps_the_users_config(tmp_path):
    _install(tmp_path)
    p, folder, events = _run(tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert (folder / "pyproject.toml").read_text().strip() == "fresh"
    assert (folder / "config.yaml").read_text() == CONFIG
    assert not _keep(tmp_path).exists()
    assert "start-task:" + SERVER not in events  # Phase 6 starts the new one


@pytest.mark.parametrize("fail_at", ["download", "extract", "rename"])
def test_a_replace_that_fails_partway_puts_the_config_back_and_stops(tmp_path, fail_at):
    _install(tmp_path)
    p, folder, _ = _run(tmp_path, fail_at)
    assert p.returncode == 1, p.stdout + p.stderr
    assert (folder / "config.yaml").read_text() == CONFIG
    assert "ERR Failed to download wintools-mcp" in p.stdout
    assert "Your config.yaml was put back" in p.stdout
    assert not _keep(tmp_path).exists()


def test_a_config_that_cant_be_put_back_stays_saved_and_the_next_run_restores_it(
    tmp_path,
):
    _install(tmp_path)
    p, folder, events = _run(tmp_path, "copy-back")
    assert p.returncode == 1, p.stdout + p.stderr
    assert events.count("copy-back-failed") == 2, events  # the put-back and its retry
    assert not (folder / "config.yaml").exists()
    assert _keep(tmp_path).read_text() == CONFIG
    assert f"Your config.yaml is saved at {_keep(tmp_path)}" in p.stdout

    p, folder, _ = _run(tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "OK Put back the config.yaml an earlier run saved" in p.stdout
    assert (folder / "config.yaml").read_text() == CONFIG
    assert not _keep(tmp_path).exists()


def test_a_saved_config_that_differs_from_the_folders_stops_the_run_untouched(
    tmp_path,
):
    folder = _install(tmp_path, config="api_keys: {}\n")
    _keep(tmp_path).write_text(CONFIG)
    p, _, events = _run(tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert f"An earlier run saved config.yaml at {_keep(tmp_path)}" in p.stdout
    assert _keep(tmp_path).read_text() == CONFIG
    assert (folder / "config.yaml").read_text() == "api_keys: {}\n"
    assert events == []


def test_the_server_is_stopped_only_once_the_new_tree_is_ready(tmp_path):
    _install(tmp_path)
    _, _, events = _run(tmp_path)
    touched = [
        i
        for i, e in enumerate(events)
        if e.startswith(("disable-", "stop-", "find-processes"))
    ]
    assert f"stop-task:{SERVER}" in events and "stop-process" in events
    assert f"stop-task:{WATCHDOG}" not in events  # it wasn't running
    assert events.index("extract") < min(touched), events
    assert max(touched) < events.index("rename"), events


def test_the_watchdog_is_disabled_for_the_replace_and_enabled_after(tmp_path):
    _install(tmp_path)
    _, _, events = _run(tmp_path)
    for task in (SERVER, WATCHDOG):
        assert (
            events.index(f"disable-task:{task}")
            < events.index("rename")
            < events.index(f"enable-task:{task}")
        ), events


@pytest.mark.parametrize("fail_at", ["download", "extract"])
def test_a_download_that_fails_leaves_the_server_running(tmp_path, fail_at):
    _install(tmp_path)
    p, _, events = _run(tmp_path, fail_at)
    assert p.returncode == 1, p.stdout + p.stderr
    assert not [e for e in events if e.split(":")[0] in (
        "disable-task", "stop-task", "stop-process", "start-task")], events  # fmt: skip


def test_a_failure_after_the_stop_starts_the_server_again(tmp_path):
    _install(tmp_path)
    p, _, events = _run(tmp_path, "rename")
    assert p.returncode == 1, p.stdout + p.stderr
    assert events.index(f"stop-task:{SERVER}") < events.index("rename")
    after = events[events.index("rename") :]
    assert f"enable-task:{WATCHDOG}" in after and f"enable-task:{SERVER}" in after
    assert after.index(f"enable-task:{SERVER}") < after.index(f"start-task:{SERVER}")
    assert f"start-task:{WATCHDOG}" not in events


def test_a_watchdog_caught_running_is_stopped_and_left_to_its_trigger(tmp_path):
    _install(tmp_path)
    p, _, events = _run(tmp_path, "rename", watchdog_running=True)
    assert p.returncode == 1, p.stdout + p.stderr
    assert events.index(f"stop-task:{WATCHDOG}") < events.index("rename")
    assert f"start-task:{SERVER}" in events and f"start-task:{WATCHDOG}" not in events
    assert f"enable-task:{WATCHDOG}" in events[events.index("rename") :]


def test_a_server_without_a_task_is_started_from_its_startup_script(tmp_path):
    _install(tmp_path)
    (tmp_path / "vhir" / "start-wintools.ps1").write_text("")
    p, _, events = _run(tmp_path, "rename", no_tasks=True)
    assert p.returncode == 1, p.stdout + p.stderr
    assert events.index("stop-process") < events.index("rename")
    assert events.index("rename") < events.index("start-process"), events


def test_the_help_no_longer_offers_an_air_gapped_install():
    assert "Air-gapped lab" not in TEXT and "pre-staged directory" not in TEXT
    assert "needs\n    # internet access to both" in TEXT
