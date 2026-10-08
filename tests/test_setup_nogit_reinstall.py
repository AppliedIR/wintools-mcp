"""Re-running the installer without git swaps wintools-mcp's folder for a
fresh download: the previous one is kept as wintools-mcp.old until the new
one's environment is built (venv and pip), and comes back, running, when
anything fails before that. The examiner's config.yaml (its API key) comes
along. The running server is stopped only once the new tree is extracted,
waited on until it exits, and its tasks stay disabled until the window
closes, on any path out of it, a Ctrl+C included. The installer's own lines
run under PowerShell; the download, the archive, the scheduled tasks, the
processes and Python are stand-ins that record what happens, in order.
"""

from __future__ import annotations

import fcntl
import os
import select
import shutil
import subprocess
import termios
import time
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


def _between(start: str, end: str) -> str:
    i = TEXT.index(start)
    return TEXT[i : TEXT.index(end, i)]


def _block() -> str:
    """The installer's stop, swap and download helpers, the clone or
    download step, and the environment's build (the rollback window)."""
    return _between(
        '$wintoolsOldDir = "$wintoolsDir.old"', "# forensic-knowledge (FK) enrichment"
    )


def _trap() -> str:
    return _between("trap {", "\n}\n") + "\n}\n"


STUBS = r"""
$ErrorActionPreference = "Stop"
function Ev { param($e) Add-Content -Path $env:EVENTS -Value $e }
function Write-Ok { param($m) Write-Host "OK $m" }
function Write-Info { param($m) Write-Host "INFO $m" }
function Write-Warn { param($m) Write-Host "WARN $m" }
function Write-Err { param($m) Write-Host "ERR $m" }
function Get-ScheduledTask { param($TaskName, $ErrorAction)
    if ($env:NO_TASKS) { return }
    if ($TaskName -eq "Valhuntir wintools-mcp") { return [pscustomobject]@{ State = "Running" } }
    if ($TaskName -eq "Valhuntir wintools-mcp watchdog") {
        return [pscustomobject]@{ State = $(if ($env:WATCHDOG_RUNNING) { "Running" } else { "Ready" }) } } }
function Disable-ScheduledTask { param($TaskName, $ErrorAction) Ev "disable-task:$TaskName" }
function Enable-ScheduledTask { param($TaskName, $ErrorAction) Ev "enable-task:$TaskName" }
function Stop-ScheduledTask { param($TaskName, $ErrorAction) Ev "stop-task:$TaskName" }
function Start-ScheduledTask { param($TaskName, $ErrorAction) Ev "start-task:$TaskName" }
function Start-Process { param($FilePath, $ArgumentList, $WindowStyle) Ev "start-process" }
function Get-CimInstance { param($ClassName, $ErrorAction)
    $out = @([pscustomobject]@{ ProcessId = 200; ParentProcessId = 100; CommandLine = "python.exe -m wintools_mcp" })
    if ($env:LOOP) { $out += [pscustomobject]@{ ProcessId = 300; ParentProcessId = 1;
        CommandLine = "powershell.exe -File C:\Tools\vhir\start-wintools.ps1" } }
    $out }
function Get-Process { param([Parameter(Position=0)]$Name, $Id)
    if ($Id) { return [pscustomobject]@{ Id = $Id; Path = "C:\Python312\python.exe" } }
    Ev "find-processes"
    @([pscustomobject]@{ Id = 100; Path = "C:\Tools\vhir\wintools-mcp\.venv\Scripts\python.exe" }) }
function Stop-Process { param([Parameter(ValueFromPipeline=$true)]$InputObject, $Id, [switch]$Force)
    process { Ev "stop-process:$(if ($Id) { $Id } else { $InputObject.Id })" } }
function Wait-Process { param([Parameter(ValueFromPipeline=$true)]$InputObject, $Id, $Timeout)
    process { Ev "wait-process:$(if ($Id) { $Id } else { $InputObject.Id })" } }
function Start-Sleep { param($Seconds) if ($env:SLOW_RETRY) { Ev "retry-wait"; [System.Threading.Thread]::Sleep(500) } }
function Invoke-WebRequest { param($Uri, $OutFile, [switch]$UseBasicParsing, $TimeoutSec)
    Ev "download"
    if ($env:FAIL_AT -eq "download") { throw "GitHub can't be reached" }
    Set-Content -Path $OutFile -Value "zip" }
function Expand-Archive { param($Path, $DestinationPath, [switch]$Force)
    Ev "extract"
    if ($env:FAIL_AT -eq "extract") { throw "the archive is damaged" }
    $d = Join-Path $DestinationPath "wintools-mcp-main"; New-Item -ItemType Directory -Force -Path $d | Out-Null
    Set-Content -Path (Join-Path $d "pyproject.toml") -Value "fresh" }
function Rename-Item { param($Path, $NewName, $ErrorAction)
    $from = Split-Path $Path -Leaf
    Ev "rename:$from"
    if ($env:FAIL_RENAME -eq $from) { throw "a file in $from is in use" }
    Microsoft.PowerShell.Management\Rename-Item -Path $Path -NewName $NewName }
function Remove-Item { param($Path, [switch]$Recurse, [switch]$Force, $ErrorAction)
    if ($env:FAIL_REMOVE -and (Split-Path $Path -Leaf) -eq "wintools-mcp") { throw "a file in it is in use" }
    Microsoft.PowerShell.Management\Remove-Item -Path $Path -Recurse:$Recurse -Force:$Force -ErrorAction SilentlyContinue }
function Assert-Venv64 { param($p) Ev "assert-64" }
function Fake-Python {
    Ev "venv"
    if ($env:FAIL_AT -eq "venv") { throw "venv failed" }
    $py = Join-Path $args[-1] "Scripts\python.exe"
    New-Item -ItemType Directory -Force -Path (Join-Path $args[-1] "Scripts") | Out-Null
    Set-Content -Path $py -Value "#!/bin/sh`necho pip >> `"$env:EVENTS`"`n[ -n `"`$PIP_HANG`" ] && sleep 60`nexit `${PIP_EXIT:-0}"
    chmod +x $py }
$pythonCmd = "Fake-Python"
"""


def _install(tmp_path, *, config=CONFIG, old=False, current=True):
    install = tmp_path / "vhir"
    folders = [install / "wintools-mcp"] * current + [
        install / "wintools-mcp.old"
    ] * old
    for folder in folders:
        folder.mkdir(parents=True)
        if config is not None:
            (folder / "config.yaml").write_text(config)
        (folder / "pyproject.toml").write_text(folder.name)
    install.mkdir(parents=True, exist_ok=True)
    return install / "wintools-mcp"


def _script(tmp_path, after, env):
    install = tmp_path / "vhir"
    folder = install / "wintools-mcp"
    events = tmp_path / "events.txt"
    events.write_text("")
    script = tmp_path / "rerun.ps1"
    script.write_text(
        STUBS
        + f"$InstallDir = '{install}'\n$wintoolsDir = '{folder}'\n"
        + "$wintoolsConfigPath = Join-Path $wintoolsDir 'config.yaml'\n"
        + "$githubOrg = 'https://github.example.test/AppliedIR'\n$hasGit = $false\n"
        + "$process = $null\n"
        + _trap()
        + _block()
        + after,
        encoding="utf-8",
    )
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "EVENTS": str(events),
           **{k.upper(): v for k, v in env.items() if v}}  # fmt: skip
    return (
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        env,
        folder,
        events,
    )


def _run(tmp_path, after="", **env):
    cmd, env, folder, events = _script(tmp_path, after, env)
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
    return p, folder, events.read_text().splitlines()


def _interrupted(tmp_path, at: str, after="", **env):
    """Runs the installer's lines in a terminal and presses Ctrl+C once the
    event `at` is recorded: the events, and what the terminal showed."""
    cmd, env, folder, events = _script(tmp_path, after, env)
    master, slave = os.openpty()

    def own_terminal():
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    p = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, env=env,
                         start_new_session=True, preexec_fn=own_terminal)  # fmt: skip
    os.close(slave)
    shown, pressed, deadline = b"", False, time.monotonic() + 60
    while time.monotonic() < deadline and p.poll() is None:
        if select.select([master], [], [], 0.1)[0]:
            try:
                shown += os.read(master, 4096)
            except OSError:
                break
        if not pressed and at in events.read_text().splitlines():
            time.sleep(0.5)
            os.write(master, b"\x03")
            pressed = True
    if p.poll() is None:
        p.kill()
    p.wait(10)
    os.close(master)
    assert pressed, events.read_text()
    return folder, events.read_text().splitlines(), shown.decode(errors="replace")


def _old(tmp_path) -> Path:
    return tmp_path / "vhir" / "wintools-mcp.old"


def _is_previous(folder) -> bool:
    return (folder / "pyproject.toml").read_text().strip() == "wintools-mcp"


def test_a_rerun_without_git_swaps_in_the_new_tree_with_the_users_config(tmp_path):
    _install(tmp_path)
    p, folder, events = _run(tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert (folder / "pyproject.toml").read_text().strip() == "fresh"
    assert (folder / "config.yaml").read_text() == CONFIG
    assert not _old(tmp_path).exists()
    assert "pip" in events and "start-task:" + SERVER not in events


@pytest.mark.parametrize("fail_at", ["venv", "pip"])
def test_a_failure_after_the_swap_before_pip_brings_the_previous_one_back_running(
    tmp_path, fail_at
):
    _install(tmp_path)
    env = {"fail_at": "venv"} if fail_at == "venv" else {"pip_exit": "1"}
    p, folder, events = _run(tmp_path, **env)
    assert p.returncode == 1, p.stdout + p.stderr
    assert _is_previous(folder) and (folder / "config.yaml").read_text() == CONFIG
    assert not _old(tmp_path).exists() and not (folder / ".venv").exists()
    assert "the previous wintools-mcp is back" in p.stdout
    back = events.index("rename:wintools-mcp.old")
    assert events.index(f"enable-task:{SERVER}") > back
    assert events.index(f"start-task:{SERVER}") > events.index(f"enable-task:{SERVER}")


def test_a_rollback_that_cant_remove_the_new_tree_says_what_to_keep(tmp_path):
    _install(tmp_path)
    p, folder, _ = _run(tmp_path, pip_exit="1", fail_remove="1")
    assert p.returncode == 1, p.stdout + p.stderr
    assert folder.exists() and _old(tmp_path).exists()
    assert (
        f"The new one is still at {folder} and the previous one at {_old(tmp_path)}: "
        f"keep the one that works as {folder}, remove the other, and re-run."
    ) in p.stdout
    assert "the next run puts it back" not in p.stdout


@pytest.mark.parametrize("fail_at", ["download", "extract"])
def test_a_download_that_fails_leaves_the_server_running(tmp_path, fail_at):
    _install(tmp_path)
    p, folder, events = _run(tmp_path, fail_at=fail_at)
    assert p.returncode == 1, p.stdout + p.stderr
    assert _is_previous(folder) and not _old(tmp_path).exists()
    assert not [e for e in events if e.split(":")[0] in (
        "disable-task", "stop-task", "stop-process", "start-task")], events  # fmt: skip


def test_a_folder_held_open_is_left_as_it_is_and_its_server_started_again(tmp_path):
    _install(tmp_path)
    p, folder, events = _run(tmp_path, fail_rename="wintools-mcp")
    assert p.returncode == 1, p.stdout + p.stderr
    assert _is_previous(folder) and (folder / "config.yaml").read_text() == CONFIG
    assert not (tmp_path / "vhir" / "wintools-mcp-main").exists()
    assert "is in use, so it was left as it is" in p.stdout
    assert events.count("rename:wintools-mcp") == 5  # tried again before giving up
    assert events.index(f"enable-task:{SERVER}") < events.index(f"start-task:{SERVER}")


def test_a_new_tree_that_cant_be_put_in_place_keeps_the_previous_one(tmp_path):
    _install(tmp_path)
    p, folder, events = _run(tmp_path, fail_rename="wintools-mcp-main")
    assert p.returncode == 1, p.stdout + p.stderr
    assert _is_previous(folder) and not _old(tmp_path).exists()
    assert "so the previous one was kept" in p.stdout
    assert f"start-task:{SERVER}" in events


def test_a_leftover_old_folder_without_the_folder_is_put_back_first(tmp_path):
    _install(tmp_path, old=True, current=False)
    p, folder, _ = _run(tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "OK Put back the wintools-mcp an earlier update left at" in p.stdout
    assert (folder / "config.yaml").read_text() == CONFIG  # carried from it
    assert not _old(tmp_path).exists()


def test_a_leftover_old_folder_beside_the_folder_stops_the_run_untouched(tmp_path):
    folder = _install(tmp_path, old=True)
    p, _, events = _run(tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert f"Both {folder} and {_old(tmp_path)} exist" in p.stdout
    assert _is_previous(folder) and _old(tmp_path).exists() and events == []


def test_the_server_is_stopped_only_once_the_new_tree_is_ready_and_waited_on(tmp_path):
    _install(tmp_path)
    _, _, events = _run(tmp_path, loop="1")
    touched = [
        i
        for i, e in enumerate(events)
        if e.split(":")[0] in ("disable-task", "stop-task")
    ]
    assert events.index("extract") < min(touched)
    stops = ["stop-process:300", "stop-process:100", "stop-process:200"]
    order = [events.index(s) for s in stops]
    assert order == sorted(order), events  # the loop, the launcher, its child
    assert events.index("wait-process:300") < events.index("stop-process:100")
    assert events.index("wait-process:200") < events.index("rename:wintools-mcp")
    assert f"stop-task:{WATCHDOG}" not in events  # it wasn't running


def test_the_tasks_stay_disabled_until_the_environment_is_built(tmp_path):
    _install(tmp_path)
    _, _, events = _run(tmp_path)
    for task in (SERVER, WATCHDOG):
        assert (
            events.index(f"disable-task:{task}")
            < events.index("rename:wintools-mcp")
            < events.index("pip")
            < events.index(f"enable-task:{task}")
        ), events


def test_a_ctrl_c_at_a_later_prompt_leaves_the_tasks_enabled(tmp_path):
    _install(tmp_path)
    folder, events, _ = _interrupted(
        tmp_path, "asking", after='Ev "asking"\n$null = Read-Host "Examiner name"\n'
    )
    assert f"enable-task:{SERVER}" in events and f"enable-task:{WATCHDOG}" in events
    assert events.index(f"enable-task:{WATCHDOG}") < events.index("asking")
    assert (folder / "pyproject.toml").read_text().strip() == "fresh"


def test_a_ctrl_c_during_pip_rolls_back_and_enables_the_tasks(tmp_path):
    _install(tmp_path)
    folder, events, _ = _interrupted(tmp_path, "pip", pip_hang="1")
    assert _is_previous(folder) and (folder / "config.yaml").read_text() == CONFIG
    assert not _old(tmp_path).exists()
    after = events[events.index("pip") :]
    assert "rename:wintools-mcp.old" in after
    assert after.index(f"enable-task:{SERVER}") < after.index(f"start-task:{SERVER}")
    assert f"enable-task:{WATCHDOG}" in after


def test_a_ctrl_c_before_the_window_puts_the_server_back_as_it_was(tmp_path):
    _install(tmp_path)
    folder, events, _ = _interrupted(
        tmp_path, "retry-wait", fail_rename="wintools-mcp", slow_retry="1"
    )
    assert _is_previous(folder) and not _old(tmp_path).exists()
    after = events[events.index("retry-wait") :]
    assert after.index(f"enable-task:{SERVER}") < after.index(f"start-task:{SERVER}")
    assert f"enable-task:{WATCHDOG}" in after


def test_a_watchdog_caught_running_is_stopped_and_left_to_its_trigger(tmp_path):
    _install(tmp_path)
    p, _, events = _run(tmp_path, pip_exit="1", watchdog_running="1")
    assert p.returncode == 1, p.stdout + p.stderr
    assert events.index(f"stop-task:{WATCHDOG}") < events.index("rename:wintools-mcp")
    assert f"start-task:{SERVER}" in events and f"start-task:{WATCHDOG}" not in events


def test_a_server_without_a_task_is_started_from_its_startup_script(tmp_path):
    _install(tmp_path)
    (tmp_path / "vhir" / "start-wintools.ps1").write_text("")
    p, _, events = _run(tmp_path, pip_exit="1", no_tasks="1")
    assert p.returncode == 1, p.stdout + p.stderr
    assert events.index("stop-process:100") < events.index("rename:wintools-mcp")
    assert events.index("rename:wintools-mcp.old") < events.index("start-process")


def test_the_whole_installer_parses():
    """A line no row runs still has to parse: PowerShell reads the whole
    file before it runs any of it."""
    p = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command",
         "$e = $null; $null = [System.Management.Automation.Language.Parser]::ParseFile("
         f"'{SCRIPT}', [ref]$null, [ref]$e); $e | ForEach-Object {{ "
         "\"$($_.Extent.StartLineNumber): $($_.Message)\" }"],
        capture_output=True, text=True, timeout=120,
    )  # fmt: skip
    assert p.returncode == 0 and p.stdout.strip() == "", p.stdout + p.stderr


def test_the_help_no_longer_offers_an_air_gapped_install():
    assert "Air-gapped lab" not in TEXT and "pre-staged directory" not in TEXT
    assert "needs\n    # internet access to both" in TEXT
