"""The wintools task and its watchdog run with no time limit. Task Scheduler's
default limit (3 days) stops a task's process when it runs out, so a task
registered without one ends wintools every 3 days. Every settings set the
installer builds says -ExecutionTimeLimit 0, and -Update removes the limit
from tasks an older install registered. The installer's own blocks run under
PowerShell with stand-in ScheduledTasks cmdlets that record what was asked.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "setup-windows.ps1"
TEXT = SCRIPT.read_text(encoding="utf-8")
MAIN = "Valhuntir wintools-mcp"
WATCHDOG = "Valhuntir wintools-mcp watchdog"

pwsh = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="PowerShell isn't installed"
)

# Stand-ins for the ScheduledTasks module. A settings set reports its limit
# in the task XML's form (PT72H when none is given, the default).
STUBS = r"""
$global:log = [System.Collections.Generic.List[string]]::new()
$global:tasks = @{}
$global:failSet = $false
function Write-Ok { param($m) $global:log.Add("OK $m") }
function Write-Warn { param($m) $global:log.Add("WARN $m") }
function Write-Info { param($m) $global:log.Add("INFO $m") }
function Add-Task([string]$n, [string]$limit) {
    $global:tasks[$n] = [pscustomobject]@{
        TaskName = $n
        Settings = [pscustomobject]@{ ExecutionTimeLimit = $limit }
        Actions = @([pscustomobject]@{ Execute = "powershell.exe"; Arguments = "-File x" })
    }
}
function Get-ScheduledTask {
    [CmdletBinding()] param([string]$TaskName)
    if ($global:tasks.ContainsKey($TaskName)) { return $global:tasks[$TaskName] }
    Write-Error "No task $TaskName"
}
function Set-ScheduledTask {
    [CmdletBinding()] param($InputObject)
    if ($global:failSet) { throw "Access is denied" }
    $global:log.Add("set $($InputObject.TaskName) $($InputObject.Settings.ExecutionTimeLimit)")
}
function New-ScheduledTaskSettingsSet {
    [CmdletBinding()] param(
        [switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries,
        [switch]$StartWhenAvailable, [int]$RestartCount, [TimeSpan]$RestartInterval,
        [TimeSpan]$ExecutionTimeLimit)
    $limit = "PT72H"
    if ($PSBoundParameters.ContainsKey("ExecutionTimeLimit")) {
        $limit = [System.Xml.XmlConvert]::ToString($ExecutionTimeLimit)
    }
    [pscustomobject]@{ ExecutionTimeLimit = $limit }
}
function Register-ScheduledTask {
    [CmdletBinding()] param($TaskName, $Action, $Trigger, $Settings, $RunLevel, $User, $Description)
    $global:log.Add("register $TaskName $($Settings.ExecutionTimeLimit)")
    Add-Task $TaskName $Settings.ExecutionTimeLimit
    $global:tasks[$TaskName]
}
function Unregister-ScheduledTask {
    [CmdletBinding(SupportsShouldProcess)] param($TaskName)
    $global:tasks.Remove($TaskName)
}
function Stop-ScheduledTask { [CmdletBinding()] param($TaskName) $global:log.Add("stop $TaskName") }
function Start-ScheduledTask { [CmdletBinding()] param($TaskName) $global:log.Add("start $TaskName") }
function New-ScheduledTaskAction { [CmdletBinding()] param($Execute, $Argument) "action" }
function New-ScheduledTaskTrigger {
    [CmdletBinding()] param([switch]$AtStartup, [switch]$Once, $At, $RepetitionInterval, $RepetitionDuration)
    "trigger"
}
"""


def _cut(start: str, end: str) -> str:
    a = TEXT.index(start)
    return TEXT[a : TEXT.index(end, a)]


def _update_block() -> str:
    return _cut("    # 5. Restart via scheduled task", "    # 7. Version check")


def _install_block() -> str:
    body = _cut(
        "    if ($serverHealthy) {", '    } else {\n        Write-Warn "Server did not'
    )
    return body + "    }\n"


def _run(tmp_path: Path, setup: str, body: str) -> list[str]:
    script = tmp_path / "check.ps1"
    script.write_text(
        STUBS
        + f'$InstallDir = "{tmp_path}"\n$Port = 4624\n$wintoolsProcs = $null\n'
        + '$venvPython = "python"\n'
        + setup
        + "\n"
        + body
        + '\n$global:log | ForEach-Object { Write-Host "LOG $_" }\n',
        encoding="utf-8",
    )
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True,
        text=True,
        timeout=120,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
    )
    assert r.returncode == 0, r.stdout + r.stderr
    return [line[4:] for line in r.stdout.splitlines() if line.startswith("LOG ")]


def _files(tmp_path: Path, *names: str) -> None:
    for name in names:
        (tmp_path / name).write_text("# stand-in\n", encoding="utf-8")


def test_every_settings_set_the_installer_builds_has_no_time_limit():
    calls = [m.start() for m in re.finditer(r"New-ScheduledTaskSettingsSet", TEXT)]
    assert len(calls) == 5
    for at in calls:
        call = TEXT[at : TEXT.index("Register-ScheduledTask", at)]
        assert "-ExecutionTimeLimit ([TimeSpan]::Zero)" in call, call


@pwsh
def test_update_removes_the_limit_from_both_existing_tasks(tmp_path):
    log = _run(
        tmp_path,
        f'Add-Task "{MAIN}" "PT72H"\nAdd-Task "{WATCHDOG}" "PT72H"',
        _update_block(),
    )
    assert f"set {MAIN} PT0S" in log
    assert f"set {WATCHDOG} PT0S" in log
    assert log.index(f"set {MAIN} PT0S") < log.index(f"start {MAIN}")
    assert not any(line.startswith(("register", "WARN")) for line in log), log


@pwsh
def test_update_renaming_an_old_task_registers_it_with_no_limit(tmp_path):
    log = _run(
        tmp_path,
        f'Add-Task "AIIR wintools-mcp" "PT72H"\nAdd-Task "{WATCHDOG}" "PT72H"',
        _update_block(),
    )
    assert f"register {MAIN} PT0S" in log
    assert f"start {MAIN}" in log
    assert f"set {WATCHDOG} PT0S" in log


@pwsh
def test_update_recreating_both_tasks_registers_them_with_no_limit(tmp_path):
    _files(tmp_path, "start-wintools.ps1", "watchdog-wintools.ps1")
    log = _run(tmp_path, "", _update_block())
    assert f"register {MAIN} PT0S" in log
    assert f"register {WATCHDOG} PT0S" in log


@pwsh
def test_update_still_restarts_wintools_when_the_limit_cannot_be_changed(tmp_path):
    log = _run(
        tmp_path,
        f'Add-Task "{MAIN}" "PT72H"\nAdd-Task "{WATCHDOG}" "PT72H"\n'
        "$global:failSet = $true",
        _update_block(),
    )
    assert f"start {MAIN}" in log
    assert "OK Scheduled task restarted" in log
    warns = [line for line in log if line.startswith("WARN")]
    assert len(warns) == 2, log
    assert all("time limit" in w and "Access is denied" in w for w in warns)


@pwsh
def test_install_registers_both_tasks_with_no_limit(tmp_path):
    _files(tmp_path, "start-wintools.ps1", "watchdog-wintools.ps1")
    log = _run(
        tmp_path,
        f'$taskName = "{MAIN}"\n$serverHealthy = $true\n'
        f'$startupPath = "{tmp_path}/start-wintools.ps1"\n'
        f'$watchdogPath = "{tmp_path}/watchdog-wintools.ps1"\n'
        f'Add-Task "{MAIN}" "PT72H"\nAdd-Task "{WATCHDOG}" "PT72H"',
        _install_block(),
    )
    assert f"register {MAIN} PT0S" in log
    assert f"register {WATCHDOG} PT0S" in log
    assert not any(line.startswith("WARN") for line in log), log
