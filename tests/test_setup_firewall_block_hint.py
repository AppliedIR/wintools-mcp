"""When the SIFT gateway can't reach wintools-mcp at the end of the install
and Windows Firewall has enabled inbound Block rules for wintools-mcp's
Python (Cancel on the Windows Security Alert writes them), the summary names
the rules and the command that removes them, and says no new join code is
needed: the gateway's own "join again" hint doesn't fit this cause. Without
such rules the warning is the one it always was. The installer never removes
the rules itself. The installer's own lines run under PowerShell; the
gateway, the firewall and the waits are stand-ins.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "setup-windows.ps1"
TEXT = SCRIPT.read_text(encoding="utf-8")

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="PowerShell isn't installed"
)

BASE = r"C:\Program Files\Python312"
GATEWAY_TEXT = (
    "no answer in 5s (it is kept until the gateway restarts; after a restart,"
    " join again with a new join code)"
)


def _between(start: str, end: str) -> str:
    i = TEXT.index(start)
    return TEXT[i : TEXT.index(end, i)]


def _function(name: str) -> str:
    return _between(f"function {name} {{", "\n}\n") + "\n}\n"


STUBS = r"""
$ErrorActionPreference = "Stop"
function Write-Ok { param($m) Write-Host "OK $m" }
function Write-Warn { param($m) Write-Host "WARN $m" }
function Start-Sleep { param($Seconds) }
function Invoke-RestMethod { param($Uri, $TimeoutSec, [switch]$UseBasicParsing, $ErrorAction)
    if (-not $env:STUB_HEALTH) { throw "Unable to connect to the remote server" }
    $env:STUB_HEALTH | ConvertFrom-Json }
function Get-NetFirewallRule { [CmdletBinding()] param($Direction, $Action, $Enabled)
    Write-Host "RULES Direction=$Direction Action=$Action Enabled=$Enabled"
    foreach ($r in ($env:STUB_RULES | ConvertFrom-Json)) { $r } }
function Get-NetFirewallApplicationFilter { [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$Rule)
    process { [pscustomobject]@{ Program = $Rule.prog } } }
function Remove-NetFirewallRule { Write-Host "REMOVED $args" }
function Disable-NetFirewallRule { Write-Host "DISABLED $args" }
"""


def _run(tmp_path: Path, rules: list, health: dict | None = None) -> tuple[int, str]:
    venv = tmp_path / ".venv"
    (venv / "Scripts").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text(
        f"home = {BASE}\ninclude-system-site-packages = false\nversion = 3.12.7\n"
    )
    run = tmp_path / "summary.ps1"
    run.write_text(
        STUBS
        + _function("Format-Quoted")
        + _function("Get-VenvBasePython")
        + _function("Get-ProgramBlockRules")
        + "$venvPython = Join-Path $env:STUB_VENV 'Scripts\\python.exe'\n"
        + "$joinSucceeded = $true; $siftIp = '10.0.1.91'; $siftPort = 4508\n"
        + "$gatewayScheme = 'https'; $GatewayCertSha256 = $null; $notFinished = @()\n"
        + _between(
            "if ($joinSucceeded) {\n    # The gateway loads", "\nif ($skipServerStart)"
        )
        + '\n"NOT FINISHED: $($notFinished -join "; ")"\n',
        encoding="utf-8",
    )
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(run)],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "STUB_VENV": str(venv),
            "STUB_RULES": json.dumps(rules),
            "STUB_HEALTH": json.dumps(health) if health else "",
        },
        timeout=120,
    )
    return r.returncode, r.stdout + r.stderr


CANCELLED = [
    {
        "Name": "TCP Query User{8C1F0B2E-1A}C:\\program files\\python312\\python.exe",
        "DisplayName": "Python",
        "prog": "C:\\program files\\python312\\python.exe",
    },
    {
        "Name": "UDP Query User{3D9E7C41-2B}C:\\program files\\python312\\python.exe",
        "DisplayName": "Python",
        "prog": "C:\\program files\\python312\\python.exe",
    },
]
OTHER = [{"Name": "{A1}", "DisplayName": "Firefox", "prog": "C:\\ff\\firefox.exe"}]
UNREACHED = {"backends": {"wintools-mcp": {"status": "error", "error": GATEWAY_TEXT}}}


@pytest.mark.parametrize("health", [UNREACHED, None], ids=["gateway-text", "no-answer"])
def test_cancelled_alert_names_the_block_rules_and_the_remove_command(tmp_path, health):
    rc, out = _run(tmp_path, CANCELLED + OTHER, health)
    assert rc == 0, out
    assert "RULES Direction=Inbound Action=Block Enabled=True" in out
    assert (
        "WARN Windows Firewall is blocking wintools-mcp:"
        " the Windows Security Alert was cancelled." in out
    )
    for rule in CANCELLED:
        assert (
            f"  Block rule 'Python' for {rule['prog']} (name {rule['Name']})" in out
        ), out
    names = ",".join(f"'{r['Name']}'" for r in CANCELLED)
    assert f"  As Administrator, run: Remove-NetFirewallRule -Name {names}\n" in out
    assert "no new join code is needed" in out
    assert "join again" not in out and "Firefox" not in out
    assert "REMOVED" not in out and "DISABLED" not in out  # never removed here
    assert "NOT FINISHED: the SIFT gateway can't use wintools-mcp" in out


@pytest.mark.parametrize("rules", [[], OTHER], ids=["no-rules", "other-program"])
def test_without_block_rules_the_warning_is_unchanged(tmp_path, rules):
    rc, out = _run(tmp_path, rules, UNREACHED)
    assert rc == 0, out
    assert f"WARN The SIFT gateway can't use wintools-mcp: {GATEWAY_TEXT}" in out
    assert "Windows Firewall is blocking" not in out
    assert "Remove-NetFirewallRule" not in out


def test_a_rule_for_the_venv_python_counts_too(tmp_path):
    venv_python = str(tmp_path / ".venv" / "Scripts" / "python.exe")
    rules = [{"Name": "{V1}", "DisplayName": "python", "prog": venv_python.upper()}]
    rc, out = _run(tmp_path, rules, UNREACHED)
    assert rc == 0, out
    assert "As Administrator, run: Remove-NetFirewallRule -Name '{V1}'" in out


def test_a_reachable_gateway_checks_no_rules(tmp_path):
    health = {"backends": {"wintools-mcp": {"status": "ok"}}}
    rc, out = _run(tmp_path, CANCELLED, health)
    assert rc == 0, out
    assert "OK The SIFT gateway reaches wintools-mcp" in out
    assert "RULES" not in out and "Windows Firewall" not in out
