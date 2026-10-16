"""Two install-screen hints. The tool scan's [MISSING] lines are printed once:
the line after the scan counts them instead of listing them again. When the
case share can't be mapped, the manual net use line says where its
<password> is kept (smb_password in config.yaml) and never prints it. The
installer's own lines run under PowerShell; the scan, the join's password and
net are stand-ins.
"""

from __future__ import annotations

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

STUBS = r"""
$ErrorActionPreference = "Stop"
function Write-Info { param($m) Write-Host "INFO $m" }
function Write-Ok { param($m) Write-Host "OK $m" }
function Write-Warn { param($m) Write-Host "WARN $m" }
function Read-Host { param($m) Write-Host "PROMPT $m"; "" }
"""


def _between(start: str, end: str) -> str:
    i = TEXT.index(start)
    return TEXT[i : TEXT.index(end, i)]


def _pwsh(tmp_path: Path, body: str, env: dict) -> tuple[int, str]:
    run = tmp_path / "run.ps1"
    run.write_text(STUBS + body, encoding="utf-8")
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(run)],
        capture_output=True,
        text=True,
        env={**os.environ, **env},
        timeout=120,
    )
    return r.returncode, r.stdout + r.stderr


SCAN = [
    "wintools-mcp Tool Inventory",
    "Category: registry (2 tools)",
    "  [OK] RECmd.exe                 C:\\Tools\\RECmd.exe",
    "  [MISSING] AmcacheParser.exe   Install: winget install EricZimmerman.Tools",
    "  [MISSING] hayabusa.exe        Install: https://github.com/Yamato-Security",
    "Summary: 1/3 tools available, 2 missing",
]

SCAN_BLOCK = (
    "$NonInteractive = [bool]$env:NONINTERACTIVE\n"
    '$scanOutput = $env:SCAN -split "\\n"\n'
    + _between(
        "$missingCount = 0\n$extraToolPaths = @()",
        "\n# Generate TOOLS_OVERVIEW.md",
    )
)


@pytest.mark.parametrize(
    "noninteractive", ["", "1"], ids=["interactive", "-NonInteractive"]
)
def test_missing_tools_are_listed_once(tmp_path, noninteractive):
    rc, out = _pwsh(
        tmp_path,
        SCAN_BLOCK,
        {"SCAN": "\n".join(SCAN), "NONINTERACTIVE": noninteractive},
    )
    assert rc == 0, out
    for line in SCAN:
        assert out.count(line) == 1, (line, out)
    assert "    - AmcacheParser.exe" not in out
    counted = (
        "  2 tool(s) marked [MISSING] above weren't found in the default search paths."
    )
    assert (counted in out) == (not noninteractive)
    assert ("PROMPT" in out) == (not noninteractive)


PASSWORD = "Derived-Secret-Value-1"

SHARE_BLOCK = (
    r"""
function Derive-SMBPassword { param($JoinCode) $env:PW }
function Get-PreviousShareRoot { param($p) $null }
function Select-ShareLetter { param($SmbHost, $PreviousShareRoot)
    if ($env:LETTER) { @{ Letter = $env:LETTER } }
    else { @{ Letter = $null; Why = "every letter from S: to Z: is in use" } } }
function net { $global:LASTEXITCODE = [int]$env:NET_RC
    if ($env:NET_RC -ne "0") { "System error 53 has occurred." } }
$joinSucceeded = $true; $joinCodeValue = "ABCD-EFGH"
$joinData = [pscustomobject]@{ smb_share = "cases"; smb_host = "10.0.1.91"; smb_user = "vhir" }
$wintoolsConfigPath = "C:\Tools\vhir\wintools-mcp\config.yaml"
$smbMapped = $false
"""
    + _between(
        "    # Drive mapping -- only if join succeeded",
        "\n    $derivedPw = $null",
    )
    + '\n"MAPPED $smbMapped"\n'
)

WHERE = "  <password> is smb_password in C:\\Tools\\vhir\\wintools-mcp\\config.yaml."


@pytest.mark.parametrize(
    ("letter", "net_rc", "hint"),
    [
        ("", "0", "  net use <LETTER>: \\\\10.0.1.91\\cases /user:vhir <password>"),
        (
            "S",
            "2",
            "  Map manually: net use S: \\\\10.0.1.91\\cases /user:vhir <password>",
        ),
    ],
    ids=["no-free-letter", "net-use-failed"],
)
def test_the_manual_hint_says_where_the_password_is(tmp_path, letter, net_rc, hint):
    rc, out = _pwsh(
        tmp_path, SHARE_BLOCK, {"PW": PASSWORD, "LETTER": letter, "NET_RC": net_rc}
    )
    assert rc == 0, out
    lines = out.splitlines()
    i = next(n for n, x in enumerate(lines) if x.startswith(hint))
    assert lines[i + 1] == WHERE
    assert PASSWORD not in out
    assert "MAPPED False" in out


def test_a_mapped_share_prints_no_hint(tmp_path):
    rc, out = _pwsh(
        tmp_path, SHARE_BLOCK, {"PW": PASSWORD, "LETTER": "S", "NET_RC": "0"}
    )
    assert rc == 0, out
    assert "OK Mapped S: to \\\\10.0.1.91\\cases" in out and "MAPPED True" in out
    assert "<password>" not in out and PASSWORD not in out
