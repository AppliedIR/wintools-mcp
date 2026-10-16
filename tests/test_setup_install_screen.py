"""What the install screen shows. Interactive mode doesn't ask again for the
join code, SIFT address and port the command line gave. A pip step that
fails shows pip's last lines (its reason), and one that works shows none of
them. Each pip step is announced before it runs, since it can take minutes.
The gateway URL clients use carries the scheme, address and port this run
knows. The installer's own lines run under PowerShell; Python is a
stand-in script that prints and exits as the test asks.
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
    shutil.which("pwsh") is None or shutil.which("bash") is None,
    reason="PowerShell or bash isn't installed",
)


def _between(start: str, end: str) -> str:
    i = TEXT.index(start)
    return TEXT[i : TEXT.index(end, i)]


def _function(name: str) -> str:
    return _between(f"function {name} {{", "\n}\n") + "\n}\n"


WRITE = r"""
$ErrorActionPreference = "Stop"
function Ev { param($e) Add-Content -Path $env:EVENTS -Value $e }
function Write-Info { param($m) Ev "INFO $m"; Write-Host "INFO $m" }
function Write-Ok { param($m) Write-Host "OK $m" }
function Write-Warn { param($m) Write-Host "WARN $m" }
function Write-Err { param($m) Write-Host "ERR $m" }
"""


def _pwsh(tmp_path: Path, body: str, env: dict) -> tuple[int, str]:
    run = tmp_path / "run.ps1"
    run.write_text(WRITE + body, encoding="utf-8")
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(run)],
        capture_output=True,
        text=True,
        env={**os.environ, "EVENTS": str(tmp_path / "events"), **env},
        timeout=120,
    )
    return r.returncode, r.stdout + r.stderr


def _events(tmp_path: Path) -> list[str]:
    path = tmp_path / "events"
    return path.read_text().splitlines() if path.exists() else []


# --- the join prompts --------------------------------------------------------

PROMPTS = (
    _function("Read-Prompt")
    + _function("Read-YesNo")
    + r"""
$script:answers = [System.Collections.Queue]::new()
foreach ($a in ($env:ANSWERS -split ";")) { if ($a -ne "<none>") { $script:answers.Enqueue($a) } }
function Read-Host { param($m) Write-Host "PROMPT $m"
    if ($script:answers.Count) { $script:answers.Dequeue() } else { "" } }
$NonInteractive = $false
$JoinCode = $env:P_CODE; $GatewayHost = $env:P_HOST; $GatewayPort = [int]$env:P_PORT
$gatewayScheme = "http"; $siftIp = ""; $siftPort = ""; $joinCodeValue = ""
"""
    + _between(
        "    if ($NonInteractive) {\n        $siftIp = $GatewayHost",
        "\n    # Reachability check",
    )
    + '\n"GOT code=[$joinCodeValue] ip=[$siftIp] port=[$siftPort]"\n'
)


def _join(tmp_path, code="", host="", port="4508", answers="<none>"):
    return _pwsh(
        tmp_path,
        PROMPTS,
        {"P_CODE": code, "P_HOST": host, "P_PORT": port, "ANSWERS": answers},
    )


def test_values_the_command_line_gave_are_not_asked_again(tmp_path):
    rc, out = _join(tmp_path, code="ABCD-EFGH", host="10.0.1.91", port="14516")
    assert rc == 0, out
    assert "PROMPT" not in out
    assert "GOT code=[ABCD-EFGH] ip=[10.0.1.91] port=[14516]" in out
    assert "SIFT gateway: 10.0.1.91:14516 (from the command line)" in out


def test_with_nothing_given_every_value_is_asked_as_before(tmp_path):
    rc, out = _join(tmp_path, answers="ABCD-EFGH;10.0.1.91;;y")
    assert rc == 0, out
    assert "PROMPT Join code from SIFT workstation (blank to skip)" in out
    assert "PROMPT SIFT workstation IP" in out
    assert "PROMPT SIFT gateway port [4508]" in out
    assert "PROMPT Correct? [Y/n]" in out
    assert "GOT code=[ABCD-EFGH] ip=[10.0.1.91] port=[4508]" in out


def test_a_given_join_code_alone_asks_only_for_the_address(tmp_path):
    rc, out = _join(tmp_path, code="ABCD-EFGH", answers="10.0.1.91;;y")
    assert rc == 0, out
    assert "PROMPT Join code" not in out
    assert "PROMPT SIFT workstation IP" in out
    assert "GOT code=[ABCD-EFGH] ip=[10.0.1.91] port=[4508]" in out


def test_a_given_name_that_resolves_is_used_without_a_prompt(tmp_path):
    rc, out = _join(tmp_path, code="ABCD-EFGH", host="localhost", port="14516")
    assert rc == 0, out
    assert "PROMPT" not in out
    assert "OK Resolved 'localhost' to 127.0.0.1" in out
    assert "SIFT gateway: 127.0.0.1:14516 (from the command line)" in out


def test_an_address_typed_for_a_given_name_that_does_not_resolve_is_confirmed(
    tmp_path,
):
    """The address was typed, not given: its port and Correct? are asked."""
    rc, out = _join(
        tmp_path,
        code="ABCD-EFGH",
        host="sift.invalid",
        port="14516",
        answers="10.0.1.92;;y",
    )
    assert rc == 0, out
    assert "PROMPT Enter the SIFT workstation IP address directly" in out
    assert "PROMPT SIFT gateway port [14516]" in out
    assert "PROMPT Correct? [Y/n]" in out
    assert "(from the command line)" not in out
    assert "GOT code=[ABCD-EFGH] ip=[10.0.1.92] port=[14516]" in out


def test_a_blank_for_a_given_name_that_does_not_resolve_asks_for_the_address(
    tmp_path,
):
    """No port or Correct? is asked for an empty address; the address is."""
    rc, out = _join(
        tmp_path, code="ABCD-EFGH", host="sift.invalid", answers=";10.0.1.93;;y"
    )
    assert rc == 0, out
    lines = [x for x in out.splitlines() if x.startswith("PROMPT")]
    assert lines == [
        "PROMPT Enter the SIFT workstation IP address directly",
        "PROMPT SIFT workstation IP",
        "PROMPT SIFT gateway port [4508]",
        "PROMPT Correct? [Y/n]",
    ], out
    assert "SIFT gateway: :" not in out
    assert "GOT code=[ABCD-EFGH] ip=[10.0.1.93] port=[4508]" in out


def test_a_given_address_without_a_join_code_is_not_used_for_a_skip(tmp_path):
    """Blank at the join code skips the join, as before."""
    rc, out = _join(tmp_path, host="10.0.1.91", answers="")
    assert rc == 0, out
    assert "PROMPT Join code from SIFT workstation (blank to skip)" in out
    assert "GOT code=[] ip=[] port=[]" in out


# --- pip -----------------------------------------------------------------------

FAKE_PYTHON = r"""#!/usr/bin/env bash
echo "CALL $*" >> "$EVENTS"
case " $* " in
  *" -c "*) exit "${IMPORT_RC:-0}" ;;
esac
if [[ " $* " == *"$PIP_FAIL_ON"* && -n "$PIP_FAIL_ON" ]]; then
  for i in $(seq 1 30); do echo "pip line $i"; done
  # stdout and stderr are separate pipes: let stdout drain so pip's last
  # line (its reason, on stderr) stays last, as it is from pip itself
  sleep 0.5
  echo "ERROR: does not appear to be a Python project: neither setup.py nor pyproject.toml found." >&2
  sleep 0.2
  exit 1
fi
echo "Successfully installed quietly"
"""


def _python(tmp_path: Path) -> Path:
    exe = tmp_path / "python"
    exe.write_text(FAKE_PYTHON)
    exe.chmod(0o755)
    return exe


INSTALL = (
    _function("Write-OutputTail")
    + "$venvPython = $env:FAKE_PY; $wintoolsDir = $env:WT_DIR\n"
    + "try {\n"
    + _between(
        '    Write-Info "Updating pip in wintools-mcp\'s environment..."',
        "    $installed = $true",
    )
    + '    "reached the end of the install step"\n} finally { }\n'
)


def _install(tmp_path, fail_on=""):
    return _pwsh(
        tmp_path,
        INSTALL,
        {
            "FAKE_PY": str(_python(tmp_path)),
            "WT_DIR": str(tmp_path / "wt"),
            "PIP_FAIL_ON": fail_on,
        },
    )


def test_a_failed_wintools_install_shows_pips_reason(tmp_path):
    rc, out = _install(tmp_path, fail_on=" -e ")
    assert rc == 1, out
    assert "ERR Failed to install wintools-mcp: pip install failed (exit 1)" in out
    assert (
        "  ERROR: does not appear to be a Python project: neither setup.py nor"
        " pyproject.toml found." in out
    )
    tail = [x for x in out.splitlines() if x.startswith("  pip line ")]
    assert tail == [f"  pip line {i}" for i in range(12, 31)]  # 19 + pip's ERROR
    assert "reached the end" not in out


def test_a_good_install_shows_no_pip_output(tmp_path):
    rc, out = _install(tmp_path)
    assert rc == 0, out
    assert "reached the end of the install step" in out
    assert "Successfully installed" not in out and "pip line" not in out


def test_each_install_pip_step_is_announced_before_it_runs(tmp_path):
    rc, out = _install(tmp_path)
    assert rc == 0, out
    ev = _events(tmp_path)
    upgrade = next(i for i, e in enumerate(ev) if "--upgrade pip" in e)
    install = next(i for i, e in enumerate(ev) if e.startswith("CALL") and " -e " in e)
    assert ev[upgrade - 1] == "INFO Updating pip in wintools-mcp's environment..."
    assert ev[install - 1] == (
        "INFO Installing wintools-mcp's Python packages; this can take several minutes..."
    )


FK_INSTALL = (
    _function("Write-OutputTail")
    + "$venvPython = $env:FAKE_PY; $InstallDir = $env:INST; $networkOk = $true\n"
    + '$githubOrg = "https://github.com/AppliedIR"\n'
    + _between(
        '$fkDir = Join-Path $InstallDir "forensic-knowledge"\n$fkInstalled',
        "if ($fkInstalled) {",
    )
    + '"FK installed=$fkInstalled"\n'
)


@pytest.mark.parametrize("local", [False, True], ids=["from-sift-mcp", "local-copy"])
def test_forensic_knowledge_steps_are_announced_and_a_failure_says_why(tmp_path, local):
    inst = tmp_path / "inst"
    inst.mkdir()
    if local:
        (inst / "forensic-knowledge").mkdir()
    rc, out = _pwsh(
        tmp_path,
        FK_INSTALL,
        {
            "FAKE_PY": str(_python(tmp_path)),
            "INST": str(inst),
            "PIP_FAIL_ON": "pip install",
            "IMPORT_RC": "1",
        },
    )
    assert rc == 0, out
    assert "FK installed=False" in out
    ev = _events(tmp_path)
    remote = next(i for i, e in enumerate(ev) if "--force-reinstall" in e)
    assert ev[remote - 1] == (
        "INFO Installing forensic-knowledge from the sift-mcp repository;"
        " this can take a few minutes..."
    )
    assert (
        "WARN Could not install forensic-knowledge: FK install failed (exit 1)" in out
    )
    assert "  ERROR: does not appear to be a Python project" in out
    if local:
        first = next(
            i for i, e in enumerate(ev) if e.startswith("CALL") and " -e " in e
        )
        assert ev[first - 1] == (
            f"INFO Installing forensic-knowledge from {inst / 'forensic-knowledge'}..."
        )


UPDATE = (
    _function("Write-OutputTail")
    + "$venvPython = $env:FAKE_PY; $wintoolsDir = $env:WT_DIR; $InstallDir = $env:INST\n"
    + _between("    # 2. Reinstall package", "    # 4. Kill running wintools process")
    + '"reached the restart"\n'
)


def _update(tmp_path, fail_on, local=False):
    inst = tmp_path / "inst"
    inst.mkdir()
    if local:
        (inst / "forensic-knowledge").mkdir()
    return _pwsh(
        tmp_path,
        UPDATE,
        {
            "FAKE_PY": str(_python(tmp_path)),
            "WT_DIR": str(tmp_path / "wt"),
            "INST": str(inst),
            "PIP_FAIL_ON": fail_on,
        },
    )


def test_a_failed_update_reinstall_shows_pips_reason(tmp_path):
    rc, out = _update(tmp_path, fail_on=" -e ")
    assert rc == 1, out
    assert "ERR pip install failed: pip install failed (exit 1)" in out
    assert "  ERROR: does not appear to be a Python project" in out
    assert "reached the restart" not in out


@pytest.mark.parametrize("local", [False, True], ids=["from-sift-mcp", "local-copy"])
def test_a_failed_update_of_forensic_knowledge_says_why_and_goes_on(tmp_path, local):
    fail_on = (
        " -e " + str(tmp_path / "inst" / "forensic-knowledge")
        if local
        else "--force-reinstall"
    )
    rc, out = _update(tmp_path, fail_on=fail_on, local=local)
    assert rc == 0, out
    assert "OK Package reinstalled" in out and "reached the restart" in out
    assert "  ERROR: does not appear to be a Python project" in out
    assert "pip line 30" in out and "Successfully installed" not in out
    ev = _events(tmp_path)
    step = next(i for i, e in enumerate(ev) if e.startswith("CALL") and fail_on in e)
    if local:
        assert ev[step - 1].startswith("INFO Reinstalling forensic-knowledge from ")
    else:
        assert ev[step - 1] == (
            "INFO Updating forensic-knowledge from the sift-mcp repository;"
            " this can take a few minutes..."
        )


def test_a_good_update_shows_no_pip_output(tmp_path):
    rc, out = _update(tmp_path, fail_on="")
    assert rc == 0, out
    assert "reached the restart" in out
    assert "Successfully installed" not in out and "pip line" not in out


# --- the gateway URL ---------------------------------------------------------------

URL = _function("Get-GatewayWintoolsUrl") + (
    '"URL " + (Get-GatewayWintoolsUrl $env:G_SCHEME $env:G_IP $env:G_PORT)\n'
)


@pytest.mark.parametrize(
    ("scheme", "ip", "port", "url"),
    [
        ("https", "10.0.1.91", "14516", "https://10.0.1.91:14516/mcp/wintools-mcp"),
        ("http", "10.0.1.91", "4508", "http://10.0.1.91:4508/mcp/wintools-mcp"),
        ("https", "10.0.1.91", "", "https://10.0.1.91:4508/mcp/wintools-mcp"),
        ("http", "", "", "http://SIFT_IP:4508/mcp/wintools-mcp"),
    ],
)
def test_the_gateway_url_carries_what_the_run_knows(tmp_path, scheme, ip, port, url):
    rc, out = _pwsh(tmp_path, URL, {"G_SCHEME": scheme, "G_IP": ip, "G_PORT": port})
    assert rc == 0, out
    assert f"URL {url}\n" in out


def test_no_line_hard_codes_the_gateway_url():
    assert 'http://SIFT_IP:4508/mcp/wintools-mcp"' not in TEXT.replace(
        'return "http://SIFT_IP:4508/mcp/wintools-mcp"', ""
    )
    assert TEXT.count("$(Get-GatewayWintoolsUrl $gatewayScheme $siftIp $siftPort)") == 2
