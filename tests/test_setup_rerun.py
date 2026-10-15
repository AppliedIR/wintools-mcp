"""When a fetch (git or ZIP) or an -Update brings a setup-windows.ps1 other
than the running one, the run starts the new one in a new PowerShell with
the same options and exits with its code. The installer's own lines run
under PowerShell against real local remotes and folders.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "setup-windows.ps1"
TEXT = SCRIPT.read_text(encoding="utf-8")

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or shutil.which("git") is None,
    reason="PowerShell or git isn't installed",
)

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@t"]


def _between(start: str, end: str) -> str:
    i = TEXT.index(start)
    return TEXT[i : TEXT.index(end, i)]


def _function(name: str) -> str:
    return _between(f"function {name} {{", "\n}\n") + "\n}\n"


PARAM_BLOCK = _between("[CmdletBinding()]\nparam(", "\n)\n") + "\n)\n"
WRITE = (
    'function Write-Info { param($m) Write-Host "INFO $m" }\n'
    'function Write-Ok { param($m) Write-Host "OK $m" }\n'
    'function Write-Warn { param($m) Write-Host "WARN $m" }\n'
    'function Write-Err { param($m) Write-Host "ERR $m" }\n'
)
# The start of the script: the parameters, the hash and the recorded options
START = (
    PARAM_BLOCK
    + _between("# The SHA-256 of a script", '$ErrorActionPreference = "Stop"')
    + '$ErrorActionPreference = "Stop"\n'
    + WRITE
    + _function("Test-NewSetupScript")
    + _function("Format-Quoted")
    + _function("Start-SetupScript")
)
# A setup-windows.ps1 an update brings: it shows what it was given
NEW = (
    PARAM_BLOCK
    + "$o = @{}\n"
    + "foreach ($k in $PSBoundParameters.Keys) { $v = $PSBoundParameters[$k];"
    + " if ($v -is [switch]) { $v = $v.IsPresent }; $o[$k] = $v }\n"
    + '"NEW ran rerun=[$env:WINTOOLS_SETUP_RERUN]"\n'
    + '"PARAMS " + ($o | ConvertTo-Json -Compress)\n'
    + "exit 7\n"
)


def _pwsh(*args, env=None):
    r = subprocess.run(
        ["pwsh", "-NoProfile", *args],
        capture_output=True,
        text=True,
        env={**os.environ, **(env or {})},
        timeout=180,
    )
    return r.returncode, r.stdout + r.stderr


def _params(out: str) -> dict:
    line = next(x for x in out.splitlines() if x.startswith("PARAMS "))
    return json.loads(line[len("PARAMS ") :])


# --- Start-SetupScript ------------------------------------------------------


def _starter(tmp_path: Path, params: str) -> Path:
    ps1 = tmp_path / "starter.ps1"
    ps1.write_text(
        START + f"Start-SetupScript $env:TARGET @{{ {params} }}\n'not reached'\n",
        encoding="utf-8",
    )
    return ps1


def test_hostile_values_reach_the_new_script_as_typed_and_nothing_runs(tmp_path):
    marker = tmp_path / "ran"
    target = tmp_path / "target dir" / "new 'one'.ps1"
    target.parent.mkdir()
    target.write_text(NEW, encoding="utf-8")
    examiner = (
        "'o''brien' + [char]0x2019 + 's $(New-Item -Path "
        + str(marker)
        + ') `"q`" \' + "line1`nline2"'
    )
    params = (
        "InstallDir = 'C:\\My Tools\\'; Examiner = " + examiner + "; "
        "JoinCode = '$(New-Item -Path " + str(marker) + ");x'; GatewayHost = 'a b'; "
        "StaticIP = ''; Port = 8443; NonInteractive = $true; "
        "AcknowledgeSecurityHole = [switch]$true; Update = $false"
    )
    rc, out = _pwsh(
        "-File", str(_starter(tmp_path, params)), env={"TARGET": str(target)}
    )
    assert rc == 7, out
    assert "NEW ran rerun=[1]" in out and "not reached" not in out
    assert _params(out) == {
        "InstallDir": "C:\\My Tools\\",
        "Examiner": "o'brien\u2019s $(New-Item -Path "
        + str(marker)
        + ') `"q`" line1\nline2',
        "JoinCode": "$(New-Item -Path " + str(marker) + ");x",
        "GatewayHost": "a b",
        "StaticIP": "",
        "Port": 8443,
        "NonInteractive": True,
        "AcknowledgeSecurityHole": True,
        "Update": False,
    }
    assert not marker.exists()


ENDINGS = {
    "normal": "'out normal'",
    "failed-native-then-normal": "'out native'; & sh -c 'exit 3'; 'after'",
    "exit-1": "'out one'; exit 1",
    "exit-2": "'out two'; exit 2",
    "throw": "'out throw'; throw 'boom'",
}


@pytest.mark.parametrize("ending", ENDINGS)
def test_the_exit_code_and_output_are_a_direct_runs(tmp_path, ending):
    """The new script prints to stdout and the console (Write-Host) and
    ends each way: the run exits as `-File` of it does, with its lines."""
    target = tmp_path / "target.ps1"
    target.write_text(
        "[CmdletBinding()]\nparam([switch]$NonInteractive)\n"
        "Write-Host 'host line'\n" + ENDINGS[ending] + "\n",
        encoding="utf-8",
    )
    direct, _ = _pwsh("-File", str(target), "-NonInteractive")
    rc, out = _pwsh(
        "-File",
        str(_starter(tmp_path, "NonInteractive = $true")),
        env={"TARGET": str(target)},
    )
    assert rc == direct, out
    assert ENDINGS[ending].split("'")[1] in out and "host line" in out
    assert "#< CLIXML" not in out


def test_a_script_without_a_passed_option_stops_loudly(tmp_path):
    """An older script that lacks an option this run was given: the binding
    error shows and the run exits 1, never 0."""
    target = tmp_path / "older.ps1"
    target.write_text(
        "[CmdletBinding()]\nparam([switch]$NonInteractive)\n'older ran'\n",
        encoding="utf-8",
    )
    rc, out = _pwsh(
        "-File",
        str(
            _starter(tmp_path, "NonInteractive = $true; ContinueWithoutUpdate = $true")
        ),
        env={"TARGET": str(target)},
    )
    assert rc == 1, out
    assert "A parameter cannot be found" in out and "older ran" not in out


def test_the_variable_is_set_in_the_new_powershell_only(tmp_path):
    target = tmp_path / "new.ps1"
    target.write_text(NEW, encoding="utf-8")
    starter = _starter(tmp_path, "NonInteractive = $true")
    rc, out = _pwsh(
        "-Command",
        f"& '{starter}'; \"after=[$env:WINTOOLS_SETUP_RERUN] code=$LASTEXITCODE\"",
        env={"TARGET": str(target)},
    )
    assert rc == 0, out
    assert "NEW ran rerun=[1]" in out and "after=[] code=7" in out


# --- the install path: after the clone, pull or download --------------------

STUBS = (
    _function("Read-YesNo")
    + _function("Rename-WithRetry")
    + _function("Get-RepoAsZip")
    + 'function Suspend-WintoolsService { Write-Host "SUSPEND" }\n'
    + "function Resume-WintoolsService { param([switch]$Restart) }\n"
    + "function Invoke-WebRequest { param($Uri, $OutFile, [switch]$UseBasicParsing,"
    + " $TimeoutSec) Copy-Item -LiteralPath $env:STUB_ZIP -Destination $OutFile }\n"
)
FETCH = (
    START
    + STUBS
    + "$hasGit = -not $env:STUB_NOGIT\n$githubOrg = $env:STUB_ORG\n"
    + '$wintoolsDir = Join-Path $InstallDir "wintools-mcp"\n'
    + _between(
        "# A new setup-windows.ps1 from the fetch", "\n# Create venv and install."
    )
    + '\n"reached the install cloneOk=$cloneOk"\n'
)


def _git(*args, cwd):
    subprocess.run([*GIT, *args], cwd=cwd, check=True, capture_output=True)


def _install(tmp_path, first: str | None, second: str | None, *, crlf=False):
    """An install checkout whose remote has a newer commit; `first` and
    `second` are the scripts/setup-windows.ps1 of each (None: no file)."""
    src, org = tmp_path / "src", tmp_path / "org"
    (src / "scripts").mkdir(parents=True)
    org.mkdir()
    script = src / "scripts" / "setup-windows.ps1"

    def commit(text, msg):
        (src / "pyproject.toml").write_text(msg + "\n")
        if text is None:
            script.unlink(missing_ok=True)
        else:
            script.write_bytes(text.replace("\n", "\r\n" if crlf else "\n").encode())
        _git("add", "-A", ".", cwd=src)
        _git("commit", "-qm", msg, cwd=src)

    _git("init", "-q", "-b", "main", cwd=src)
    _git("config", "core.autocrlf", "false", cwd=src)
    commit(first, "one")
    remote = org / "wintools-mcp.git"
    _git("clone", "-q", "--bare", str(src), str(remote), cwd=tmp_path)
    inst = tmp_path / "install"
    inst.mkdir()
    _git("clone", "-q", str(remote), str(inst / "wintools-mcp"), cwd=tmp_path)
    commit(second, "two")
    _git("push", "-q", str(remote), "main", cwd=src)
    return inst


def _fetch(tmp_path, inst, *, run=None, env=None):
    run = run or tmp_path / "fetch.ps1"
    if not run.exists():
        run.write_text(FETCH, encoding="utf-8")
    return _pwsh(
        "-File",
        str(run),
        "-InstallDir",
        str(inst),
        "-NonInteractive",
        "-Examiner",
        "o'b",
        env={"STUB_ORG": f"file://{tmp_path / 'org'}", **(env or {})},
    )


def test_a_pull_that_changes_the_script_runs_the_new_one(tmp_path):
    inst = _install(tmp_path, FETCH, NEW)
    rc, out = _fetch(tmp_path, inst)
    assert rc == 7, out
    assert "INFO The update changed setup-windows.ps1: running the new one" in out
    assert "NEW ran rerun=[1]" in out and "reached the install" not in out
    assert _params(out) == {
        "InstallDir": str(inst),
        "NonInteractive": True,
        "Examiner": "o'b",
        "AcknowledgeSecurityHole": True,
    }


def test_a_pull_with_the_same_script_carries_on(tmp_path):
    inst = _install(tmp_path, NEW, FETCH)
    rc, out = _fetch(tmp_path, inst)
    assert rc == 0, out
    assert "reached the install cloneOk=True" in out and "NEW ran" not in out
    assert "running the new one" not in out


def test_the_same_script_with_crlf_line_ends_carries_on(tmp_path):
    inst = _install(tmp_path, NEW, FETCH, crlf=True)
    assert (
        b"\r\n" in (inst.parent / "src" / "scripts" / "setup-windows.ps1").read_bytes()
    )
    rc, out = _fetch(tmp_path, inst)
    assert rc == 0, out
    assert "reached the install cloneOk=True" in out and "NEW ran" not in out
    assert "running the new one" not in out


def test_a_pull_with_no_script_carries_on(tmp_path):
    inst = _install(tmp_path, NEW, None)
    rc, out = _fetch(tmp_path, inst)
    assert rc == 0, out
    assert "reached the install cloneOk=True" in out and "NEW ran" not in out
    assert "running the new one" not in out


def test_the_running_file_replaced_by_the_pull_runs_the_new_one(tmp_path):
    inst = _install(tmp_path, FETCH, NEW)
    running = inst / "wintools-mcp" / "scripts" / "setup-windows.ps1"
    rc, out = _fetch(tmp_path, inst, run=running)
    assert rc == 7, out
    assert "NEW ran rerun=[1]" in out


def test_a_re_run_never_starts_another(tmp_path):
    inst = _install(tmp_path, FETCH, NEW)
    rc, out = _fetch(tmp_path, inst, env={"WINTOOLS_SETUP_RERUN": "1"})
    assert rc == 0, out
    assert "WARN The update changed setup-windows.ps1 again" in out
    assert "reached the install cloneOk=True" in out and "NEW ran" not in out
    assert "running the new one" not in out


def _zip(tmp_path, script: str) -> Path:
    z = tmp_path / "main.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("wintools-mcp-main/pyproject.toml", "zip\n")
        f.writestr("wintools-mcp-main/scripts/setup-windows.ps1", script)
    return z


def _zip_install(tmp_path):
    inst = tmp_path / "install"
    (inst / "wintools-mcp").mkdir(parents=True)
    (inst / "wintools-mcp" / "pyproject.toml").write_text("kept\n")
    temp = tmp_path / "temp"
    temp.mkdir()
    return inst, temp


def test_a_download_that_changes_the_script_runs_it_and_replaces_nothing(tmp_path):
    inst, temp = _zip_install(tmp_path)
    rc, out = _fetch(
        tmp_path,
        inst,
        env={
            "STUB_NOGIT": "1",
            "STUB_ZIP": str(_zip(tmp_path, NEW)),
            "TMPDIR": str(temp),
        },
    )
    assert rc == 7, out
    assert "NEW ran rerun=[1]" in out and _params(out)["InstallDir"] == str(inst)
    assert "SUSPEND" not in out and "OK wintools-mcp downloaded" not in out
    assert (inst / "wintools-mcp" / "pyproject.toml").read_text() == "kept\n"
    assert sorted(p.name for p in inst.iterdir()) == ["wintools-mcp"]
    assert list(temp.iterdir()) == []


def test_a_download_with_the_same_script_is_set_up(tmp_path):
    inst, temp = _zip_install(tmp_path)
    rc, out = _fetch(
        tmp_path,
        inst,
        env={
            "STUB_NOGIT": "1",
            "STUB_ZIP": str(_zip(tmp_path, FETCH)),
            "TMPDIR": str(temp),
        },
    )
    assert rc == 0, out
    assert "SUSPEND" in out and "OK wintools-mcp downloaded" in out
    assert "reached the install cloneOk=False" in out and "NEW ran" not in out
    assert "running the new one" not in out
    assert (inst / "wintools-mcp" / "pyproject.toml").read_text() == "zip\n"


# --- the -Update path --------------------------------------------------------

UPDATE_CHECK = "# The installed setup-windows.ps1 does the rest"


def test_the_update_check_sits_after_the_source_update_and_before_pip():
    update = _between("if ($Update) {", "# 2. Reinstall package")
    assert update.index('Write-Ok "Source updated"') < update.index(UPDATE_CHECK)
    assert update.index("Converted to git repo") < update.index(UPDATE_CHECK)


@pytest.mark.parametrize(("installed", "rc"), [("new", 7), ("same", 0)])
def test_an_update_with_a_new_installed_script_runs_it(tmp_path, installed, rc):
    run = tmp_path / "update.ps1"
    run.write_text(
        START
        + "$wintoolsDir = $env:STUB_DIR\n"
        + _between(UPDATE_CHECK, "\n    # 2. Reinstall package")
        + '\n"reached pip"\n',
        encoding="utf-8",
    )
    scripts = tmp_path / "wt" / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "setup-windows.ps1").write_text(
        NEW if installed == "new" else run.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    got, out = _pwsh(
        "-File",
        str(run),
        "-Update",
        "-NonInteractive",
        env={"STUB_DIR": str(tmp_path / "wt")},
    )
    assert got == rc, out
    if installed == "new":
        assert "NEW ran rerun=[1]" in out and "reached pip" not in out
        assert _params(out) == {"Update": True, "NonInteractive": True}
    else:
        assert "reached pip" in out and "NEW ran" not in out
        assert "running the new one" not in out
