"""A re-run whose `git pull` of the install's wintools-mcp fails stops with
git's own lines, unless -ContinueWithoutUpdate or a "y" says to set up the
code already there. The installer's own lines run under PowerShell against a
real local remote and checkout; Read-Host answers from STUB_ANSWER.
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
    shutil.which("pwsh") is None or shutil.which("git") is None,
    reason="PowerShell or git isn't installed",
)

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@t"]


def _between(start: str, end: str) -> str:
    i = TEXT.index(start)
    return TEXT[i : TEXT.index(end, i)]


def _function(name: str) -> str:
    return _between(f"function {name} {{", "\n}\n") + "\n}\n"


def _harness(tmp_path: Path, stubs: str) -> Path:
    """The clone-or-pull step, with the installer's own Read-YesNo."""
    ps1 = tmp_path / "pull.ps1"
    ps1.write_text(
        "param([switch]$NonInteractive, [switch]$ContinueWithoutUpdate,"
        " [string]$wintoolsDir)\n"
        '$ErrorActionPreference = "Stop"\n'
        'function Write-Info { param($m) Write-Host "INFO $m" }\n'
        'function Write-Ok { param($m) Write-Host "OK $m" }\n'
        'function Write-Warn { param($m) Write-Host "WARN $m" }\n'
        'function Write-Err { param($m) Write-Host "ERR $m" }\n'
        + stubs
        + _function("Read-YesNo")
        + '$hasGit = $true\n$githubOrg = "file:///nowhere"\n'
        + _between("# Clone or download wintools-mcp", "\nif (-not $cloneOk) {")
        + '\n"cloneOk=$cloneOk"\n',
        encoding="utf-8",
    )
    return ps1


def _git(*args, cwd):
    subprocess.run([*GIT, *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def install(tmp_path):
    """An install checkout one commit behind its remote."""
    src, remote, inst = tmp_path / "src", tmp_path / "remote.git", tmp_path / "inst"
    src.mkdir()
    (src / "pyproject.toml").write_text("one\n")
    _git("init", "-q", "-b", "main", cwd=src)
    _git("add", ".", cwd=src)
    _git("commit", "-qm", "one", cwd=src)
    _git("tag", "v1", cwd=src)
    _git("clone", "-q", "--bare", str(src), str(remote), cwd=tmp_path)
    _git("clone", "-q", str(remote), str(inst), cwd=tmp_path)
    (src / "pyproject.toml").write_text("two\n")
    _git("commit", "-qam", "two", cwd=src)
    _git("push", "-q", str(remote), "main", cwd=src)
    return tmp_path, remote, inst


READ_HOST = (
    'function Read-Host { param($m) Write-Host "PROMPT $m"; $env:STUB_ANSWER }\n'
)


def _run(tmp_path, inst, *flags, answer=None, stubs=READ_HOST, host=()):
    env = {k: v for k, v in os.environ.items() if k != "STUB_ANSWER"}
    if answer is not None:
        env["STUB_ANSWER"] = answer
    r = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            *host,
            "-File",
            str(_harness(tmp_path, stubs)),
            "-wintoolsDir",
            str(inst),
            *flags,
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    return r.returncode, r.stdout + r.stderr


def _gone(remote):
    remote.rename(remote.with_name("gone.git"))


def test_a_pull_that_works_sets_up_the_update(install):
    tmp_path, _, inst = install
    rc, out = _run(tmp_path, inst, "-NonInteractive")
    assert rc == 0 and "cloneOk=True" in out
    assert (inst / "pyproject.toml").read_text() == "two\n"


def test_unattended_failed_pull_stops_with_gits_lines(install):
    tmp_path, remote, inst = install
    _gone(remote)
    rc, out = _run(tmp_path, inst, "-NonInteractive")
    assert rc == 1, out
    assert f"ERR Couldn't update the wintools-mcp at {inst}" in out
    assert "git pull failed (exit 1):" in out and "fatal:" in out
    assert "re-run with -ContinueWithoutUpdate" in out and "cloneOk=" not in out


def test_continue_without_update_sets_up_the_code_there(install):
    tmp_path, remote, inst = install
    _gone(remote)
    rc, out = _run(tmp_path, inst, "-NonInteractive", "-ContinueWithoutUpdate")
    assert rc == 0, out
    assert "ERR Couldn't update" in out
    assert (
        f"WARN Continuing with the wintools-mcp already at {inst}, not updated" in out
    )
    assert "cloneOk=True" in out


@pytest.mark.parametrize(
    ("answer", "rc"), [("n", 1), ("", 1), ("y", 0)], ids=["no", "enter", "yes"]
)
def test_interactive_failed_pull_asks_and_defaults_to_stop(install, answer, rc):
    tmp_path, remote, inst = install
    _gone(remote)
    got, out = _run(tmp_path, inst, answer=answer)
    assert got == rc, out
    assert (
        "PROMPT Set up the wintools-mcp already there, without the update? [y/N]" in out
    )
    assert ("cloneOk=True" in out) == (rc == 0)


def test_a_checked_out_tag_stops(install):
    tmp_path, _, inst = install
    _git("checkout", "-q", "v1", cwd=inst)
    rc, out = _run(tmp_path, inst, "-NonInteractive")
    assert rc == 1, out
    assert "You are not currently on a branch." in out


def test_a_local_change_the_pull_would_overwrite_stops(install):
    tmp_path, _, inst = install
    (inst / "pyproject.toml").write_text("edited\n")
    rc, out = _run(tmp_path, inst, "-NonInteractive")
    assert rc == 1, out
    assert "would be overwritten by merge" in out
    assert (inst / "pyproject.toml").read_text() == "edited\n"


def test_a_host_that_cant_prompt_stops_and_replaces_nothing(install):
    """powershell -NonInteractive without the script's -NonInteractive: the
    prompt throws, which is a No, not the ZIP fallback's swap of the folder."""
    tmp_path, _, inst = install
    (inst / "pyproject.toml").write_text("edited\n")
    rc, out = _run(tmp_path, inst, stubs="", host=("-NonInteractive",))
    assert rc == 1, out
    assert "would be overwritten by merge" in out
    assert "falling back to ZIP" not in out and "cloneOk=" not in out
    assert (inst / "pyproject.toml").read_text() == "edited\n"


def test_a_failed_pull_that_prints_nothing_says_so(install):
    tmp_path, _, inst = install
    git = "function git { $global:LASTEXITCODE = 1 }\n"
    rc, out = _run(tmp_path, inst, "-NonInteractive", stubs=READ_HOST + git)
    assert rc == 1, out
    assert "git pull failed (exit 1) and printed nothing" in out
    assert "(exit 1):" not in out
