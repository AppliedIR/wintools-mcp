"""The installer requires a 64-bit Python 3.10+: the cryptography package has
no 32-bit Windows build. Every path that runs pip checks the interpreter it
runs pip with: a fresh install picks the first 64-bit 3.10+ candidate, and
`-Update` and a re-run check the existing `.venv`. The installer's own blocks
run under PowerShell with stand-in interpreters that report their version and
pointer size.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "setup-windows.ps1"
TEXT = SCRIPT.read_text(encoding="utf-8")
UPDATE_CHECK = "Assert-Venv64 $venvPython  # the environment pip will run in"
RERUN_CHECK = "Assert-Venv64 $venvPython  # a .venv kept from an earlier install too"
VENV_32 = (
    "ERR This wintools-mcp environment uses 32-bit Python. Install 64-bit Python 3.10+, "
    "remove `.venv`, and re-run."
)

pwsh = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="PowerShell isn't installed"
)


def _cut(start: str, end: str, include_end: bool = False) -> str:
    a = TEXT.index(start)
    b = TEXT.index(end, a)
    return TEXT[a : b + len(end)] if include_end else TEXT[a:b]


def _helpers() -> str:
    a = TEXT.index("# 64-bit only:")
    b = TEXT.index("\n}\n", TEXT.index("function Assert-Venv64", a)) + 3
    return TEXT[a:b]


def _stub(path: Path, bits: str, version: str = "3.12") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'#!/bin/sh\ncase "$*" in *struct*) echo {bits} ;; *) echo {version} ;; esac\n'
    )
    path.chmod(0o755)


def _run(tmp_path: Path, body: str, after: str):
    script = tmp_path / "check.ps1"
    script.write_text(
        'function Write-Ok { param($m) Write-Host "OK $m" }\n'
        'function Write-Err { param($m) Write-Host "ERR $m" }\n'
        + _helpers()
        + body
        + f'\nWrite-Host "{after}"\n',
        encoding="utf-8",
    )
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True,
        text=True,
        timeout=120,
        env={"PATH": f"{tmp_path / 'bin'}:/usr/bin:/bin", "HOME": str(tmp_path)},
    )


def test_every_path_checks_the_interpreter_before_its_first_pip():
    update = TEXT.index(UPDATE_CHECK)
    assert update < TEXT.index("$venvPython -m pip install", update)
    assert TEXT.index("if ($Update)") < update < TEXT.index('Write-Header "Phase 1')
    rerun = TEXT.index(RERUN_CHECK)
    assert TEXT.index("# Create venv and install") < rerun
    assert rerun < TEXT.index("$venvPython -m pip install", rerun)


# -- a fresh install: the candidate interpreters


def _prereq() -> str:
    return _cut("# Python 3.10+\n", "\n# pip\n")


@pwsh
@pytest.mark.parametrize(
    "python, python3, picked",
    [("64", None, "python"), ("32", "64", "python3")],
    ids=["first is 64-bit", "first 64-bit of two"],
)
def test_a_fresh_install_takes_the_first_64_bit_python(
    tmp_path, python, python3, picked
):
    _stub(tmp_path / "bin" / "python", python)
    if python3:
        _stub(tmp_path / "bin" / "python3", python3)
    p = _run(tmp_path, _prereq() + '\nWrite-Host "PICKED $pythonCmd"', "REACHED PIP")
    assert p.returncode == 0 and "REACHED PIP" in p.stdout, p.stdout + p.stderr
    assert f"PICKED {picked}" in p.stdout and "OK Python 3.12 (64-bit)" in p.stdout


@pwsh
def test_a_fresh_install_with_only_32_bit_pythons_stops(tmp_path):
    _stub(tmp_path / "bin" / "python", "32")
    _stub(tmp_path / "bin" / "python3", "32")
    p = _run(tmp_path, _prereq(), "REACHED PIP")
    assert p.returncode == 1 and "REACHED PIP" not in p.stdout, p.stdout + p.stderr
    assert (
        "ERR 64-bit Python 3.10+ required (found only Python 3.12 (32-bit, 'python'))"
        in (p.stdout)
    )
    assert "python.org/downloads/windows" in p.stdout


# -- an existing environment: -Update, and a re-run that keeps .venv


def _venv(tmp_path: Path, bits: str) -> Path:
    wintools = tmp_path / "wintools-mcp"
    _stub(wintools / ".venv" / "Scripts" / "python.exe", bits)
    return wintools


@pwsh
@pytest.mark.parametrize("bits, ok", [("64", True), ("32", False)])
def test_update_checks_the_existing_environment(tmp_path, bits, ok):
    wintools = _venv(tmp_path, bits)
    body = f"$wintoolsDir = '{wintools}'\n" + _cut(
        '    $venvDir = Join-Path $wintoolsDir ".venv"', UPDATE_CHECK, include_end=True
    )
    p = _run(tmp_path, body, "REACHED PIP")
    if ok:
        assert p.returncode == 0 and "REACHED PIP" in p.stdout, p.stdout + p.stderr
    else:
        assert p.returncode == 1 and "REACHED PIP" not in p.stdout, p.stdout + p.stderr
        assert VENV_32 in p.stdout


@pwsh
@pytest.mark.parametrize("bits, ok", [("64", True), ("32", False)])
def test_a_rerun_checks_the_environment_it_keeps(tmp_path, bits, ok):
    wintools = _venv(tmp_path, bits)
    # the environment's paths, then its steps up to the check (inside the
    # rollback window's try)
    a = TEXT.index("# Create venv and install")
    head = TEXT[a : TEXT.index("$installed = $false", a)]
    s = TEXT.index("    if (-not (Test-Path $venvDir)) {", a)
    steps = TEXT[s : TEXT.index(RERUN_CHECK, s) + len(RERUN_CHECK)]
    body = f"$wintoolsDir = '{wintools}'\n$pythonCmd = 'python'\n" + head + steps
    p = _run(tmp_path, body, "REACHED PIP")
    if ok:
        assert p.returncode == 0 and "REACHED PIP" in p.stdout, p.stdout + p.stderr
    else:
        assert p.returncode == 1 and "REACHED PIP" not in p.stdout, p.stdout + p.stderr
        assert VENV_32 in p.stdout
