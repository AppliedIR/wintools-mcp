"""The installer requires a 64-bit Python 3.10+: the cryptography package has
no 32-bit Windows build. The installer's own prerequisite block runs under
PowerShell with a stand-in `python` that reports its version and pointer size.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "setup-windows.ps1"


def _block() -> str:
    """The installer's Python prerequisite: from its heading to the pip check."""
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index("# Python 3.10+\n")
    return text[start : text.index("\n# pip\n", start)]


def test_the_installer_checks_the_pointer_size_after_the_version():
    block = _block()
    assert "struct.calcsize('P')" in block
    assert block.index("struct.calcsize('P')") > block.index("Python 3.10+ not found")
    assert "64-bit Python 3.10+ required" in block


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell isn't installed")
@pytest.mark.parametrize("bits, ok", [("64", True), ("32", False)])
def test_a_32_bit_python_stops_the_installer(tmp_path, bits, ok):
    stub = tmp_path / "python"
    stub.write_text(
        '#!/bin/sh\ncase "$*" in *struct*) echo ' + bits + " ;; *) echo 3.12 ;; esac\n"
    )
    stub.chmod(0o755)
    script = tmp_path / "check.ps1"
    script.write_text(
        'function Write-Ok { param($m) Write-Host "OK $m" }\n'
        'function Write-Err { param($m) Write-Host "ERR $m" }\n'
        + _block()
        + '\nWrite-Host "REACHED PIP"\n',
        encoding="utf-8",
    )
    p = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True,
        text=True,
        timeout=120,
        env={"PATH": f"{tmp_path}:/usr/bin:/bin", "HOME": str(tmp_path)},
    )
    if ok:
        assert p.returncode == 0 and "REACHED PIP" in p.stdout, p.stdout + p.stderr
        assert "OK Python is 64-bit" in p.stdout
    else:
        assert p.returncode == 1 and "REACHED PIP" not in p.stdout, p.stdout + p.stderr
        assert "ERR 64-bit Python 3.10+ required (this Python is 32-bit)" in p.stdout
        assert "python.org/downloads/windows" in p.stdout
