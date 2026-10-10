"""On an upgrade the share moved (`cases` to `vhir-cases`), and Windows still
remembers the old mapping on S:. net use would stop at its overwrite prompt,
which fails non-interactively, so the installer removes a remembered mapping
first, but only Valhuntir's own earlier one: the share root the last install
recorded, or a Valhuntir share on this SIFT. Any other remembered mapping is
left alone, and the installer says which letter holds what. The installer's
own functions run under PowerShell, with the remembered mappings stubbed and
a stand-in `net` that logs what it is asked."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "setup-windows.ps1"
TEXT = SCRIPT.read_text(encoding="utf-8")

pwsh = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="PowerShell isn't installed"
)


def _functions() -> str:
    a = TEXT.index("# -- The share's drive letter, past a remembered mapping --")
    b = TEXT.index("\n}\n", TEXT.index("function Select-ShareLetter", a)) + 3
    return TEXT[a:b]


def _run(tmp_path: Path, remembered: dict, body: str, net_exit: int = 0):
    log = tmp_path / "net.log"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "net").write_text(f'#!/bin/sh\necho "$*" >> {log}\nexit {net_exit}\n')
    (bin_dir / "net").chmod(0o755)
    table = "; ".join(f'"{k}" = "{v}"' for k, v in remembered.items())
    script = tmp_path / "check.ps1"
    script.write_text(
        'function Write-Info { param($m) Write-Host "INFO $m" }\n'
        + _functions()
        + f"\n$script:remembered = @{{ {table} }}\n"
        + "function Get-RememberedMapping { param([string]$Letter) "
        + "return $script:remembered[$Letter] }\n"
        + body,
        encoding="utf-8",
    )
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True,
        text=True,
        timeout=120,
        env={"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path)},
    )
    calls = log.read_text().splitlines() if log.exists() else []
    return r, calls


PICK = (
    "$p = Select-ShareLetter -SmbHost '10.0.1.95' -PreviousShareRoot $previous\n"
    'Write-Host "LETTER=$($p.Letter)"\nWrite-Host "WHY=$($p.Why)"\n'
)


@pwsh
def test_the_earlier_mapping_the_last_install_recorded_is_removed_first(tmp_path):
    # the 0.6.3 join's SIFT was another address: config.yaml names its share
    r, calls = _run(
        tmp_path,
        {"S": r"\\10.0.1.91\cases"},
        "$previous = '\\\\10.0.1.91\\cases'\n" + PICK,
    )
    assert "LETTER=S" in r.stdout, r.stdout + r.stderr
    assert calls == ["use S: /delete /y"]
    assert r"Removed Valhuntir's earlier mapping S: to \\10.0.1.91\cases" in r.stdout


@pwsh
@pytest.mark.parametrize("share", ["cases", "Cases", "vhir-cases"])
def test_a_valhuntir_share_on_this_sift_is_removed_first(tmp_path, share):
    r, calls = _run(
        tmp_path, {"S": rf"\\10.0.1.95\{share}"}, "$previous = $null\n" + PICK
    )
    assert "LETTER=S" in r.stdout, r.stdout + r.stderr
    assert calls == ["use S: /delete /y"]


@pwsh
@pytest.mark.parametrize(
    "target",
    [r"\\fileserver\cases", r"\\10.0.1.95\projects", r"\\10.0.1.91\cases"],
)
def test_any_other_remembered_mapping_is_left_and_named(tmp_path, target):
    r, calls = _run(tmp_path, {"S": target}, "$previous = $null\n" + PICK)
    assert "LETTER=\n" in r.stdout  # no letter
    assert "LETTER=S" not in r.stdout
    assert calls == []  # never deleted
    assert "remove it (net use S: /delete)" in r.stdout  # the user's exact command
    assert (
        f"WHY=S: is remembered as a mapping to {target}, which isn't Valhuntir's"
        in (r.stdout)
    )


@pwsh
def test_a_free_letter_is_taken_with_nothing_removed(tmp_path):
    r, calls = _run(tmp_path, {}, "$previous = $null\n" + PICK)
    assert "LETTER=S" in r.stdout and calls == []


@pwsh
def test_a_removal_that_fails_leaves_no_letter_and_says_so(tmp_path):
    r, calls = _run(
        tmp_path, {"S": r"\\10.0.1.95\cases"}, "$previous = $null\n" + PICK, net_exit=2
    )
    assert "LETTER=S" not in r.stdout and calls == ["use S: /delete /y"]
    assert r"couldn't be removed" in r.stdout


@pwsh
def test_the_previous_share_root_is_read_from_config_yaml(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("api_keys:\n  x: y\nshare_root: \\\\10.0.1.91\\cases\nsmb_user: u\n")
    r, _ = _run(
        tmp_path,
        {},
        f"Write-Host \"ROOT=$(Get-PreviousShareRoot '{cfg}')\"\n"
        f"Write-Host \"NONE=$(Get-PreviousShareRoot '{tmp_path / 'missing.yaml'}')\"\n",
    )
    assert r"ROOT=\\10.0.1.91\cases" in r.stdout, r.stdout + r.stderr
    assert "NONE=\n" in r.stdout  # no config: none


def test_the_mapping_step_picks_its_letter_this_way():
    step = TEXT[TEXT.index("# Drive mapping -- only if join succeeded") :]
    step = step[: step.index("$derivedPw = $null")]
    assert "Select-ShareLetter -SmbHost $smbHost" in step
    assert "Get-PreviousShareRoot $wintoolsConfigPath" in step
    assert 'Write-Warn "Drive mapping failed: $($pick.Why)' in step
