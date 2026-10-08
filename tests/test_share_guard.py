"""wintools writes into the case only through a share that is the active case.

The share's root holds a marker naming its case. A share pointed at no case,
at another case (SIFT repointed it before telling wintools), or at a folder
that isn't a case (an old mapping to SIFT's own shares) refuses tool runs,
saved output, the audit log and the session probe, and nothing is written.
The share is a local folder here.
"""

from __future__ import annotations

import io
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from wintools_mcp import audit as audit_mod
from wintools_mcp import config as config_mod
from wintools_mcp import share_guard, smb
from wintools_mcp.config import WintoolsConfig
from wintools_mcp.executor import execute


@pytest.fixture
def share(tmp_path, monkeypatch):
    """A share root that is a case folder, wintools' active case `C-1`.
    `mark(text)` writes its marker (None: none)."""
    root = tmp_path / "share"
    (root / "audit").mkdir(parents=True)
    (root / "CASE.yaml").write_text("case_id: C-1\n")
    cfg = WintoolsConfig()
    cfg.share_root = cfg.case_dir = str(root)
    cfg.active_case = "C-1"
    monkeypatch.setattr(config_mod, "_config", cfg)
    monkeypatch.setenv("VHIR_CASE_DIR", str(root))
    monkeypatch.delenv("VHIR_AUDIT_DIR", raising=False)

    def mark(text):
        if text is not None:
            (root / share_guard.MARKER).write_text(text)

    yield SimpleNamespace(root=root, cfg=cfg, mark=mark)
    audit_mod._set_share_error("")


def _files(root):
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


WRONG = [None, "C-2", ""]
WRONG_IDS = ["no marker", "another case", "empty marker"]


# -- the check


def test_a_marker_naming_the_active_case_passes(share):
    share.mark("C-1\n")
    assert share_guard.refusal() == ""


@pytest.mark.parametrize("text", WRONG, ids=WRONG_IDS)
def test_any_other_share_is_refused(share, text):
    share.mark(text)
    why = share_guard.refusal()
    assert share_guard.is_refusal(why) and "the active case is C-1" in why


def test_no_active_case_refuses_even_a_marked_share(share):
    share.mark("C-1")
    share.cfg.active_case = ""
    assert share_guard.is_refusal(share_guard.refusal())


def test_a_share_that_cant_be_read_says_so(share):
    (share.root / share_guard.MARKER).mkdir()
    why = share_guard.refusal()
    assert why.startswith(
        "evidence share not accessible"
    ) and not share_guard.is_refusal(why)


def test_a_wintools_with_no_share_is_not_checked(share):
    share.cfg.share_root = ""
    assert share_guard.refusal() == ""


# -- a tool run


def _run(monkeypatch, tmp_path):
    from wintools_mcp import server as srv

    ran = []
    monkeypatch.setattr(
        "wintools_mcp.tools.generic.run_command",
        lambda command, **k: (
            ran.append(command) or {"exit_code": 0, "stdout": "ok", "stderr": ""}
        ),
    )
    evidence = tmp_path / "evidence.bin"
    evidence.write_text("x")
    fn = srv.create_server()._tool_manager._tools["run_windows_command"].fn
    return fn(command=["sigcheck.exe", str(evidence)], purpose="unit test"), ran


@pytest.mark.parametrize("text", WRONG, ids=WRONG_IDS)
def test_a_run_on_a_share_that_isnt_the_active_case_is_refused_and_writes_nothing(
    share, monkeypatch, tmp_path, text
):
    share.mark(text)
    before = _files(share.root)
    resp, ran = _run(monkeypatch, tmp_path)
    assert resp["success"] is False and share_guard.is_refusal(resp["error"])
    assert ran == [] and _files(share.root) == before


def test_sifts_repoint_before_wintools_is_told_is_refused(share, monkeypatch, tmp_path):
    """SIFT moved the share to C-2 and hasn't told wintools yet: nothing of
    C-1's lands in C-2."""
    share.mark("C-2")
    before = _files(share.root)
    resp, ran = _run(monkeypatch, tmp_path)
    assert resp["success"] is False and "it holds case 'C-2'" in resp["error"]
    assert ran == [] and _files(share.root) == before


def test_a_run_on_the_active_cases_share_runs_and_is_audited(
    share, monkeypatch, tmp_path
):
    share.mark("C-1")
    resp, ran = _run(monkeypatch, tmp_path)
    assert ran and resp.get("success", True) is not False
    assert "audit/wintools-mcp.jsonl" in _files(share.root)


# -- saved output, the audit log, the probe


@pytest.mark.parametrize("text", WRONG, ids=WRONG_IDS)
def test_output_is_not_saved_to_a_share_that_isnt_the_active_case(share, text):
    share.mark(text)
    proc = MagicMock(stdout=io.BytesIO(b"out"), stderr=io.BytesIO(b""), returncode=0)
    proc.wait.return_value = 0
    save_dir = share.root / "extractions" / "wintools"
    with patch("wintools_mcp.executor.subprocess.Popen", return_value=proc):
        result = execute(["test"], save_output=True, save_dir=str(save_dir))
    assert share_guard.is_refusal(
        result["save_error"].removeprefix("Output not saved: ")
    )
    assert not save_dir.exists() and "output_file" not in result


@pytest.mark.parametrize("text", WRONG, ids=WRONG_IDS)
@pytest.mark.parametrize("found", ["case dir", "active_case file"])
def test_the_audit_log_is_not_written_to_a_share_that_isnt_the_active_case(
    share, monkeypatch, tmp_path, text, found
):
    if found == "active_case file":  # the Windows-local pointer, VHIR_CASE_DIR unset
        monkeypatch.delenv("VHIR_CASE_DIR")
        home = tmp_path / "home"
        (home / ".vhir").mkdir(parents=True)
        (home / ".vhir" / "active_case").write_text(str(share.root))
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
    share.mark(text)
    writer = audit_mod.AuditWriter()
    assert writer.log(tool="t", params={}, result_summary="x") is None
    assert not (share.root / "audit" / "wintools-mcp.jsonl").exists()
    assert share_guard.is_refusal(audit_mod.share_error())


@pytest.mark.parametrize("text", WRONG, ids=WRONG_IDS)
def test_the_probe_writes_nothing_to_a_share_that_isnt_the_active_case(share, text):
    share.mark(text)
    before = _files(share.root)
    assert share_guard.is_refusal(smb._probe(str(share.root), "C-1"))
    assert _files(share.root) == before


def test_a_mapping_to_the_wrong_case_is_no_session_and_is_kept(share, monkeypatch):
    """Nothing to re-map: the mapping works, the case is wrong."""
    share.mark("C-2")
    calls = []

    def run(cmd, **k):
        calls.append(cmd)
        return subprocess.CompletedProcess(
            cmd, 2, "", "System error 1219 ... already ..."
        )

    monkeypatch.setattr(smb.subprocess, "run", run)
    cfg = SimpleNamespace(
        share_root="\\\\sift\\vhir-cases", smb_user="vhir-smb", smb_password="pw",
        active_case="C-1",
    )  # fmt: skip
    monkeypatch.setattr(
        smb, "_probe", lambda root, case="C-1": share_guard.check(share.root, case)
    )
    assert smb.establish_smb_session(cfg) is False
    assert not any("/delete" in c for c in calls)
