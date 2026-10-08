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


@pytest.mark.parametrize("text", [None, ""], ids=["no marker", "empty marker"])
def test_a_share_without_a_marker_says_how_sift_marks_it(share, text):
    """wintools updated before SIFT re-joined: SIFT re-joins, or activates the
    case again, and the write is retried."""
    share.mark(text)
    why = share_guard.refusal()
    assert share_guard.is_refusal(why) and "has no case marker" in why
    assert "on SIFT, re-join ('vhir setup join-code', then setup-windows.ps1" in why
    assert "'vhir case activate C-1'), then retry" in why


def test_a_marker_naming_another_case_keeps_its_reason(share):
    share.mark("C-2")
    why = share_guard.refusal()
    assert (
        why.endswith("the active case is C-1, it holds case 'C-2'")
        and "re-join (" not in why
    )


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


def _stub_tools(monkeypatch, share):
    """The real run path, with the tool found and its launch recorded: the
    catalog's output folder is created and passed as for a real run."""
    from wintools_mcp.tools import generic

    ran = []
    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")

    def execute(command, **k):
        ran.append(command)
        return {"exit_code": 0, "stdout": "ok", "stderr": ""}

    monkeypatch.setattr(generic, "execute", execute)
    return ran


def _run(monkeypatch, tmp_path, share):
    from wintools_mcp import server as srv

    ran = _stub_tools(monkeypatch, share)
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
    resp, ran = _run(monkeypatch, tmp_path, share)
    assert resp["success"] is False and share_guard.is_refusal(resp["error"])
    assert ran == [] and _files(share.root) == before


def test_sifts_repoint_before_wintools_is_told_is_refused(share, monkeypatch, tmp_path):
    """SIFT moved the share to C-2 and hasn't told wintools yet: nothing of
    C-1's lands in C-2."""
    share.mark("C-2")
    before = _files(share.root)
    resp, ran = _run(monkeypatch, tmp_path, share)
    assert resp["success"] is False and "it holds case 'C-2'" in resp["error"]
    assert ran == [] and _files(share.root) == before


def test_a_run_on_the_active_cases_share_runs_and_is_audited(
    share, monkeypatch, tmp_path
):
    share.mark("C-1")
    resp, ran = _run(monkeypatch, tmp_path, share)
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


# -- every writer, right before it writes


def _batch(share, tmp_path):
    from wintools_mcp import server as srv

    folder = tmp_path / "in"
    folder.mkdir()
    for n in ("a.exe", "b.exe"):
        (folder / n).write_text("x")
    fn = srv.create_server()._tool_manager._tools["batch_scan"].fn
    return fn(tool="sigcheck", directory=str(folder))


@pytest.mark.parametrize("text", WRONG, ids=WRONG_IDS)
def test_a_batch_scan_on_a_share_that_isnt_the_active_case_writes_nothing(
    share, monkeypatch, tmp_path, text
):
    share.mark(text)
    ran = _stub_tools(monkeypatch, share)
    before = _files(share.root)
    resp = _batch(share, tmp_path)
    assert ran == [] and _files(share.root) == before
    assert resp["files_processed"] == 0 and share_guard.is_refusal(resp["errors"][0])
    assert not (share.root / "extractions").exists()


def test_a_batch_scan_on_the_active_cases_share_runs_every_file(
    share, monkeypatch, tmp_path
):
    share.mark("C-1")
    ran = _stub_tools(monkeypatch, share)
    assert _batch(share, tmp_path)["files_processed"] == 2 and len(ran) == 2


def test_an_expired_session_is_recovered_before_the_check(share, monkeypatch, tmp_path):
    """The share answers "Access is denied" until the session is mapped
    again: the run maps it, then checks the marker, then runs."""
    import builtins

    share.mark("C-1")
    mapped = []
    real_open = builtins.open

    def share_open(file, *a, **k):
        if str(file).startswith(str(share.root)) and not mapped:
            raise PermissionError(13, "[WinError 5] Access is denied", str(file))
        return real_open(file, *a, **k)

    monkeypatch.setattr(builtins, "open", share_open)
    monkeypatch.setattr(
        smb, "establish_smb_session", lambda cfg: mapped.append(1) or True
    )
    resp, ran = _run(monkeypatch, tmp_path, share)
    assert mapped == [1] and ran and resp.get("success", True) is not False


def test_a_share_that_stays_unreadable_is_refused_without_a_loop(
    share, monkeypatch, tmp_path
):
    import builtins

    real_open = builtins.open

    def share_open(file, *a, **k):
        if str(file).startswith(str(share.root)):
            raise PermissionError(13, "[WinError 5] Access is denied", str(file))
        return real_open(file, *a, **k)

    tries = []

    def establish(cfg):  # as the real one, it notes its own failure
        tries.append(1)
        smb._note_smb_failure(cfg.share_root, "Access is denied")
        return False

    monkeypatch.setattr(builtins, "open", share_open)
    monkeypatch.setattr(smb, "establish_smb_session", establish)
    resp, ran = _run(monkeypatch, tmp_path, share)
    assert ran == [] and resp["success"] is False and "not accessible" in resp["error"]
    assert len(tries) <= 3  # the run's own check, and its audit's, each try once


def test_a_repoint_while_the_inputs_are_hashed_is_caught(share, monkeypatch, tmp_path):
    """SIFT moves the share to C-2 while the run is still hashing its input:
    nothing is launched into C-2."""
    import builtins

    share.mark("C-1")
    real_open = builtins.open

    def hashing_open(file, mode="r", *a, **k):
        if str(file).endswith("evidence.bin") and "b" in mode:
            (share.root / share_guard.MARKER).write_text("C-2")
        return real_open(file, mode, *a, **k)

    monkeypatch.setattr(builtins, "open", hashing_open)
    before = set(_files(share.root))
    resp, ran = _run(monkeypatch, tmp_path, share)
    assert (
        ran == []
        and resp["success"] is False
        and "it holds case 'C-2'" in resp["error"]
    )
    assert set(_files(share.root)) == before


def test_health_says_why_the_last_run_was_refused(share, monkeypatch, tmp_path):
    from starlette.testclient import TestClient

    from wintools_mcp import http_server
    from wintools_mcp.http_server import create_http_app

    share.mark("C-2")
    _run(monkeypatch, tmp_path, share)
    monkeypatch.setattr(http_server, "get_config", lambda: share.cfg)
    with TestClient(
        create_http_app(share.cfg), raise_server_exceptions=False
    ) as client:
        body = client.get("/health").json()
    assert share_guard.is_refusal(body["evidence_share"])
    share.mark("C-1")
    _run(monkeypatch, tmp_path, share)
    assert audit_mod.share_error() == ""


@pytest.mark.parametrize(
    "text", ["C-10", "c-1", "C-1 ", "C"], ids=["prefix", "case", "space", "short"]
)
def test_the_marker_must_name_the_active_case_exactly(share, text):
    (share.root / share_guard.MARKER).write_text(text)
    if text == "C-1 ":  # surrounding whitespace is the writer's newline, nothing else
        assert share_guard.refusal() == ""
    else:
        assert share_guard.is_refusal(share_guard.refusal())


# -- a session attempt never writes to the share


def _unreachable(monkeypatch, tmp_path):
    """A UNC share that can't be reached at all: net use fails, nothing under
    it can be opened."""
    import builtins
    import os.path

    root = "\\\\sift\\vhir-cases"
    cfg = WintoolsConfig()
    cfg.share_root = cfg.case_dir = root
    cfg.active_case = "C-1"
    cfg.smb_user, cfg.smb_password = "vhir-smb", "pw"
    monkeypatch.setattr(config_mod, "_config", cfg)
    monkeypatch.setenv("VHIR_CASE_DIR", root)
    monkeypatch.delenv("VHIR_AUDIT_DIR", raising=False)
    real_open = builtins.open

    def no_share(file, *a, **k):
        if str(file).startswith(root):
            raise OSError(53, "[WinError 53] The network path was not found")
        return real_open(file, *a, **k)

    monkeypatch.setattr(builtins, "open", no_share)
    failed = subprocess.CompletedProcess(
        [], 2, stdout="", stderr="System error 53 has occurred."
    )
    monkeypatch.setattr(smb.subprocess, "run", lambda *a, **k: failed)
    monkeypatch.setattr(os.path, "isdir", lambda p: False)
    return cfg


def _returns_within(fn, seconds=5.0):
    import threading

    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", fn()), daemon=True)
    t.start()
    t.join(seconds)
    assert "r" in out, "no answer: the call hung"
    return out["r"]


def test_a_session_attempt_on_an_unreachable_share_answers_promptly(
    monkeypatch, tmp_path
):
    cfg = _unreachable(monkeypatch, tmp_path)
    assert _returns_within(lambda: smb.establish_smb_session(cfg)) is False
    assert audit_mod.share_error().endswith("share not reachable")  # for /health
    audit_mod._set_share_error("")


def test_startup_and_new_credentials_on_an_unreachable_share_answer_promptly(
    monkeypatch, tmp_path
):
    """Startup maps the share, and the credentials endpoint maps it again:
    both answer, the endpoint saying the session failed."""
    from starlette.testclient import TestClient

    from wintools_mcp import http_server

    cfg = _unreachable(monkeypatch, tmp_path)
    cfg.api_keys = {"k1": {"examiner": "ex1"}}
    monkeypatch.setattr(http_server, "get_config", lambda: cfg)
    monkeypatch.setattr(http_server, "_persist_config_fields", lambda *a, **k: None)

    def startup_then_update():
        app = http_server.create_http_app(cfg)  # maps the share at startup
        with TestClient(app, raise_server_exceptions=False) as client:
            return client.post("/config/update-smb", json={"smb_password": "pw2"},
                               headers={"Authorization": "Bearer k1"})  # fmt: skip

    resp = _returns_within(startup_then_update, seconds=10)
    assert resp.status_code != 200 or resp.json().get("status") != "ok"
    audit_mod._set_share_error("")


# -- the share's state, /health and the log carry a reason, never the command


def test_a_net_use_timeout_never_shows_its_password(monkeypatch, tmp_path, caplog):
    """net use's command line holds the SMB password; a timeout's text holds
    the command line. Neither reaches /health, the log or the audit."""
    import logging

    from starlette.testclient import TestClient

    from wintools_mcp import http_server

    cfg = _unreachable(monkeypatch, tmp_path)
    cfg.smb_password = "SYNTH-pw-7c1e9b"

    def timeout(cmd, **k):
        raise subprocess.TimeoutExpired(cmd, 15)

    monkeypatch.setattr(smb.subprocess, "run", timeout)
    monkeypatch.setattr(http_server, "get_config", lambda: cfg)
    caplog.set_level(logging.DEBUG)
    with TestClient(
        http_server.create_http_app(cfg), raise_server_exceptions=False
    ) as client:
        body = client.get("/health").text
    assert smb.establish_smb_session(cfg) is False
    seen = [body, audit_mod.share_error(), caplog.text]
    seen += [f.read_text(errors="replace") for f in tmp_path.rglob("*") if f.is_file()]
    assert not any("SYNTH-pw-7c1e9b" in text for text in seen)
    assert audit_mod.share_error().endswith("timed out")
    audit_mod._set_share_error("")


@pytest.mark.parametrize(
    "exc, reason",
    [
        (
            subprocess.TimeoutExpired(["net", "use", "x", "/user:u", "pw"], 15),
            "timed out",
        ),
        (OSError(13, "Permission denied: /secret/path"), "access denied"),
        (
            OSError(64, "The specified network name is no longer available"),
            "share not reachable",
        ),
        (OSError(99, "something new"), "error 99"),
        (ValueError("pw in a message"), "failed (ValueError)"),
    ],
)
def test_a_share_reason_is_a_category_never_the_errors_text(exc, reason):
    assert audit_mod.share_reason(exc) == reason


def test_an_unreachable_share_is_a_fault_not_a_share_without_a_marker(
    share, monkeypatch
):
    """Windows says "not found" (53, 67) for a network path it can't reach:
    with the share itself gone, the reason is the share, never the
    no-marker refusal, so its session is recovered."""
    gone = share.root.parent / "unreachable"  # the mapping points nowhere now
    why = share_guard.check(str(gone), "C-1")
    assert why == "evidence share not accessible: not found"
    assert not share_guard.is_refusal(why)

    def unreachable(path, *a, **k):
        e = FileNotFoundError(2, "The network path was not found")
        e.winerror = 53
        raise e

    monkeypatch.setattr(share_guard.os, "stat", unreachable)
    assert share_guard.check(str(gone), "C-1") == (
        "evidence share not accessible: share not reachable"
    )


def test_a_write_to_an_unreachable_share_recovers_its_session_first(share, monkeypatch):
    from wintools_mcp import smb

    gone = share.root.parent / "unreachable"
    share.cfg.share_root = str(gone)
    tried = []

    def recover(cfg):
        tried.append(cfg.share_root)
        share.cfg.share_root = str(share.root)  # mapped again: the share is back
        share.mark("C-1")
        return True

    monkeypatch.setattr(smb, "establish_smb_session", recover)
    share_guard.before_write(share.cfg)  # no ShareRefused: recovered, then passed
    assert tried == [str(gone)]


def test_a_reachable_share_without_a_marker_is_still_refused(share):
    why = share_guard.check(str(share.root), "C-1")  # no marker written
    assert share_guard.is_refusal(why) and "has no case marker" in why
