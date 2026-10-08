"""The evidence share, when it can't be read or its mapping is stale.

A share the service can't read (access denied, a dropped session) is said on
the call and in /health, and never fails a call or the control endpoints. A
mapping Windows says is already there is a session only once a file written
through it reads back; a stale one is dropped and mapped again. The share is
a local folder here, and net use is a stand-in.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from wintools_mcp import audit as audit_mod
from wintools_mcp import smb
from wintools_mcp.config import WintoolsConfig
from wintools_mcp.http_server import create_http_app


@pytest.fixture
def denied(tmp_path, monkeypatch):
    """A case folder on a share that now refuses access."""
    case = tmp_path / "case"
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: c1\n")
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    monkeypatch.delenv("VHIR_AUDIT_DIR", raising=False)
    real = Path.is_dir

    def is_dir(self, *a, **k):
        if str(self).startswith(str(case)):
            raise PermissionError(13, "Access is denied", str(self))
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "is_dir", is_dir)
    yield case
    audit_mod._set_share_error("")


# -- a share that can't be read


def test_a_denied_share_is_said_and_no_call_fails(denied):
    writer = audit_mod.AuditWriter()
    assert writer.log(tool="t", params={}, result_summary="x") is None  # never raises
    assert audit_mod.share_error().startswith("evidence share not accessible: ")
    assert audit_mod.share_error().endswith(": access denied")


def test_health_answers_and_names_the_denied_share(denied, monkeypatch):
    from wintools_mcp import http_server

    cfg = WintoolsConfig()
    cfg.case_dir = str(denied)
    monkeypatch.setattr(http_server, "get_config", lambda: cfg)
    audit_mod.AuditWriter().log(
        tool="t", params={}, result_summary="x"
    )  # a call meets it
    app = create_http_app(cfg)
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["evidence_share"].startswith("evidence share not accessible: ")


def test_a_share_that_comes_back_clears_the_error(denied, monkeypatch):
    writer = audit_mod.AuditWriter()
    writer.log(tool="t", params={}, result_summary="x")
    assert audit_mod.share_error()
    monkeypatch.undo()  # access restored
    monkeypatch.setenv("VHIR_CASE_DIR", str(denied))
    assert writer.log(tool="t", params={}, result_summary="x")
    assert audit_mod.share_error() == ""


def test_a_run_says_why_it_wasnt_audited(denied, tmp_path, monkeypatch):
    from wintools_mcp import server as srv

    monkeypatch.setattr(
        "wintools_mcp.tools.generic.run_command",
        lambda command, **k: {"exit_code": 0, "stdout": "ok", "stderr": ""},
    )
    evidence = tmp_path / "evidence.bin"
    evidence.write_text("x")
    run = srv.create_server()._tool_manager._tools["run_windows_command"].fn
    resp = run(command=["sigcheck.exe", str(evidence)], purpose="unit test")
    assert any(
        w.startswith("Audit trail unavailable") and "evidence share not accessible" in w
        for w in resp.get("warnings", [])
    ), resp


def test_a_hanging_share_never_delays_health(tmp_path, monkeypatch):
    import time

    from wintools_mcp import http_server

    case = tmp_path / "case"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: c1\n")
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    real = Path.is_dir

    def is_dir(self, *a, **k):
        if str(self).startswith(str(case)):
            time.sleep(5)  # a share that doesn't answer
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "is_dir", is_dir)
    cfg = WintoolsConfig()
    cfg.case_dir = str(case)
    monkeypatch.setattr(http_server, "get_config", lambda: cfg)
    with TestClient(create_http_app(cfg), raise_server_exceptions=False) as client:
        t0 = time.monotonic()
        assert client.get("/health").status_code == 200
        assert time.monotonic() - t0 < 1.0


def test_a_failed_append_shows_in_health(tmp_path, monkeypatch):
    import builtins

    from wintools_mcp import http_server

    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    real_open = builtins.open

    def failing_open(file, mode="r", *a, **k):
        if str(file).startswith(str(audit_dir)) and "a" in mode:
            raise OSError(64, "The specified network name is no longer available")
        return real_open(file, mode, *a, **k)

    writer = audit_mod.AuditWriter(audit_dir=str(audit_dir))
    monkeypatch.setattr(builtins, "open", failing_open)
    try:
        assert writer.log(tool="t", params={}, result_summary="x") is None
    finally:
        monkeypatch.setattr(builtins, "open", real_open)
    cfg = WintoolsConfig()
    monkeypatch.setattr(http_server, "get_config", lambda: cfg)
    with TestClient(create_http_app(cfg), raise_server_exceptions=False) as client:
        body = client.get("/health").json()
    assert body["evidence_share"].endswith(": share not reachable")
    assert writer.log(tool="t", params={}, result_summary="x")  # the share is back
    assert audit_mod.share_error() == ""


# -- a mapping that's already there


def _cfg(share):
    return SimpleNamespace(
        share_root=share, smb_user="vhir-smb", smb_password="pw", active_case="c1"
    )


@pytest.fixture
def net(monkeypatch):
    """net use stand-in: answers in turn from `answers`; records each call."""
    calls: list[list[str]] = []
    answers: list[tuple[int, str]] = []

    def run(cmd, **k):
        calls.append(cmd)
        if "/delete" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        code, err = answers.pop(0)
        return subprocess.CompletedProcess(cmd, code, "", err)

    monkeypatch.setattr(smb.subprocess, "run", run)
    monkeypatch.setattr(smb, "_smb_session_ok", False)
    return SimpleNamespace(calls=calls, answers=answers)


ALREADY = (2, "System error 1219 has occurred. Multiple connections ... already ...")


def test_an_existing_mapping_that_works_is_a_session(net, monkeypatch):
    monkeypatch.setattr(smb, "_probe", lambda share, case: "")
    net.answers += [ALREADY]
    assert smb.establish_smb_session(_cfg("\\\\sift\\cases")) is True
    assert smb.is_smb_session_ok() is True
    assert not any("/delete" in c for c in net.calls)


def test_a_stale_mapping_is_dropped_and_mapped_again(net, monkeypatch):
    probes = iter(["The network name cannot be found", ""])
    monkeypatch.setattr(smb, "_probe", lambda share, case: next(probes))
    net.answers += [ALREADY, (0, "")]
    assert smb.establish_smb_session(_cfg("\\\\sift\\cases")) is True
    assert [("/delete" in c) for c in net.calls] == [False, True, False]
    assert smb.is_smb_session_ok() is True


def test_a_mapping_that_still_fails_is_no_session(net, monkeypatch):
    monkeypatch.setattr(
        smb, "_probe", lambda share, case: "The network name cannot be found"
    )
    net.answers += [ALREADY, (0, "")]
    assert smb.establish_smb_session(_cfg("\\\\sift\\cases")) is False
    assert smb.is_smb_session_ok() is False  # /health says so


def test_a_new_mapping_is_a_session_only_once_the_probe_works(net, monkeypatch):
    monkeypatch.setattr(smb, "_probe", lambda share, case: "Access is denied")
    net.answers += [(0, "")]
    assert smb.establish_smb_session(_cfg("\\\\sift\\cases")) is False
    assert smb.is_smb_session_ok() is False


def test_a_persistent_mapping_counts_only_when_the_probe_works(net, monkeypatch):
    monkeypatch.setattr(smb.os.path, "isdir", lambda p: True)
    monkeypatch.setattr(smb, "_probe", lambda share, case: "Access is denied")
    net.answers += [(2, "System error 53")]
    assert smb.establish_smb_session(_cfg("\\\\sift\\cases")) is False


def test_the_probe_writes_reads_back_and_leaves_nothing(tmp_path):
    (tmp_path / ".vhir-share-case").write_text("c1")
    assert smb._probe(str(tmp_path), "c1") == ""
    assert [p.name for p in tmp_path.iterdir()] == [".vhir-share-case"]


def test_the_probe_says_why_a_folder_cant_be_written(tmp_path):
    missing = tmp_path / "gone"
    assert smb._probe(str(missing), "c1") != ""


def test_a_session_that_worked_before_and_now_fails_is_reported_down(net, monkeypatch):
    monkeypatch.setattr(smb, "_smb_session_ok", True)  # an earlier success
    monkeypatch.setattr(
        smb, "_probe", lambda share, case: "The network name cannot be found"
    )
    net.answers += [ALREADY, (2, "System error 53")]
    assert smb.establish_smb_session(_cfg("\\\\sift\\cases")) is False
    assert smb.is_smb_session_ok() is False


def test_a_failed_log_read_is_noted_too(tmp_path, monkeypatch):
    import builtins

    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    writer = audit_mod.AuditWriter(audit_dir=str(audit_dir))
    assert writer.log(tool="t", params={}, result_summary="x")
    real_open = builtins.open

    def failing_open(file, mode="r", *a, **k):
        if str(file).startswith(str(audit_dir)) and "r" in mode:
            raise OSError(59, "An unexpected network error occurred")
        return real_open(file, mode, *a, **k)

    monkeypatch.setattr(builtins, "open", failing_open)
    try:
        assert writer.get_entries() == []
    finally:
        monkeypatch.setattr(builtins, "open", real_open)
    assert audit_mod.share_error().endswith(": network error")
    audit_mod._set_share_error("")


def test_each_session_attempt_records_its_result_and_when_it_ended(monkeypatch):
    """What /health reads: set at the end of every attempt, failed ones too."""
    import time

    from wintools_mcp import smb

    monkeypatch.setattr(smb, "_smb_last", None)
    cfg = SimpleNamespace(
        share_root=r"\\sift\cases", smb_user="u", smb_password="p", active_case="C-1"
    )

    def refused(*a, **k):
        raise OSError("net use can't run here")

    monkeypatch.setattr(smb, "_net_use", refused)
    before = time.time()
    assert smb.establish_smb_session(cfg) is False
    ok, at = smb._smb_last
    assert ok is False and before <= at <= time.time()
    assert smb.smb_session_state()["checking"] is False
