"""What a run in a case records: its own folder, the command it ran, the tool
and its settings, its inputs and outputs by path and hash, and its stdout as
the bytes the tool wrote.

The share is a local folder that is the active case; the tool is a stand-in
file, and Popen is replaced by a function that writes what the tool would.
No process starts. Values are synthetic.
"""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from wintools_mcp import server as srv


def sha(path_or_bytes) -> str:
    data = (
        path_or_bytes
        if isinstance(path_or_bytes, bytes)
        else Path(path_or_bytes).read_bytes()
    )
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def case(tmp_path, monkeypatch):
    """An active case on a share that is that case."""
    case = tmp_path / "share"
    (case / "audit").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "CASE.yaml").write_text("case_id: c1\n")
    (case / ".vhir-share-case").write_text("c1")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    monkeypatch.setenv("VHIR_SHARE_ROOT", str(case))
    monkeypatch.setenv("VHIR_ACTIVE_CASE", "c1")
    monkeypatch.delenv("VHIR_AUDIT_DIR", raising=False)
    return case


@pytest.fixture
def tools(tmp_path):
    """Stand-in tool files, each beside its settings folders."""
    root = tmp_path / "Tools"
    evtx = root / "EvtxECmd" / "EvtxECmd.exe"
    (evtx.parent / "Maps").mkdir(parents=True)
    evtx.write_bytes(b"MZ-evtxecmd")
    (evtx.parent / "Maps" / "Security_4624.map").write_text("Provider: x\n")
    pmem = root / "winpmem.exe"
    pmem.write_bytes(b"MZ-winpmem")
    sig = root / "sigcheck.exe"
    sig.write_bytes(b"MZ-sigcheck")
    hay = root / "hayabusa" / "hayabusa.exe"
    hay.parent.mkdir()
    hay.write_bytes(b"MZ-hayabusa")
    return {
        "evtxecmd": str(evtx),
        "winpmem": str(pmem),
        "sigcheck": str(sig),
        "hayabusa": str(hay),
    }


def _popen(write=None, stdout=b"tool output line\n", calls=None):
    def popen(cmd, **kw):
        if calls is not None:
            calls.append((list(cmd), kw.get("cwd")))
        if write:
            write(cmd, kw)
        proc = MagicMock()
        proc.stdout = io.BytesIO(stdout)
        proc.stderr = io.BytesIO(b"")
        proc.returncode = 0
        proc.wait.return_value = 0
        proc.poll.return_value = 0
        proc.pid = 4242
        return proc

    return popen


def _run(tools, tool, write=None, stdout=b"tool output line\n", calls=None, **args):
    run = srv.create_server()._tool_manager._tools["run_windows_command"].fn
    with (
        patch(
            "wintools_mcp.tools.generic.find_tool",
            side_effect=lambda name: tools[tool],
        ),
        patch(
            "wintools_mcp.executor.subprocess.Popen",
            side_effect=_popen(write, stdout, calls),
        ),
    ):
        return run(purpose="row", **args)


def _entries(case: Path) -> list[dict]:
    log = case / "audit" / "wintools-mcp.jsonl"
    lines = log.read_text().splitlines() if log.exists() else []
    return [json.loads(x) for x in lines]


def _csv(cmd, kw):
    out = Path(cmd[cmd.index("--csv") + 1])
    out.mkdir(parents=True, exist_ok=True)
    (out / "20261009_EvtxECmd_Output.csv").write_text("TimeCreated,EventId\n")


def _evtx(case: Path) -> Path:
    ev = case / "evidence" / "Security.evtx"
    ev.write_bytes(b"ElfFile-synthetic")
    return ev


def test_a_run_in_a_case_has_its_own_folder_named_by_its_audit_id(case, tools):
    ev = _evtx(case)
    resp = _run(tools, "evtxecmd", _csv, command=["EvtxECmd", "-f", str(ev)])
    (entry,) = _entries(case)
    op = case / "extractions" / entry["audit_id"]
    csv = op / "20261009_EvtxECmd_Output.csv"
    assert csv.is_file()
    assert not (case / "extractions" / "evtxecmd").exists()
    assert entry["op_folder"] == resp["op_folder"] == f"extractions/{entry['audit_id']}"
    listed = {o["sift_path"]: o for o in entry["outputs"]}
    rel = f"extractions/{entry['audit_id']}/{csv.name}"
    assert listed[rel]["sha256"] == sha(csv)
    assert (
        listed[rel]["share_path"] == rel and listed[rel]["size"] == csv.stat().st_size
    )


def test_the_entry_records_the_command_that_ran_and_the_tool_and_its_settings(
    case, tools
):
    ev = _evtx(case)
    _run(tools, "evtxecmd", _csv, command=["EvtxECmd", "-f", str(ev)])
    (entry,) = _entries(case)
    op = str(case / "extractions" / entry["audit_id"])
    assert entry["params"]["command"] == [tools["evtxecmd"], "-f", str(ev), "--csv", op]
    assert entry["requested_command"] == ["EvtxECmd", "-f", str(ev)]
    assert entry["tool_sha256"] == sha(tools["evtxecmd"])
    (maps,) = entry["settings"]
    the_map = Path(tools["evtxecmd"]).parent / "Maps" / "Security_4624.map"
    assert maps["files"] == 1
    assert maps["sha256"] == sha(f"Security_4624.map {sha(the_map)}\n".encode())
    manifest = json.loads(Path(maps["manifest"]).read_text())
    assert manifest == {"Security_4624.map": sha(the_map)}
    assert maps["manifest_sha256"] == sha(maps["manifest"])
    # the manifest is the run's record, not one of the tool's outputs
    assert all("settings-" not in o["path"] for o in entry["outputs"])


def test_inputs_come_from_the_command_and_a_listed_extra_is_declared(case, tools):
    ev = _evtx(case)
    other = case / "evidence" / "other.evtx"
    other.write_bytes(b"other")
    _run(
        tools,
        "evtxecmd",
        _csv,
        command=["EvtxECmd", "-f", str(ev)],
        input_files=[str(other)],
    )
    (entry,) = _entries(case)
    by_path = {Path(i["path"]).name: i for i in entry["inputs"]}
    assert by_path["Security.evtx"]["found"] == "catalog"
    assert by_path["Security.evtx"]["sha256"] == sha(ev)
    assert by_path["Security.evtx"]["sift_path"] == "evidence/Security.evtx"
    assert by_path["other.evtx"]["found"] == "declared"
    assert entry["input_files"] == [str(ev.resolve())]  # the parsed ones only
    assert entry["input_sha256s"] == [sha(ev)]
    assert entry["input_detection_method"] == "catalog"


def test_a_file_over_the_limit_is_recorded_pending_not_hashed(case, tools, monkeypatch):
    monkeypatch.setattr("wintools_mcp.operation.HASH_LIMIT", 10)
    ev = _evtx(case)  # 17 bytes
    _run(tools, "evtxecmd", _csv, command=["EvtxECmd", "-f", str(ev)])
    (entry,) = _entries(case)
    (inp,) = entry["inputs"]
    assert inp["hash_state"] == "pending" and "sha256" not in inp
    assert inp["share_path"] == "evidence/Security.evtx"
    assert entry["input_sha256s"] == ["pending"]
    big = [o for o in entry["outputs"] if o["size"] > 10]
    assert big and all(o.get("hash_state") == "pending" for o in big)


def test_with_a_case_active_every_call_runs_the_tool(case, tools):
    target = case / "evidence" / "x.exe"
    target.write_bytes(b"MZ-x")
    calls = []
    for _ in range(2):
        _run(tools, "sigcheck", calls=calls, command=["sigcheck", str(target)])
    assert len(calls) == 2
    assert len(_entries(case)) == 2


def test_without_a_case_a_repeated_call_is_still_answered_from_the_cache(
    tmp_path, tools, monkeypatch
):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    for name in ("VHIR_CASE_DIR", "VHIR_SHARE_ROOT", "VHIR_ACTIVE_CASE"):
        monkeypatch.delenv(name, raising=False)
    target = tmp_path / "x.exe"
    target.write_bytes(b"MZ-x")
    calls = []
    for _ in range(2):
        resp = _run(tools, "sigcheck", calls=calls, command=["sigcheck", str(target)])
    assert len(calls) == 1
    assert "op_folder" not in resp


@pytest.mark.parametrize(
    "stdout, encoding",
    [
        (b"caf\xe9 \xff not utf-8\r\nline 2\n", "utf-8"),
        ("sigcheck output\r\n".encode("utf-16-le"), "utf-16-le"),
        (b"\xff\xfe" + "with a BOM\r\n".encode("utf-16-le"), "utf-16"),
        (b"", "utf-8"),
    ],
    ids=["non-utf8-byte", "utf16le", "utf16-bom", "empty"],
)
def test_stdout_is_saved_as_the_bytes_the_tool_wrote(case, tools, stdout, encoding):
    target = case / "evidence" / "x.exe"
    target.write_bytes(b"MZ-x")
    _run(tools, "sigcheck", stdout=stdout, command=["sigcheck", str(target)])
    (entry,) = _entries(case)
    summary = entry["result_summary"]
    saved = Path(summary["output_file"])
    assert saved.parent == case / "extractions" / entry["audit_id"]
    assert saved.read_bytes() == stdout  # even a small or empty one
    assert summary["output_sha256"] == sha(stdout)
    assert summary["output_sha256_scope"] == "raw_stdout"
    assert summary["stdout_encoding"] == encoding
    assert any(o["path"] == str(saved) for o in entry["outputs"])


def test_an_acquisition_lands_in_the_op_folder_hashed_and_marked(case, tools):
    def dump(cmd, kw):  # winpmem <outfile>, relative to where it runs
        (Path(kw["cwd"]) / cmd[-1]).write_bytes(b"FAKE-PHYSMEM")

    _run(tools, "winpmem", dump, command=["winpmem", "memdump.raw"])
    (entry,) = _entries(case)
    dump_file = case / "extractions" / entry["audit_id"] / "memdump.raw"
    assert dump_file.read_bytes() == b"FAKE-PHYSMEM"
    assert {o["path"]: o.get("sha256") for o in entry["outputs"]}[
        str(dump_file)
    ] == sha(dump_file)
    assert entry["acquisition"] is True and entry["acquisition_tool"] == "winpmem"


def test_a_run_that_is_not_an_acquisition_is_not_marked(case, tools):
    ev = _evtx(case)
    _run(tools, "evtxecmd", _csv, command=["EvtxECmd", "-f", str(ev)])
    (entry,) = _entries(case)
    assert "acquisition" not in entry


def test_what_a_user_given_output_folder_gains_is_listed_and_nothing_else(case, tools):
    ev = _evtx(case)
    out = case / "work" / "evtx"
    out.mkdir(parents=True)
    earlier = out / "earlier.csv"
    earlier.write_text("old\n")
    _run(
        tools, "evtxecmd", _csv, command=["EvtxECmd", "-f", str(ev), "--csv", str(out)]
    )
    (entry,) = _entries(case)
    listed = {o["sift_path"]: o for o in entry["outputs"]}
    new = out / "20261009_EvtxECmd_Output.csv"
    assert listed["work/evtx/20261009_EvtxECmd_Output.csv"]["sha256"] == sha(new)
    assert "work/evtx/earlier.csv" not in listed
    assert entry["params"]["command"].count("--csv") == 1  # nothing injected


def test_a_tools_own_output_flag_given_by_the_user_is_not_injected_again(case, tools):
    evtx_dir = case / "evidence"
    out = case / "work" / "hayabusa.jsonl"
    out.parent.mkdir()

    def write(cmd, kw):
        Path(cmd[cmd.index("--json-output") + 1]).write_text("{}\n")

    _run(
        tools,
        "hayabusa",
        write,
        command=["hayabusa", "-d", str(evtx_dir), "--json-output", str(out)],
    )
    (entry,) = _entries(case)
    assert entry["params"]["command"].count("--json-output") == 1
    listed = {o["sift_path"]: o for o in entry["outputs"]}
    assert listed["work/hayabusa.jsonl"]["sha256"] == sha(out)
    folder = {Path(i["path"]).name: i for i in entry["inputs"]}["evidence"]
    assert folder["folder"] is True and "sha256" not in folder


def test_a_folder_left_by_a_run_that_died_is_never_taken_over(case, tools, monkeypatch):
    from wintools_mcp.audit import AuditWriter

    monkeypatch.setattr(
        AuditWriter, "_next_audit_id", lambda self, *a, **k: "wintools-row-000001"
    )
    dead = case / "extractions" / "wintools-row-000001"
    dead.mkdir(parents=True)
    (dead / "left-by-the-dead-run.raw").write_bytes(b"NOT THIS RUN'S")
    ev = _evtx(case)
    resp = _run(tools, "evtxecmd", _csv, command=["EvtxECmd", "-f", str(ev)])
    (entry,) = _entries(case)
    assert (
        entry["op_folder"] == resp["op_folder"] == "extractions/wintools-row-000001-2"
    )
    names = {Path(o["path"]).name for o in entry["outputs"]}
    assert "20261009_EvtxECmd_Output.csv" in names
    assert "left-by-the-dead-run.raw" not in names
    assert (dead / "left-by-the-dead-run.raw").read_bytes() == b"NOT THIS RUN'S"


def test_a_settings_folder_that_cannot_be_read_still_records_the_run(
    case, tools, monkeypatch
):
    def locked(*a, **k):
        raise PermissionError(13, "The process cannot access the file")

    monkeypatch.setattr("wintools_mcp.operation.settings_record", locked)
    ev = _evtx(case)
    _run(tools, "evtxecmd", _csv, command=["EvtxECmd", "-f", str(ev)])
    (entry,) = _entries(case)
    assert entry["result_summary"]["exit_code"] == 0
    assert entry["outputs"] and entry["inputs"]
    (rec,) = entry["settings"]
    assert "cannot access" in rec["error"]


def test_a_relative_input_in_a_case_is_read_from_the_runs_folder(
    case, tools, monkeypatch
):
    monkeypatch.chdir(case / "evidence")
    (case / "evidence" / "here.evtx").write_bytes(b"E")
    calls = []
    resp = _run(
        tools, "evtxecmd", _csv, calls=calls, command=["EvtxECmd", "-f", "here.evtx"]
    )
    assert resp["success"] is False and "not accessible" in resp["error"], resp
    assert calls == []  # never run against a file it wouldn't have read


def test_an_acquisition_written_outside_the_case_is_recorded_unhashed(
    case, tools, tmp_path
):
    outside = tmp_path / "elsewhere" / "mem.raw"
    outside.parent.mkdir()

    def dump(cmd, kw):
        Path(cmd[-1]).write_bytes(b"FAKE-PHYSMEM")

    _run(tools, "winpmem", dump, command=["winpmem", str(outside)])
    (entry,) = _entries(case)
    (rec,) = [o for o in entry["outputs"] if o["path"] == str(outside)]
    assert rec["outside_case"] is True and "sha256" not in rec
    assert rec["note"] == (
        "outside the case: not hashed, not registrable until copied into the case"
    )
    assert entry["acquisition"] is True


def test_a_relative_input_is_never_read_from_a_dead_runs_folder(
    case, tools, monkeypatch
):
    from wintools_mcp.audit import AuditWriter

    monkeypatch.setattr(
        AuditWriter, "_next_audit_id", lambda self, *a, **k: "wintools-row-000002"
    )
    dead = case / "extractions" / "wintools-row-000002"
    dead.mkdir(parents=True)
    (dead / "here.evtx").write_bytes(b"LEFT BY THE DEAD RUN")
    calls = []
    resp = _run(
        tools, "evtxecmd", _csv, calls=calls, command=["EvtxECmd", "-f", "here.evtx"]
    )
    assert resp["success"] is False and "not accessible" in resp["error"], resp
    assert "wintools-row-000002-2" in resp["error"]
    assert calls == [] and _entries(case) == []


def test_one_output_folder_that_cannot_be_listed_keeps_the_others(
    case, tools, monkeypatch
):
    from wintools_mcp import operation

    ev = _evtx(case)
    out = case / "work" / "evtx"
    out.mkdir(parents=True)
    real = operation.written

    def written(before, folder):
        if Path(folder) == out:
            raise PermissionError(13, "The process cannot access the file")
        return real(before, folder)

    monkeypatch.setattr(operation, "written", written)
    _run(
        tools, "evtxecmd", _csv, command=["EvtxECmd", "-f", str(ev), "--csv", str(out)]
    )
    (entry,) = _entries(case)
    errors = [o for o in entry["outputs"] if "error" in o]
    assert [(o["path"], "cannot access" in o["error"]) for o in errors] == [
        (str(out), True)
    ]
    kept = [o for o in entry["outputs"] if "sha256" in o]
    assert kept and all(
        o["sift_path"].startswith(entry["op_folder"] + "/") for o in kept
    )
