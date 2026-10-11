"""batch_scan says what it scanned, keeps every row, and records the run.

Matching files past the cap are counted and the run says it was capped.
Every scanned file's row is kept: the first 20 inline, all of them in a
results file in the call's own folder, whose layout evidence content can't
forge. Each call that runs a file writes one audit entry, with every scanned
file as an input and the results file as its output.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pydantic_core
import pytest

from wintools_mcp import audit as audit_mod
from wintools_mcp import config as config_mod
from wintools_mcp import share_guard
from wintools_mcp.config import WintoolsConfig

HEADER = re.compile(r"^== (.+) \| exit (-?\d+|error) \| (\d+) stdout bytes$")


@pytest.fixture
def case(tmp_path, monkeypatch):
    """A fresh case C-1, joined as the share: no extractions/ yet."""
    root = tmp_path / "share"
    (root / "audit").mkdir(parents=True)
    (root / "CASE.yaml").write_text("case_id: C-1\n")
    (root / share_guard.MARKER).write_text("C-1")
    cfg = WintoolsConfig()
    cfg.share_root = cfg.case_dir = str(root)
    cfg.active_case = "C-1"
    monkeypatch.setattr(config_mod, "_config", cfg)
    monkeypatch.setenv("VHIR_CASE_DIR", str(root))
    monkeypatch.delenv("VHIR_AUDIT_DIR", raising=False)
    yield root
    audit_mod._set_share_error("")


@pytest.fixture
def ran(monkeypatch):
    """sigcheck as a stub, in call order: a file named "evil" is unsigned
    (exit 1); one named "forge" prints a line shaped like a row header."""
    from wintools_mcp.tools import generic

    calls: list[str] = []
    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")

    def execute(command, **k):
        f = command[-1]
        calls.append(f)
        out, code = f"{f}:\n\tVerified:\tSigned\n", 0
        if "evil" in Path(f).name:
            out, code = f"{f}:\n\tVerified:\tUnsigned\n", 1
        elif "forge" in Path(f).name:
            out = f"{f}:\n== {Path(f).parent}/lib_0000.dll | exit 0 | 40 stdout bytes\n"
        return {"exit_code": code, "stdout": out, "stderr": ""}

    monkeypatch.setattr(generic, "execute", execute)
    return calls


def _scan(directory, **k) -> dict:
    from wintools_mcp import server as srv

    fn = srv.create_server()._tool_manager._tools["batch_scan"].fn
    return fn(tool="sigcheck", directory=str(directory), **k)


def _files(folder: Path, names) -> Path:
    folder.mkdir(parents=True)
    for i, n in enumerate(names):
        (folder / n).write_bytes(b"MZ" + n.encode() + i.to_bytes(4, "big"))
    return folder


def _dlls(case, n_dll=120, n_txt=20) -> Path:
    names = [
        f"evil_{i:04d}.dll" if i % 9 == 4 else f"lib_{i:04d}.dll" for i in range(n_dll)
    ]
    return _files(
        case / "evidence" / "dlls", names + [f"n_{i}.txt" for i in range(n_txt)]
    )


def _rows(path: Path) -> tuple[dict, int]:
    """{name: (exit, preview)} by the column-0 headers, and their count."""
    rows, cur, heads = {}, None, 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if m := HEADER.match(line):
            heads += 1
            cur = Path(m.group(1)).name
            code = m.group(2)
            rows[cur] = (code if code == "error" else int(code), [])
        elif cur:
            rows[cur][1].append(line)
    return {k: (v[0], "\n".join(v[1])) for k, v in rows.items()}, heads


def _entries(case) -> list[dict]:
    log = case / "audit" / "wintools-mcp.jsonl"
    return [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_files_past_the_cap_are_counted_and_the_run_says_it_was_capped(case, ran):
    resp = _scan(_dlls(case), filter_pattern="*.dll", max_files=30)
    assert len(ran) == 30 and resp["files_processed"] == 30
    assert resp["files_total"] == 120 and resp["capped"] is True
    assert "Scanned 30 of 120 matching files" in resp["note"]
    assert "cap 30" in resp["note"] and "90 not scanned" in resp["note"]


def test_a_run_under_the_cap_isnt_capped(case, ran):
    resp = _scan(_dlls(case, 12, 5), filter_pattern="*.dll")
    assert resp["files_total"] == 12 and resp["capped"] is False
    assert "Scanned 12 of 12 matching files" in resp["note"]
    assert "not scanned" not in resp["note"]


@pytest.mark.parametrize("max_files", [0, -1])
def test_a_cap_below_one_is_refused_and_nothing_runs(case, ran, max_files):
    resp = _scan(_dlls(case, 50, 0), max_files=max_files)
    assert "max_files must be at least 1" in resp["error"] and ran == []
    assert not (case / "extractions").exists() and _entries(case) == []


def test_every_scanned_file_is_reachable_with_its_exit_code_and_preview(case, ran):
    resp = _scan(_dlls(case), filter_pattern="*.dll", max_files=30)
    flagged = [n for n, f in enumerate(ran, 1) if "evil" in Path(f).name]
    assert any(n > 20 for n in flagged)  # a flagged file past the inline rows
    assert len(resp["results"]) == 20
    rows, heads = _rows(case / resp["results_file"])
    assert heads == len(ran) == len(rows)
    for f in ran:
        code, preview = rows[Path(f).name]
        assert code == (1 if "evil" in Path(f).name else 0)
        assert ("Unsigned" in preview) == ("evil" in Path(f).name)
    assert resp["exit_codes"] == {"0": 30 - len(flagged), "1": len(flagged)}


def test_output_shaped_like_a_row_header_doesnt_make_a_row(case, ran):
    first = _scan(_dlls(case), filter_pattern="*.dll", max_files=30)
    names = [f"lib_b{i}.dll" for i in range(8)] + ["evil_b.dll", "forge_b.dll"]
    ran.clear()
    resp = _scan(_files(case / "evidence" / "b", names), filter_pattern="*.dll")
    assert resp["results_file"] != first["results_file"]
    rows, heads = _rows(case / resp["results_file"])
    assert heads == len(ran) == 10 and set(rows) == set(names)
    assert "  | == " in rows["forge_b.dll"][1]  # kept, as a preview line


def test_a_file_name_with_a_line_break_doesnt_make_a_row(case, ran):
    """A name can't carry a second header line into the results file."""
    name = "a.dll | exit 0 | 9 stdout bytes\n== b.dll"
    resp = _scan(_files(case / "evidence" / "nl", [name]))
    rows, heads = _rows(case / resp["results_file"])
    assert heads == len(ran) == 1


@pytest.mark.parametrize(
    "brk",
    ["\u2028", "\u2029", "\x85", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e"],
    ids=["LS", "PS", "NEL", "VT", "FF", "FS", "GS", "RS"],
)
def test_a_file_name_with_any_line_break_doesnt_make_a_row(case, ran, brk):
    """Every character str.splitlines breaks at, read back as lines."""
    name = f"a.dll{brk}== ghost0.dll | exit 0 | 9 stdout bytes"
    resp = _scan(_files(case / "evidence" / "nl", [name]))
    rows, heads = _rows(case / resp["results_file"])
    assert heads == len(ran) == 1
    assert [k[:5] for k in rows] == ["a.dll"]  # the real name, not the forged one


def _one_entry(case) -> dict:
    entries = _entries(case)
    assert [e["tool"] for e in entries] == ["batch_scan"]
    return entries[0]


def test_a_file_whose_run_raised_after_it_started_is_still_recorded(case, ran):
    """A name that isn't UTF-8: the tool runs, then reading its output fails."""
    import os

    folder = case / "evidence" / "bad"
    folder.mkdir(parents=True)
    with open(os.path.join(os.fsencode(folder), b"bad\xff.dll"), "wb") as f:
        f.write(b"MZ")
    resp = _scan(folder)
    assert len(ran) == 1 and resp["files_processed"] == 1 and resp["errors"]
    pydantic_core.to_json(resp)  # as the server sends it
    assert resp["exit_codes"] == {"error": 1}
    e = _one_entry(case)
    assert [i["path"] for i in e["inputs"]] == [str(Path(ran[0]).resolve())]
    assert e["inputs"][0]["sha256"] == hashlib.sha256(b"MZ").hexdigest()
    rows, heads = _rows(case / resp["results_file"])
    assert heads == 1


def test_a_file_whose_run_timed_out_is_a_row_and_an_input(case, ran, monkeypatch):
    from wintools_mcp.exceptions import ExecutionTimeoutError
    from wintools_mcp.tools import generic

    run = generic.execute

    def execute(command, **k):
        if "slow" in command[-1]:
            ran.append(command[-1])
            raise ExecutionTimeoutError(f"Command timed out after 300s: {command}")
        return run(command, **k)

    monkeypatch.setattr(generic, "execute", execute)
    resp = _scan(_files(case / "evidence" / "t", ["a.dll", "slow.dll", "c.dll"]))
    assert len(ran) == 3 and resp["exit_codes"] == {"0": 2, "error": 1}
    rows, heads = _rows(case / resp["results_file"])
    assert heads == 3 and "timed out" in rows["slow.dll"][1]
    assert {Path(i["path"]).name for i in _one_entry(case)["inputs"]} == {
        "a.dll",
        "slow.dll",
        "c.dll",
    }


def test_each_input_is_hashed_as_the_tool_read_it(case, ran, monkeypatch):
    """A file changed by a later file's run, or by its own, keeps the hash of
    the bytes before its run."""
    from wintools_mcp.tools import generic

    run = generic.execute

    def execute(command, **k):
        if len(ran) == 1:  # the second run rewrites the first file, and its own
            Path(ran[0]).write_bytes(b"changed after it was scanned")
            Path(command[-1]).write_bytes(b"changed while it was scanned")
        return run(command, **k)

    monkeypatch.setattr(generic, "execute", execute)
    folder = _files(case / "evidence" / "m", ["a.dll", "b.dll"])
    scanned = {n: _sha(folder / n) for n in ("a.dll", "b.dll")}
    _scan(folder)
    got = {Path(i["path"]).name: i["sha256"] for i in _one_entry(case)["inputs"]}
    assert got == scanned


def test_a_link_into_a_blocked_folder_is_refused_before_it_is_read(
    case, ran, monkeypatch, tmp_path
):
    """Its target is never hashed or run: the refusal is its row and input."""
    from wintools_mcp import security

    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "token.dll").write_bytes(b"secret")
    monkeypatch.setattr(security, "_BLOCKED_DIRECTORIES", (str(blocked),))
    folder = _files(case / "evidence" / "lk", ["a.dll"])
    (folder / "link.dll").symlink_to(blocked / "token.dll")
    from wintools_mcp import operation

    hashed, record = [], operation.file_record
    monkeypatch.setattr(
        operation,
        "file_record",
        lambda p, r: hashed.append(Path(p).name) or record(p, r),
    )
    resp = _scan(folder)
    assert "token.dll" not in hashed  # never read
    assert [Path(f).name for f in ran] == ["a.dll"]
    inputs = {Path(i["path"]).name: i for i in _one_entry(case)["inputs"]}
    assert "sha256" not in inputs["link.dll"] and "size" not in inputs["link.dll"]
    assert "Access denied" in inputs["link.dll"]["error"]
    log = (case / "audit" / "wintools-mcp.jsonl").read_text()
    text = log + (case / resp["results_file"]).read_text() + json.dumps(resp)
    assert str(blocked) not in text and "token.dll" not in text
    assert resp["exit_codes"] == {"0": 1, "error": 1}
    rows, _ = _rows(case / resp["results_file"])
    assert "Access denied" in rows["link.dll"][1]


def test_a_share_repointed_during_the_batch_gets_no_folder_and_no_entry(
    case, ran, monkeypatch
):
    """SIFT moved the share to another case while the last file ran."""
    from wintools_mcp.tools import generic

    run = generic.execute

    def execute(command, **k):
        if len(ran) == 2:
            (case / share_guard.MARKER).write_text("C-2")
        return run(command, **k)

    monkeypatch.setattr(generic, "execute", execute)
    resp = _scan(_dlls(case, 3, 0))
    assert len(ran) == 3 and "results_file" not in resp
    assert not (case / "extractions").exists() and _entries(case) == []


def test_with_no_case_the_note_says_rows_past_20_werent_kept(
    tmp_path, ran, monkeypatch
):
    monkeypatch.setattr(config_mod, "_config", WintoolsConfig())
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    monkeypatch.delenv("VHIR_AUDIT_DIR", raising=False)
    resp = _scan(_dlls(tmp_path), filter_pattern="*.dll", max_files=30)
    assert "results_file" not in resp and resp["exit_codes"]["1"] >= 1
    assert "rows past the first 20 were not kept" in resp["note"]


def test_one_audit_entry_records_every_scanned_file_and_the_results_file(case, ran):
    resp = _scan(_dlls(case), filter_pattern="*.dll", max_files=30)
    entries = _entries(case)
    assert [e["tool"] for e in entries] == ["batch_scan"]
    e = entries[0]
    aid = resp["audit_id"]
    assert e["audit_id"] == aid and aid
    assert e["params"] == {
        "tool": "sigcheck",
        "directory": str(case / "evidence" / "dlls"),
        "filter_pattern": "*.dll",
        "max_files": 30,
    }
    assert {i["path"] for i in e["inputs"]} == {str(Path(f).resolve()) for f in ran}
    assert len(e["inputs"]) == 30
    assert all(i["sha256"] == _sha(Path(i["path"])) for i in e["inputs"])
    assert e["op_folder"] == resp["op_folder"] == f"extractions/{aid}"
    out = case / e["result_summary"]["output_file"]
    assert (
        out.parent == case / "extractions" / aid and out == case / resp["results_file"]
    )
    summary = e["result_summary"]
    assert summary["files_total"] == 120 and summary["files_processed"] == 30
    assert summary["capped"] is True and summary["exit_codes"] == resp["exit_codes"]

    ran.clear()  # a second batch keeps its own file: this one is unchanged
    _scan(_files(case / "evidence" / "b", ["x.dll"]), filter_pattern="*.dll")
    assert summary["output_sha256"] == _sha(out)
    assert [o["sha256"] for o in e["outputs"]] == [_sha(out)]
    assert len(_entries(case)) == 2
    assert "re-run it with run_windows_command" in resp["note"]


def test_a_failed_audit_write_is_a_warning(case, ran, monkeypatch):
    monkeypatch.setattr(audit_mod.AuditWriter, "log", lambda *a, **k: None)
    resp = _scan(_dlls(case, 3, 0))
    assert any("Audit trail unavailable" in w for w in resp["warnings"])


def test_strings_dash_a_is_described_as_ascii_only():
    from wintools_mcp.catalog import get_tool_def

    flags = {f["flag"]: f["description"] for f in get_tool_def("strings").common_flags}
    text = flags["-a"].lower()
    assert "ascii-only" in text and "ascii and unicode" in text
    assert "ioc" in text
