"""WxTCmd (the one tool whose catalog entry has ``local_work_folder: true``)
runs, in a case, in a new private folder in the server account's temp folder,
removed afterwards, and reads copies of its input and the SQLite files beside
it there; and a case run of a tool with a catalog output flag that writes no
file fails. Each row is named by its id: R1-R4, A1-A15 and B179's SPEC-001 to
SPEC-007e. Popen is a stand-in; no process starts. Values are synthetic.
"""

import hashlib
import io
import json
import os
import pathlib
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_run_records as trr
from test_run_records import _csv, _entries, _evtx, _run, sha

from wintools_mcp import operation
from wintools_mcp.config import get_config
from wintools_mcp.exceptions import ExecutionError, ExecutionTimeoutError
from wintools_mcp.tools import generic

case, tools = trr.case, trr.tools  # fixtures
RAW = Path(__file__).parent / "fixtures" / "raw_output"
DEPLOYED = (RAW / "wxtcmd-1.0-interop-denied.stdout").read_bytes()
CAUSE = "Unable to load DLL 'SQLite.Interop.dll'"
DLL = "SQLite.Interop.dll"
REL = "evidence/ActivitiesCache.db"
LONG = b"Error processing database: " + CAUSE.encode() + b"\r\n"
LONG += b"".join(b"processing record %05d of the timeline\r\n" % i for i in range(400))


@pytest.fixture
def wtemp(tmp_path, monkeypatch):
    """The server account's temp folder, apart from the share."""
    (tmp_path / "wtemp").mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "wtemp"))
    return tmp_path / "wtemp"


@pytest.fixture
def wx(tools, tmp_path):
    exe = tmp_path / "Tools" / "WxTCmd" / "WxTCmd.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"MZ-wxtcmd")
    return {**tools, "wxtcmd": str(exe)}


def _db(case):
    p = case / "evidence" / "ActivitiesCache.db"
    p.write_bytes(b"SQLite format 3\x00synthetic")
    return p


def _wx(case):
    return ["WxTCmd", "-f", str(_db(case))]


def _inside(p, root):
    return Path(p).resolve().is_relative_to(Path(root).resolve())


def _dll(cmd, kw):
    (Path(kw["cwd"]) / DLL).write_bytes(b"MZ-interop")


def _runs(case):
    x = case / "extractions"
    return sorted(p.name for p in x.iterdir()) if x.exists() else []


def _paths(case):
    db, x = str(_db(case)), case / "extractions"
    climb = str(case / "evidence" / ".." / "evidence" / "ActivitiesCache.db")
    (x / "mine").mkdir(parents=True)
    (case / "evidence" / "x.exe").write_bytes(b"MZ-x")
    return SimpleNamespace(db=db, ev=str(_evtx(case)), x=str(x), climb=climb)


@pytest.mark.parametrize("exe", ["WxTCmd", "WxTCmd.exe"], ids=["R1", "R1-os-shaped"])
def test_wxtcmd_runs_in_a_new_private_local_folder_named_by_its_run(
    case, wx, wtemp, exe
):
    """R1-os-shaped: opensearch-mcp sends [WxTCmd.exe, -f, path], no output flag."""
    seen = {}

    def write(cmd, kw):
        st = os.stat(kw["cwd"])
        mode, listing = stat.S_IMODE(st.st_mode), os.listdir(kw["cwd"])
        seen.update(cwd=kw["cwd"], listing=listing, mode=mode, uid=st.st_uid)
        _csv(cmd, kw)

    resp = _run(wx, "wxtcmd", write, command=[exe, "-f", str(_db(case))])
    (entry,) = _entries(case)
    cwd = seen["cwd"]
    assert not _inside(cwd, case) and _inside(cwd, wtemp) and Path(cwd) != wtemp, cwd
    assert Path(cwd).name.startswith(entry["audit_id"] + "-"), (entry, cwd)
    assert seen["listing"] == ["input"] and seen["uid"] == os.geteuid(), seen
    assert seen["mode"] & 0o077 == 0, oct(seen["mode"])
    assert not Path(cwd).exists(), "work folder not removed"
    assert resp["success"] is True, resp.get("error")


def test_r1_guard_unflagged_tool_still_runs_in_its_run_folder(case, tools, wtemp):
    calls = []
    command = ["EvtxECmd", "-f", str(_evtx(case))]
    resp = _run(tools, "evtxecmd", _csv, calls=calls, command=command)
    (entry,) = _entries(case)
    run_folder = (case / "extractions" / entry["audit_id"]).resolve()
    assert Path(calls[0][1]).resolve() == run_folder, calls
    assert resp["success"] is True, resp.get("error")


def test_r1_private_step_runs_on_the_folder_before_the_tool(
    case, wx, wtemp, monkeypatch
):
    order = []
    private = lambda f: order.append(("private", Path(f).resolve()))  # noqa: E731
    monkeypatch.setattr(generic, "_private", private, raising=False)
    tool = lambda cmd, kw: order.append(("tool", Path(kw["cwd"]).resolve()))  # noqa: E731
    _run(wx, "wxtcmd", tool, command=_wx(case))
    assert [k for k, _ in order] == ["private", "tool"] and order[0][1] == order[1][1]


def _raise(e):
    def f(*a, **k):
        raise e

    return f


def _plant(*parts):
    def plant(folder):
        Path(folder, *parts).parent.mkdir(exist_ok=True)
        Path(folder, *parts).write_bytes(b"MZ-planted")

    return plant


NO_FOLDER = {  # row: (what fails, as what, named in the error)
    "R1-private-step-fails": (
        "_private",
        _raise(OSError("icacls exit code 5")),
        "icacls exit code 5",
    ),
    "R1-planted-before-rights": ("_private", _plant(DLL), DLL),
    "A4-planted-subfolder": ("_private", _plant("x64", DLL), "x64"),
    "A10-guard-run-folder-fails": (
        "_make_dir",
        lambda path: "can't make it",
        "",  # its reply has no exit_code: base's KeyError, as before
    ),
    "R1-no-temp-folder": (None, None, "wtemp"),
}


@pytest.mark.parametrize("row", NO_FOLDER)
def test_a_run_with_no_private_empty_folder_is_refused(
    case, wx, wtemp, monkeypatch, row
):
    name, value, named = NO_FOLDER[row]
    if name:
        monkeypatch.setattr(generic, name, value, raising=False)
    else:
        wtemp.chmod(0o500)
    calls = []
    try:
        resp = _run(wx, "wxtcmd", _csv, calls=calls, command=_wx(case))
    finally:
        wtemp.chmod(0o700)
    assert not calls and resp["success"] is False, resp
    assert named in resp["error"] and not list(wtemp.iterdir()), resp["error"]


@pytest.mark.parametrize("stays", [False, True], ids=["R2", "R1-folder-that-stays"])
def test_what_the_tool_leaves_in_its_folder_is_no_output(case, wx, wtemp, stays):
    seen = {}

    def write(cmd, kw):
        _csv(cmd, kw)
        _dll(cmd, kw)
        seen["cwd"] = kw["cwd"]
        os.chmod(kw["cwd"], 0o500 if stays else 0o700)

    try:
        resp = _run(wx, "wxtcmd", write, command=_wx(case))
    finally:
        if Path(seen["cwd"]).exists():
            os.chmod(seen["cwd"], 0o700)
    names = [Path(o["path"]).name for o in resp.get("outputs") or []]
    assert DLL not in names and not list(case.rglob(DLL)), names
    assert resp["success"] is True, resp.get("error")
    warnings = " ".join(resp.get("warnings") or [])
    assert (seen["cwd"] in warnings) is stays, warnings


RAISES = {  # row: (what execute raises, the folder stays, the error starts with)
    "R1-timeout": (ExecutionTimeoutError("timed out after 300s"), False, ""),
    "A5-other-exception": (OSError(5, "Access is denied"), False, ""),
    "A13-timeout-stays": (ExecutionTimeoutError("Command timed out: WxTCmd"), True, ""),
    "A14-unexpected-stays": (
        PermissionError(13, "Access is denied"),
        True,
        "Unexpected error: [Errno 13] Access is denied",
    ),
    "A15-tool-error-stays": (
        ExecutionError("OS error executing WxTCmd: [WinError 5]"),
        True,
        "OS error executing WxTCmd",
    ),
}


@pytest.mark.parametrize("row", RAISES)
def test_the_work_folder_goes_or_is_named_whatever_the_run_raises(
    case, wx, wtemp, monkeypatch, row
):
    exc, stays, start = RAISES[row]
    seen = {}

    def run(command, timeout=None, cwd=None, **kw):
        seen["cwd"] = cwd
        (Path(cwd) / DLL).write_bytes(b"MZ-interop")
        os.chmod(cwd, 0o500 if stays else 0o700)  # 0o500: the DLL still loaded
        raise exc

    monkeypatch.setattr(generic, "execute", run)
    try:
        resp = _run(wx, "wxtcmd", None, command=_wx(case))
    except OSError as e:
        resp = {"success": False, "error": str(e)}
    finally:
        if Path(seen["cwd"]).exists():
            os.chmod(seen["cwd"], 0o700)
    err = resp.get("error") or ""
    assert _inside(seen["cwd"], wtemp) and resp["success"] is False, (seen, resp)
    assert Path(seen["cwd"]).exists() is stays, seen
    assert (seen["cwd"] in err) is stays and err.startswith(start), err
    if isinstance(exc, ExecutionTimeoutError):
        assert resp.get("stopped") == "timeout", resp


WROTE_NOTHING = {  # row: (command, tool writes, stdout, stderr, exit code, in the error)
    "R3-deployed-text": ("wx", None, DEPLOYED, b"", 0, CAUSE),
    "R3-leftover-is-not-a-result": ("wx", _dll, DEPLOYED, b"", 0, CAUSE),
    "R3-saved-output-named-another-way": ("wx", None, DEPLOYED, b"", 0, CAUSE),
    "R3-long-output-head-and-tail": ("wx", None, LONG, b"", 0, (CAUSE, "record 00399")),
    "R3-unflagged-tool": ("ev", None, b"tool output line\n", b"", 0, "tool output"),
    "R3-user-output-folder": ("mine", None, b"x\r\n", b"", 0, "extractions/mine"),
    "A2-nonzero-exit": ("wx", None, b"Error: bad db\r\n", b"", 2, "bad db"),
    "A3-stderr": (
        "wx",
        None,
        b"WxTCmd 1.0\r\n",
        b"Unhandled: disk full\r\n",
        0,
        "disk full",
    ),
}


@pytest.mark.parametrize("row", WROTE_NOTHING)
def test_a_case_run_that_wrote_no_file_failed_and_says_what_it_printed(
    case, wx, wtemp, monkeypatch, row
):
    kind, write, out, err_bytes, rc, said = WROTE_NOTHING[row]
    real_popen, real_execute, spelt = trr._popen, generic.execute, []

    def popen(write, stdout, calls):
        def p(cmd, **kw):
            proc = real_popen(write, stdout, calls)(cmd, **kw)
            proc.stderr = io.BytesIO(err_bytes)
            proc.returncode = proc.wait.return_value = proc.poll.return_value = rc
            return proc

        return p

    def renamed(*a, **kw):  # the saved files' paths, spelt another way
        r = real_execute(*a, **kw)
        for k in ("output_file", "stderr_file"):
            if r.get(k):
                r[k] = f"{Path(r[k]).parent}/./{Path(r[k]).name}"
                spelt.append(r[k])
        return r

    monkeypatch.setattr(trr, "_popen", popen)
    if row == "R3-saved-output-named-another-way":
        monkeypatch.setattr(generic, "execute", renamed)
    p = _paths(case)
    command = ["EvtxECmd", "-f", p.ev] if kind != "wx" else _wx(case)
    command += ["--csv", p.x + "/mine"] if kind == "mine" else []
    tool, binary = ("wxtcmd", "WxTCmd") if kind == "wx" else ("evtxecmd", "EvtxECmd")
    resp = _run(wx, tool, write, stdout=out, command=command)
    (entry,) = _entries(case)
    err = resp.get("error") or ""
    where = "extractions/" + ("mine" if kind == "mine" else entry["audit_id"])
    assert resp["success"] is False and resp["metadata"]["exit_code"] == rc, resp
    assert err.startswith(f"{binary} wrote no file to {where} (exit code {rc})"), err
    said = (said,) if isinstance(said, str) else said
    assert all(s in err for s in said) and len(err) <= 2300, err
    assert any(spelt) or row != "R3-saved-output-named-another-way", "control"
    assert entry["result_summary"].get("error") == err


GUARDS = {  # row: (tool, the tool writes, command); each runs and succeeds
    "R3-guard-csv-written": ("wxtcmd", _csv, lambda p: ["-f", p.db]),
    "R3-guard-user-folder-written": ("evtxecmd", _csv, lambda p: ["-f", p.ev, "--csv", p.x + "/mine"]),
    "R3-guard-stdout-only-tool": ("sigcheck", None, lambda p: [str(Path(p.ev).parent / "x.exe")]),
    "R4-guard-dt-value": ("wxtcmd", _csv, lambda p: ["-f", p.db, "--dt", "yyyy-MM-dd HH:mm:ss"]),
    "R4-guard-csvf-name": ("wxtcmd", _csv, lambda p: ["-f", p.db, "--csvf", "out.csv"]),
    "R4-guard-unflagged-keeps-todays-rules": ("evtxecmd", _csv, lambda p: ["-f", p.ev.replace("evidence", "evidence/../evidence", 1)]),
    "A7-guard-no-case-wxtcmd-runs": ("wxtcmd", _csv, lambda p: ["-f", p.db, "--csv", p.x + "/nc"]),
    "A8-guard-no-case-wrote-nothing": ("evtxecmd", None, lambda p: ["-f", p.ev, "--csv", p.x + "/nc"]),
    "X1-guard-saved-output-unresolvable": ("evtxecmd", _csv, lambda p: ["-f", p.ev]),
    "X1e-guard-saved-stderr-unresolvable": ("evtxecmd", _csv, lambda p: ["-f", p.ev]),
    "X2-guard-user-folder-unlistable": ("evtxecmd", None, lambda p: ["-f", p.ev, "--csv", p.x + "/mine"]),
    "X2M-guard-run-folder-unlistable": ("evtxecmd", None, lambda p: ["-f", p.ev]),
}  # fmt: skip
CSV_SHA = hashlib.sha256(b"TimeCreated,EventId\n").hexdigest()  # what _csv writes
UNLISTED = {"X2": "mine", "X2M": "extractions"}  # listing failed: no wrote-nothing


@pytest.mark.parametrize("row", GUARDS)
def test_guard_runs_the_rules_leave_alone(case, wx, wtemp, monkeypatch, row):
    tool, write, args = GUARDS[row]
    command = [Path(wx[tool]).stem, *args(_paths(case))]
    monkeypatch.setattr(generic, "_account", "LAB\\examiner")
    if row.startswith(("A7", "A8")):
        monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
        get_config().case_dir = ""
    real_execute, real_resolve, saved = generic.execute, pathlib.Path.resolve, []
    fails = {"X1": ("output_file", "stderr_file"), "X1e": ("stderr_file",)}
    real_popen, fails = trr._popen, fails.get(row.split("-")[0], ())

    def popen(*a):  # X1e: the tool also prints to stderr
        def p(cmd, **kw):
            proc = real_popen(*a)(cmd, **kw)
            proc.stderr = io.BytesIO(b"warning\r\n")
            return proc

        return p

    def execute(*a, **kw):
        r = real_execute(*a, **kw)
        saved.extend(r[k] for k in fails if r.get(k))
        return r

    def resolve(self, *a, **kw):  # the share drops while the run is recorded
        if str(self) in saved:
            raise OSError(5, "The network name cannot be found")
        return real_resolve(self, *a, **kw)

    def written(before, folder):
        if UNLISTED[row.split("-")[0]] in str(folder):
            raise PermissionError(13, "Access is denied")
        return real_written(before, folder)

    real_written = operation.written
    if row.startswith("X1"):
        monkeypatch.setattr(generic, "execute", execute)
        monkeypatch.setattr(pathlib.Path, "resolve", resolve)
    if row.startswith("X1e"):
        monkeypatch.setattr(trr, "_popen", popen)
    if row.startswith("X2"):
        monkeypatch.setattr(operation, "written", written)
    calls = []
    resp = _run(wx, tool, write, calls=calls, command=command)
    assert calls and resp["success"] is True and not resp.get("error"), resp
    if row.startswith("X1"):  # recorded as before: the CSV, its hash, the exit code
        (entry,) = _entries(case)
        summary = entry["result_summary"]
        assert saved and summary["output_sha256"] and summary["exit_code"] == 0, entry
        assert saved[-1].endswith("stderr.txt") is row.startswith("X1e"), saved
        csv = {Path(o["path"]).name: o.get("sha256") for o in entry["outputs"]}
        assert csv["20261009_EvtxECmd_Output.csv"] == CSV_SHA, entry
    if row.startswith("X2"):  # the listing error is kept in the record
        assert "Access is denied" in str(_entries(case)), _entries(case)


REFUSED = {  # row: WxTCmd's arguments, the one named; refused before anything
    "R4-absolute-input-with-dotdot": lambda p: (["-f", p.climb], p.climb),
    "R4-attached-input": lambda p: (["-f:" + p.db], "-f:" + p.db),
    "R4-attached-output": lambda p: (["-f", p.db, "--csv=" + p.x], "--csv=" + p.x),
    "R4-relative-output": lambda p: (["-f", p.db, "--csv", "out"], "out"),
    "R4-csvf-with-dotdot": lambda p: (["-f", p.db, "--csvf", "../x.csv"], "../x.csv"),
    "R4-guard-relative-input-climbing": lambda p: (["-f", "../../" + REL], "../../" + REL),
    "R4-guard-relative-input": lambda p: (["-f", REL], REL),
    "A9-relative-input-the-case-lacks": lambda p: (["-f", "nothere/A.db"], "nothere/A.db"),
    "A11-dotdot-behind-a-backslash": lambda p: (["-f", p.db, "--csv", p.x + "\\..\\o"], p.x + "\\..\\o"),
    "A12-flag-in-another-case": lambda p: (["-f", p.db, "--CSV", "out"], "out"),
}  # fmt: skip


@pytest.mark.parametrize("row", REFUSED)
def test_wxtcmd_argument_refused_before_anything(case, wx, wtemp, row):
    args, named = REFUSED[row](_paths(case))
    calls, before = [], _runs(case)
    resp = _run(wx, "wxtcmd", _csv, calls=calls, command=["WxTCmd", *args])
    assert not calls and resp["success"] is False, resp
    assert named in resp["error"], resp["error"]
    assert _runs(case) == before and not list(wtemp.iterdir()), _runs(case)


def _shas(case):
    files = (p for p in (case / "evidence").rglob("*") if p.is_file())
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def _set(case, name, beside):
    """The input (a folder of evtx for hayabusa), the files beside it (a
    trailing 0: empty), Other.db and a folder."""
    ev = case / "evidence"
    (ev / "dbdir").mkdir()
    (ev / "Other.db").write_bytes(b"SQLite format 3\x00other")
    src = ev / name
    if name == "logs":
        src.mkdir()
        (src / "Security.evtx").write_bytes(b"ElfFile-synthetic")
    else:
        src.write_bytes(b"SQLite format 3\x00" + name.encode())
    for s in beside:
        Path(str(src) + s.rstrip("0")).write_bytes(b"" if s[-1] == "0" else s.encode())
    return src


def _fault(kind, side, monkeypatch, src):
    """SPEC-005: unreadable; 005b: gone after its record; 005c: made after
    every record, before the copy (at the work-folder step)."""
    p = Path(str(src) + side)
    if kind == "chmod":
        p.chmod(0)
    real_record, real_folder = operation.file_record, generic._work_folder

    def record(path, root):
        r = real_record(path, root)
        if str(path).endswith(side):
            p.unlink()
        return r

    def work_folder(op_dir):
        p.write_bytes(b"late")
        return real_folder(op_dir)

    if kind == "gone":
        monkeypatch.setattr(operation, "file_record", record)
    if kind == "late":
        monkeypatch.setattr(generic, "_work_folder", work_folder)
    return p


DB, U = "ActivitiesCache.db", "Activities Cache ü.db"
WS = ("-wal", "-shm")
COMP = {
    "none": (),
    "wal-shm": WS,
    "journal": ("-journal",),
    "wal-only": ("-wal",),
    "wal0-shm": ("-wal0", "-shm"),
    "journal0": ("-journal0",),
}
DEF = lambda db, o: (["-f", db], None)  # noqa: E731
B179 = {  # row: (tool, beside the input, its name, args(input, Other.db) -> (args, named if refused), fault)
    "SPEC-001": ("wxtcmd", (), DB, DEF, None),
    "SPEC-001b-dll-named-input": ("wxtcmd", (), DLL, DEF, None),
    "SPEC-001b": ("wxtcmd", ("-wal",), DB, DEF, None),
    **{f"SPEC-002-{c}-{n}": ("wxtcmd", COMP[c], name, DEF, None) for c in COMP for n, name in (("ascii", DB), ("u", U))},
    "SPEC-002b-old-bak": ("wxtcmd", ("-wal", "-old", ".bak"), DB, DEF, None),
    "SPEC-003-guard": ("wxtcmd", WS, DB, DEF, None),
    "SPEC-003b": ("wxtcmd", WS, DB, DEF, None),
    "SPEC-003c": ("wxtcmd", WS, DB, DEF, None),
    "SPEC-003d-guard": ("wxtcmd", WS, DB, DEF, None),
    "SPEC-003e-guard": ("wxtcmd", WS, DB, DEF, None),
    "SPEC-004": ("wxtcmd", WS + ("-journal",), DB, DEF, None),
    "SPEC-005-db-unreadable": ("wxtcmd", WS, DB, DEF, ("chmod", "")),
    "SPEC-005-wal-unreadable": ("wxtcmd", WS, DB, DEF, ("chmod", "-wal")),
    "SPEC-005b-shm-gone": ("wxtcmd", WS, DB, DEF, ("gone", "-shm")),
    "SPEC-005c-late-journal": ("wxtcmd", WS, DB, DEF, ("late", "-journal")),
    "SPEC-006-folder": ("wxtcmd", (), DB, lambda db, o: (["-f", str(Path(db).parent / "dbdir")], "dbdir"), None),
    "SPEC-006b-two-files": ("wxtcmd", (), DB, lambda db, o: (["-f", db, "-f", o], "-f"), None),
    "SPEC-006b-same-file": ("wxtcmd", (), DB, lambda db, o: (["-f", db, "-f", db], "-f"), None),
    "SPEC-007b--F": ("wxtcmd", (), DB, lambda db, o: (["-f", db, "-F", o], ("-F", o)), None),
    "SPEC-007b-/f": ("wxtcmd", (), DB, lambda db, o: (["-f", db, "/f", o], ("/f", o)), None),
    "SPEC-007b---f": ("wxtcmd", (), DB, lambda db, o: (["-f", db, "--f", o], ("--f", o)), None),
    "SPEC-007b-/f-joined": ("wxtcmd", (), DB, lambda db, o: (["-f", db, "/f:" + o], "/f:" + o), None),
    "SPEC-007b-bare": ("wxtcmd", (), DB, lambda db, o: (["-f", db, o], o), None),
    "SPEC-007b-rooted": ("wxtcmd", (), DB, lambda db, o: (["-f", db, "--f", "\\evidence\\Other.db"], "\\evidence"), None),
    "SPEC-007b-drive-relative": ("wxtcmd", (), DB, lambda db, o: (["-f", db, "--f", "Z:Other.db"], "Z:Other.db"), None),
    "SPEC-007b-guard-rooted-after-F": ("wxtcmd", (), DB, lambda db, o: (["-f", db, "-F", "\\evidence\\Other.db"], "\\evidence"), None),
    "SPEC-007b-guard-dash-joined": ("wxtcmd", (), DB, lambda db, o: (["-f", db, "--x=" + o], "--x="), None),
    "SPEC-007-guard-evtxecmd": ("evtxecmd", (), "Security.evtx", DEF, None),
    "SPEC-007c-guard": ("wxtcmd", (), DB, lambda db, o: (["-f", db, "--csvf", "x.csv", "--dt", "yyyy"], None), None),
    "SPEC-007d-guard-hayabusa": ("hayabusa", (), "logs", lambda d, o: (["csv-timeline", "-D", "-d", d], None), None),
    "SPEC-007e-guard-evtx-wal": ("evtxecmd", ("-wal",), "Security.evtx", DEF, None),
}  # fmt: skip
SIDES = ("-wal", "-shm", "-journal")  # what SQLite reads beside a db


@pytest.mark.parametrize("row", B179)
def test_b179_wxtcmd_reads_a_copy_of_its_input(case, wx, wtemp, monkeypatch, row):
    tool, beside, name, args, fault = B179[row]
    src = _set(case, name, beside)
    argv, named = args(str(src), str(src.parent / "Other.db"))
    local = tool == "wxtcmd"
    want = [s.rstrip("0") for s in beside if local and s.rstrip("0") in SIDES]
    if fault and fault[0] == "gone":
        want.remove(fault[1])
    want = {str(Path(str(src) + s).resolve()): sha(str(src) + s) for s in want}
    before, runs, seen, calls = _shas(case), _runs(case), {}, []
    flag = "-d" if tool == "hayabusa" else "-f"

    def stand_in(cmd, kw):  # does what WxTCmd does to the db it is given
        f = cmd[cmd.index(flag) + 1]
        seen.update(cmd=list(cmd), cwd=kw["cwd"], top=os.listdir(kw["cwd"]), f=f)
        if _inside(f, kw["cwd"]):
            seen.update(beside=sorted(os.listdir(Path(f).parent)))
            seen.update(data=Path(f).read_bytes())
            Path(f).write_bytes(b"checkpointed")
            for s in WS:
                Path(f + s).unlink(missing_ok=True)
        if "--csv" in cmd:
            _csv(cmd, kw)

    made = fault and _fault(*fault, monkeypatch, src)
    try:
        command = [Path(wx[tool]).stem, *argv]
        resp = _run(wx, tool, stand_in, calls=calls, command=command)
    finally:
        if made and made.exists():
            made.chmod(0o600)
    if named or (fault and fault[0] != "late"):  # stopped before the tool
        named = (named,) if isinstance(named, str) else named or (made.name,)
        assert not calls and resp["success"] is False, resp
        assert any(n in resp["error"] for n in named), resp["error"]  # any one
        assert not list(wtemp.iterdir()), list(wtemp.iterdir())
        assert fault or (_runs(case) == runs and _shas(case) == before), _runs(case)
        return
    (entry,) = _entries(case)
    guard = "guard" in row  # what a GUARD row checks holds at base too
    assert calls and (resp["success"] is True or tool == "hayabusa"), resp
    for where, inputs in (("reply", resp["inputs"]), ("audit", entry["inputs"])):
        assert [r["path"] for r in inputs] == [str(src.resolve())], (where, inputs)
        got = {c["path"]: c["sha256"] for c in inputs[0].get("companions", [])}
        assert guard or got == want and ("companions" in inputs[0]) is bool(want)
    recorded = {k: v for k, v in entry.items() if k.startswith("input")}
    assert str(wtemp) not in json.dumps(recorded), recorded
    files = [str(src.resolve())] if tool != "hayabusa" else None  # a folder: none
    assert entry.get("input_files") == files, recorded
    after = _shas(case)  # the case's files are only read
    assert {k: after.get(k) for k in before} == before, after
    assert set(after) - set(before) == ({made.name} if made else set()), after
    if not local:
        assert seen["f"] == str(src) and "copy_note" not in resp, (seen, resp)
        assert tool != "hayabusa" or inputs[0]["found"] == "catalog", inputs
        return
    run = str(case / "extractions" / entry["audit_id"])
    assert entry["params"]["command"] == [wx["wxtcmd"], *argv, "--csv", run], entry
    if guard:
        return
    f, cwd = Path(seen["f"]), Path(seen["cwd"])
    assert f.parent == cwd / "input" and seen["top"] == ["input"], seen
    assert f.name == src.name and seen["data"] == src.read_bytes(), seen
    copied = sorted([src.name] + [Path(p).name for p in want])
    assert seen["beside"] == copied, (seen["beside"], copied)
    note = resp.get("copy_note") or ""
    assert "cop" in note and all(n in note for n in copied), note
    others = set(after) - set(copied) - {src.name}
    assert not any(n in note for n in others), (note, others)
    assert json.dumps(note) in json.dumps(entry), entry
