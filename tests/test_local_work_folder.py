"""WxTCmd (the one tool whose catalog entry has ``local_work_folder: true``)
runs, in a case, in a new private folder in the server account's temp folder,
removed afterwards; and a case run of a tool with a catalog output flag that
writes no file fails. Each row is named by its id: R1-R4 and A1-A15. Popen
is a stand-in; no process starts. Values are synthetic.
"""

import io
import os
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_run_records as trr
from test_run_records import _csv, _entries, _evtx, _run

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
    assert seen["listing"] == [] and seen["uid"] == os.geteuid(), seen
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
}  # fmt: skip


@pytest.mark.parametrize("row", GUARDS)
def test_guard_runs_the_rules_leave_alone(case, wx, wtemp, monkeypatch, row):
    tool, write, args = GUARDS[row]
    command = [Path(wx[tool]).stem, *args(_paths(case))]
    monkeypatch.setattr(generic, "_account", "LAB\\examiner")
    if row.startswith(("A7", "A8")):
        monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
        get_config().case_dir = ""
    calls = []
    resp = _run(wx, tool, write, calls=calls, command=command)
    assert calls and resp["success"] is True and not resp.get("error"), resp


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
