"""A Sysinternals tool's EULA is accepted only when the account running
wintools hasn't accepted it, and the reply says so.

Before a catalogued Sysinternals tool runs, wintools reads the tool's
`EulaAccepted` value in the running account's own hive. Set: the run is
unchanged and says nothing. Not set, or unreadable: the run passes
-accepteula (once, whoever passed it) and the reply and its audit entry carry
one note that the EULA was accepted on the examiner's behalf; a batch carries
one note, not one per file. The registry is a stand-in here: a tool run with
-accepteula sets its key, as the real tools do. Values are synthetic.
"""

from __future__ import annotations

import json
import sys
import types

import pydantic_core
import pytest
from test_batch_scan import _entries, _files, case  # noqa: F401 - fixtures
from test_eula_surrogate import EULA

from wintools_mcp import catalog
from wintools_mcp import server as srv
from wintools_mcp.tools import generic

ON_BEHALF = "was accepted on the examiner's behalf"
FLAG = "-accepteula"
# each tool's key under Software\\Sysinternals, by the binary run
KEYS = {"autorunsc": "AutoRuns", "strings64": "Strings", "handle64": "Handle",
        "procdump64": "ProcDump", "sigcheck": "sigcheck"}  # fmt: skip
ACCOUNT = "nt authority\\system"  # whoami, as SYSTEM (measured on the guest)


def _sent(r: dict) -> dict:
    return json.loads(pydantic_core.to_json(r))


def _tool(name: str):
    return srv.create_server()._tool_manager._tools[name].fn


def _whoami(monkeypatch, out="", code=0, error=None):
    """whoami.exe, as the service sees it: what it prints, or an error. The
    environment is the guest's: SYSTEM's USERNAME is the machine account."""
    import subprocess

    calls = []
    real = subprocess.run

    def run(argv, *a, **k):
        if not str(argv[0]).endswith("whoami.exe"):
            return real(argv, *a, **k)
        calls.append(argv)
        if error:
            raise error
        return subprocess.CompletedProcess(argv, code, out, "")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(generic, "_account", None, raising=False)  # read afresh
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    monkeypatch.setenv("USERDOMAIN", "WORKGROUP")
    monkeypatch.setenv("USERNAME", "SANS-SIFT$")
    return calls


@pytest.fixture
def box(monkeypatch):
    """The account's Sysinternals keys (`accepted`: key -> True; a key
    missing is not accepted; `unreadable` makes every read fail), and the
    argv of every run. A tool run without the flag, its key not accepted,
    shows the EULA screen and exits 1; with the flag, it sets its key."""
    state = {"accepted": {}, "unreadable": False, "runs": [], "reads": []}
    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")
    _whoami(monkeypatch, "nt authority\\system\r\n")

    def eula_accepted(key):
        state["reads"].append(key)
        return None if state["unreadable"] else state["accepted"].get(key, False)

    def execute(command, **k):
        state["runs"].append(list(command))
        key = KEYS[command[0].rsplit("/", 1)[-1].removesuffix(".exe")]
        if FLAG in command:
            state["accepted"][key] = True
        if state["accepted"].get(key):
            code, out = 0, "Verified:\tSigned\n"
        else:
            code, out = 1, EULA
        # as the executor gives it: the argv it ran, stdout decoded and counted
        return {"exit_code": code, "stdout": out, "stderr": "",
                "stdout_total_bytes": len(out.encode()), "command": list(command)}  # fmt: skip

    # raising=False: at a base without the read, the runs show the screen
    monkeypatch.setattr(generic, "eula_accepted", eula_accepted, raising=False)
    monkeypatch.setattr(generic, "execute", execute)
    return state


def _target(case, name="one"):  # noqa: F811
    return str(_files(case / "evidence" / name, ["a.exe"]) / "a.exe")


def _run(case, *args):  # noqa: F811
    r = _tool("run_windows_command")(command=list(args), purpose="check")
    (entry,) = [e for e in _entries(case) if e["tool"] == "run_windows_command"]
    return _sent(r), entry


def test_a_tool_not_accepted_runs_with_the_flag_and_says_so(case, box):  # noqa: F811
    target = _target(case)
    r, entry = _run(case, "sigcheck", target)
    assert r["success"] is True and "error" not in r, r
    ((argv),) = box["runs"]
    assert argv == ["C:/Tools/sigcheck", "-accepteula", target]
    note = (
        "The Sysinternals EULA for sigcheck was accepted on the examiner's behalf "
        f"(it hadn't been accepted for {ACCOUNT})."
    )
    assert r["eula_note"] == note
    assert entry["result_summary"]["eula_note"] == note
    assert entry["params"]["command"] == argv  # the flag is in the record
    assert box["accepted"] == {"sigcheck": True}


def test_once_accepted_a_run_is_clean(case, box):  # noqa: F811
    target = _target(case)
    _tool("run_windows_command")(command=["sigcheck", target], purpose="first")
    r = _sent(_tool("run_windows_command")(command=["sigcheck", target], purpose="2"))
    assert r["success"] is True and "eula_note" not in r
    assert box["runs"][1] == ["C:/Tools/sigcheck", target]


@pytest.mark.parametrize(
    "tool, key",
    [("autorunsc", "AutoRuns"), ("strings", "Strings"), ("handle", "Handle"),
     ("procdump", "ProcDump"), ("sigcheck", "sigcheck")],
)  # fmt: skip
def test_an_accepted_tool_runs_unchanged_with_no_note(case, box, tool, key):  # noqa: F811
    box["accepted"][key] = True
    args = ["-a", "*"] if tool == "autorunsc" else [_target(case)]
    r, entry = _run(case, tool, *args)
    assert r["success"] is True, r
    ((argv),) = box["runs"]
    assert FLAG not in argv
    assert "eula_note" not in r and "eula_note" not in entry["result_summary"]
    assert box["reads"] == [key]


def test_an_unreadable_flag_is_accepted_and_says_it_couldnt_be_read(case, box):  # noqa: F811
    box["unreadable"] = True
    target = _target(case)
    r, entry = _run(case, "strings", target)
    assert r["success"] is True, r
    assert box["runs"] == [["C:/Tools/strings64.exe", "-accepteula", target]]
    note = (
        "The Sysinternals EULA for strings was accepted on the examiner's behalf "
        f"(whether it had been accepted for {ACCOUNT} couldn't be read)."
    )
    assert r["eula_note"] == entry["result_summary"]["eula_note"] == note


@pytest.mark.parametrize("given", ["-accepteula", "-AcceptEula"])
def test_a_callers_flag_is_kept_once_and_the_note_still_given(case, box, given):  # noqa: F811
    target = _target(case)
    r, entry = _run(case, "sigcheck", given, target)
    assert box["runs"] == [["C:/Tools/sigcheck", given, target]]
    assert (
        ON_BEHALF in r["eula_note"]
        and ON_BEHALF in entry["result_summary"]["eula_note"]
    )


def test_a_callers_flag_on_an_accepted_tool_says_nothing(case, box):  # noqa: F811
    box["accepted"]["sigcheck"] = True
    target = _target(case)
    r, _ = _run(case, "sigcheck", "-accepteula", target)
    assert box["runs"] == [["C:/Tools/sigcheck", "-accepteula", target]]
    assert "eula_note" not in r


def test_a_batch_gives_one_note_and_only_its_first_run_accepts(case, box):  # noqa: F811
    folder = _files(case / "evidence" / "many", ["a.exe", "b.exe", "c.exe"])
    r = _sent(_tool("batch_scan")(tool="sigcheck", directory=str(folder)))
    assert r["exit_codes"] == {"0": 3} and r["errors"] == [], r
    flags = [run.count(FLAG) for run in box["runs"]]
    assert flags == [1, 0, 0]
    assert ON_BEHALF in r["eula_note"] and json.dumps(r).count(ON_BEHALF) == 1
    (entry,) = [e for e in _entries(case) if e["tool"] == "batch_scan"]
    assert entry["result_summary"]["eula_note"] == r["eula_note"]


def test_a_batch_that_cant_read_the_flag_still_gives_one_note(case, box):  # noqa: F811
    box["unreadable"] = True
    folder = _files(case / "evidence" / "many", ["a.exe", "b.exe"])
    r = _sent(_tool("batch_scan")(tool="strings", directory=str(folder)))
    assert [run.count(FLAG) for run in box["runs"]] == [1, 1]
    assert json.dumps(r).count(ON_BEHALF) == 1


def test_an_accepted_batch_says_nothing(case, box):  # noqa: F811
    box["accepted"]["sigcheck"] = True
    folder = _files(case / "evidence" / "many", ["a.exe", "b.exe"])
    r = _sent(_tool("batch_scan")(tool="sigcheck", directory=str(folder)))
    assert all(FLAG not in run for run in box["runs"])
    assert "eula_note" not in r
    (entry,) = [e for e in _entries(case) if e["tool"] == "batch_scan"]
    assert "eula_note" not in entry["result_summary"]


def test_a_tool_without_an_eula_is_never_checked(case, box, monkeypatch):  # noqa: F811
    monkeypatch.setattr(
        generic, "execute",
        lambda command, **k: (box["runs"].append(list(command)) or
                              {"exit_code": 0, "stdout": "ok\n", "stderr": "",
                               "stdout_total_bytes": 3}),
    )  # fmt: skip
    r, _ = _run(case, "densityscout", "-pe", _target(case))
    assert box["reads"] == [] and "eula_note" not in r
    assert FLAG not in box["runs"][0]


def test_every_tool_that_takes_the_flag_has_its_key_and_only_those():
    flagged = {
        td.name
        for td in catalog.load_catalog().values()
        if any(f.get("flag") == "-accepteula" for f in td.common_flags)
    }
    keyed = {td.name for td in catalog.load_catalog().values() if td.eula_key}
    assert (
        flagged == keyed == {"autorunsc", "strings", "handle", "procdump", "sigcheck"}
    )


# --- the registry read, with a stand-in winreg -------------------------------


def _winreg(monkeypatch, value=None, error=None):
    opened = []

    class Key:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def open_key(root, path):
        opened.append((root, path))
        if error:
            raise error
        return Key()

    def query(key, name):
        assert name == "EulaAccepted"
        if value is None:
            raise FileNotFoundError(2, "value missing")
        return value, 4

    fake = types.SimpleNamespace(
        HKEY_CURRENT_USER="HKCU", OpenKey=open_key, QueryValueEx=query
    )
    monkeypatch.setitem(sys.modules, "winreg", fake)
    return opened


@pytest.mark.parametrize(
    "value, error, expected",
    [
        (1, None, True),
        (0, None, False),
        (None, None, False),  # the key, without the value
        (None, FileNotFoundError(2, "no key"), False),
        (None, PermissionError(5, "denied"), None),
        (None, OSError(1, "other"), None),
    ],
    ids=["accepted", "zero", "no-value", "no-key", "denied", "other-error"],
)  # fmt: skip
def test_the_flag_is_read_from_the_accounts_own_hive(
    monkeypatch, value, error, expected
):
    opened = _winreg(monkeypatch, value, error)
    assert generic.eula_accepted("sigcheck") is expected
    assert opened == [("HKCU", "Software\\Sysinternals\\sigcheck")]


def test_no_registry_is_an_unreadable_flag(monkeypatch):
    monkeypatch.setitem(sys.modules, "winreg", None)  # import fails
    assert generic.eula_accepted("sigcheck") is None


# --- the account named in the note -------------------------------------------


def test_the_account_is_named_as_whoami_names_it_and_read_once(monkeypatch):
    calls = _whoami(monkeypatch, "nt authority\\system\r\n")
    assert generic.run_account() == "nt authority\\system"
    assert generic.run_account() == "nt authority\\system"
    assert len(calls) == 1 and calls[0][0].endswith("System32\\whoami.exe")


@pytest.mark.parametrize(
    "out, code, error",
    [("", 0, FileNotFoundError(2, "no whoami")), ("", 1, None), ("  \r\n", 0, None)],
    ids=["missing", "failed", "empty"],
)  # fmt: skip
def test_without_whoami_the_account_is_the_environments(monkeypatch, out, code, error):
    _whoami(monkeypatch, out, code, error)
    assert generic.run_account() == "WORKGROUP\\SANS-SIFT$"
