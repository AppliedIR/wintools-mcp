"""A Sysinternals EULA screen and an escaped file name are never read as
results.

- A Sysinternals tool run by an account that hasn't accepted its EULA prints
  the license and exits 1. sigcheck's catalog reads exit 1 as "unsigned
  files found", so the screen is an error of its own, named, with no exit
  meaning, in batch_scan rows and in run_windows_command. A real exit 1
  still means what it says, and the license text in a tool's real output
  (strings over a Sysinternals binary) isn't the screen.
- A character a file name can't carry in UTF-8 (a lone surrogate) is shown as
  its code point, `<U+D800>`. A backslash escape (`\\ud800`) reads on Windows
  as a folder and a file, and can be a different, real file's name. The
  audit entry keeps the real name.

The tools are stand-ins; the EULA screen is shaped like the one measured on a
Windows guest (the banner, then the license terms, on stdout). Values are
synthetic.
"""

from __future__ import annotations

import json
import ntpath
import os

import pydantic_core
import pytest
from test_batch_scan import HEADER, _files, _rows, case  # noqa: F401 - fixtures

from wintools_mcp import server as srv

# The screen's head as captured on a Windows guest (sigcheck 2.90, Autoruns
# 14.10 and strings 2.54 show the same title and first terms line), with the
# Windows line ends it was written with
TERMS = (
    "These license terms are an agreement between Sysinternals(a wholly owned subsidiary"
    " of Microsoft Corporation) and you.Please read them.They apply to the software you"
    " are downloading from technet.microsoft.com / sysinternals, which includes the media"
    " on which you received it, if any.The terms also apply to any Sysinternals"
)
BANNER = (
    "\r\nSigcheck v2.90 - File version and signature viewer\r\n"
    "Copyright (C) 2004-2022 Mark Russinovich\r\nSysinternals - www.sysinternals.com\r\n\r\n"
)
EULA = BANNER + "SYSINTERNALS SOFTWARE LICENSE TERMS\r\n" + TERMS + "\r\n* updates,\r\n"
NAMED = "showed its license (EULA) screen and didn't run"


def _sent(r: dict) -> dict:
    return json.loads(pydantic_core.to_json(r))


def _tool(name: str):
    return srv.create_server()._tool_manager._tools[name].fn


@pytest.fixture
def tools(monkeypatch):
    """Stand-in tools: `screen` makes every run show the EULA screen (exit
    1); otherwise sigcheck reports "evil" files unsigned (exit 1) and others
    signed, and `said` is what a run prints, with `code` its exit code."""
    from wintools_mcp.tools import generic

    state = {"screen": False, "said": None, "code": 0}
    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")

    def execute(command, **k):  # stdout as the executor gives it: decoded, counted
        code, out = 0, "Verified:\tSigned\n"
        if state["screen"]:
            code, out = 1, EULA
        elif state["said"] is not None:
            code, out = state["code"], state["said"]
        elif "evil" in os.path.basename(command[-1]):
            code, out = 1, "Verified:\tUnsigned\n"
        return {"exit_code": code, "stdout": out, "stderr": "",
                "stdout_total_bytes": len(out.encode())}  # fmt: skip

    monkeypatch.setattr(generic, "execute", execute)
    return state


@pytest.mark.parametrize("tool", ["sigcheck", "strings"])
def test_an_eula_screen_in_a_batch_is_an_error_not_a_result(case, tools, tool):  # noqa: F811
    tools["screen"] = True
    folder = _files(case / "evidence" / tool, ["a.exe", "evil.exe"])
    r = _sent(_tool("batch_scan")(tool=tool, directory=str(folder)))
    assert r["files_processed"] == 2 and r["exit_codes"] == {"error": 2}
    for row in r["results"]:
        assert NAMED in row["error"] and "exit_meaning" not in row, row
    assert len(r["errors"]) == 2 and all(NAMED in e for e in r["errors"])
    assert "2 errors" in r["note"]
    assert "unsigned files found" not in json.dumps(r)
    rows, _ = _rows(case / r["results_file"])
    assert len(rows) == 2 and all(code == "error" for code, _ in rows.values())


def test_an_eula_screen_through_run_windows_command_is_a_named_failure(case, tools):  # noqa: F811
    tools["screen"] = True
    target = _files(case / "evidence" / "one", ["a.exe"]) / "a.exe"
    r = _sent(
        _tool("run_windows_command")(command=["sigcheck", str(target)], purpose="check")
    )
    assert r["success"] is False and NAMED in r["error"], r
    assert (
        "sigcheck" in r["error"]
        and "hasn't accepted the Sysinternals EULA" in r["error"]
    )
    assert "unsigned files found" not in json.dumps(r)


def test_a_real_unsigned_result_still_means_unsigned(case, tools):  # noqa: F811
    folder = _files(case / "evidence" / "mixed", ["evil.exe", "good.exe"])
    r = _sent(_tool("batch_scan")(tool="sigcheck", directory=str(folder)))
    rows = {os.path.basename(row["file"]): row for row in r["results"]}
    assert (
        rows["evil.exe"]["exit_meaning"] == "unsigned files found" and r["errors"] == []
    )
    rwc = _tool("run_windows_command")
    one = _sent(rwc(command=["sigcheck", str(folder / "evil.exe")], purpose="check"))
    assert one["success"] is True
    assert one["metadata"]["exit_code_meaning"] == "unsigned files found"


@pytest.mark.parametrize(
    "code, said",
    [
        (0, EULA),  # strings over a Sysinternals binary: a clean exit
        (1, BANNER + "SYSINTERNALS SOFTWARE LICENSE TERMS\r\nsomething else\r\n"),
        (1, "line\r\n" * 10 + EULA),  # deep in a failed run's output
    ],
    ids=["clean-exit", "title-alone", "deep"],
)
def test_the_license_text_in_real_output_isnt_the_screen(case, tools, code, said):  # noqa: F811
    tools["said"], tools["code"] = said, code
    target = _files(case / "evidence" / "bin", ["sigcheck.exe"]) / "sigcheck.exe"
    r = _sent(
        _tool("run_windows_command")(command=["strings", str(target)], purpose="read")
    )
    assert NAMED not in json.dumps(r) and r["metadata"]["exit_code"] == code, r


def test_a_file_named_after_the_title_is_still_a_result(case, monkeypatch):  # noqa: F811
    """Hostile evidence: sigcheck names the file in its result."""
    from wintools_mcp.tools import generic

    def execute(command, **k):
        out = BANNER + f"{command[-1]}:\r\n\tVerified:\tUnsigned\r\n"
        return {"exit_code": 1, "stdout": out, "stderr": "",
                "stdout_total_bytes": len(out.encode())}  # fmt: skip

    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")
    monkeypatch.setattr(generic, "execute", execute)
    folder = _files(
        case / "evidence" / "hostile", ["SYSINTERNALS SOFTWARE LICENSE TERMS"]
    )
    r = _sent(_tool("batch_scan")(tool="sigcheck", directory=str(folder)))
    (row,) = r["results"]
    assert row["exit_meaning"] == "unsigned files found" and "error" not in row, row


def test_an_eula_run_is_audited_in_full(case, tools):  # noqa: F811
    tools["screen"] = True
    target = _files(case / "evidence" / "aud", ["a.exe"]) / "a.exe"
    r = _sent(_tool("run_windows_command")(command=["sigcheck", str(target)],
                                           purpose="check", save_output=True))  # fmt: skip
    assert r["success"] is False and NAMED in r["error"]
    entries = [
        json.loads(line)
        for p in (case / "audit").glob("*.jsonl")
        for line in p.read_text().splitlines()
    ]
    (entry,) = [e for e in entries if e.get("audit_id") == r["audit_id"]]
    assert entry.get("input_sha256s") and entry.get("tool_sha256") is not None, entry
    assert NAMED in json.dumps(entry)


def _undecodable(folder, name=b"bad\xff.exe", body=b"MZbad"):
    folder.mkdir(parents=True, exist_ok=True)
    raw = os.fsencode(str(folder)) + b"/" + name
    with open(raw, "wb") as f:
        f.write(body)
    return os.fsdecode(raw)


def test_an_undecodable_name_shows_its_code_point(case, tools):  # noqa: F811
    folder = case / "evidence" / "odd"
    _undecodable(folder)
    r = _sent(_tool("batch_scan")(tool="sigcheck", directory=str(folder)))
    (row,) = r["results"]
    assert row["file"] == f"{folder}/bad<U+DCFF>.exe", row["file"]
    assert "\\udcff" not in json.dumps(r, ensure_ascii=False)
    text = (case / r["results_file"]).read_text(encoding="utf-8")
    assert f"== {folder}/bad<U+DCFF>.exe | exit 0" in text and "\\udcff" not in text


def test_a_windows_lone_surrogate_doesnt_read_as_a_folder_and_a_file():
    name = "C:\\case\\evidence\\bad\ud800.exe"
    for shown in (srv._utf8(name), srv._one_line(name)):
        assert shown == "C:\\case\\evidence\\bad<U+D800>.exe"
        assert ntpath.basename(shown) == "bad<U+D800>.exe"


def test_two_files_never_share_a_shown_name(case, tools):  # noqa: F811
    folder = case / "evidence" / "two"
    _undecodable(folder, body=b"MZ-one")
    (folder / "bad\\udcff.exe").write_bytes(
        b"MZ-the-other"
    )  # a real name with a backslash
    r = _sent(_tool("batch_scan")(tool="sigcheck", directory=str(folder)))
    shown = sorted(row["file"] for row in r["results"])
    assert shown == sorted([f"{folder}/bad<U+DCFF>.exe", f"{folder}/bad\\udcff.exe"]), (
        shown
    )
    rows, _ = _rows(case / r["results_file"])
    assert len(rows) == 2


@pytest.mark.parametrize("name", ["naïve-ü.exe", "日本語.exe", "plain.exe"])
def test_a_name_utf8_can_carry_is_unchanged(case, tools, name):  # noqa: F811
    folder = _files(case / "evidence" / "fine", [name])
    r = _sent(_tool("batch_scan")(tool="sigcheck", directory=str(folder)))
    assert r["results"][0]["file"] == str(folder / name)
    assert srv._one_line(name) == name and srv._utf8(name) == name


def test_the_audit_entry_keeps_the_real_name(case, tools):  # noqa: F811
    folder = case / "evidence" / "kept"
    real = _undecodable(folder)
    r = _sent(_tool("batch_scan")(tool="sigcheck", directory=str(folder)))
    entries = [
        json.loads(line)
        for p in (case / "audit").glob("*.jsonl")
        for line in p.read_text().splitlines()
    ]
    (entry,) = [e for e in entries if e.get("audit_id") == r["audit_id"]]
    assert [i["path"] for i in entry["inputs"]] == [real]


def test_an_error_naming_an_odd_name_shows_its_code_point(case, monkeypatch):  # noqa: F811
    """In the results file too, where a failed row's error is written."""
    from wintools_mcp.tools import generic

    def execute(command, **k):
        raise ValueError(f"cannot read {command[-1]}")

    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")
    monkeypatch.setattr(generic, "execute", execute)
    folder = case / "evidence" / "err"
    _undecodable(folder)
    good = _files(folder / "x", ["good.exe"]) / "good.exe"
    good.rename(folder / "good.exe")  # one row runs, one fails naming the file
    r = _sent(_tool("batch_scan")(tool="sigcheck", directory=str(folder)))
    text = (case / r["results_file"]).read_text(encoding="utf-8")
    assert f"  | cannot read {folder}/bad<U+DCFF>.exe" in text, text
    assert "\\udcff" not in text
