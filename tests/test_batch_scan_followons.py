"""batch_scan says which subfolders it didn't scan, gives an exit code its
catalog meaning, runs a catalog name's binary, and scans the rest of a folder
when one entry can't be read; run_windows_command's reply can always be sent.

- batch_scan reads one folder, not its subfolders: the note says how many it
  left.
- A row whose exit code has a catalog meaning (sigcheck's 1: unsigned files
  found) carries it; the summary's exit-code keys stay as they are.
- A catalog name (strings) runs its binary (strings64.exe), as
  run_windows_command does.
- An entry whose type can't be read (a symlink loop) is an error of its own;
  the folder's other files are scanned.
- A file name with an undecodable byte doesn't stop run_windows_command's
  reply from being sent: the tool's output doesn't echo the name here, so
  what can't be sent is the reply's own record of it.
"""

from __future__ import annotations

import json
import os

import pydantic_core
import pytest
from test_batch_scan import _files, _scan, case, ran  # noqa: F401 - fixtures

from wintools_mcp import server as srv


def test_the_note_says_how_many_subfolders_werent_scanned(case, ran):  # noqa: F811
    folder = _files(case / "evidence" / "tree", ["top.exe"])
    _files(folder / "sub", ["deep.exe"])
    os.symlink("gone.exe", folder / "dangling.exe")  # neither a file nor a folder
    r = _scan(folder)
    assert [os.path.basename(f) for f in ran] == ["top.exe"]
    assert r["note"].startswith(
        "Scanned 1 of 1 matching files, 1 subfolder not scanned."
    )


def test_a_flat_folder_says_nothing_of_subfolders(case, ran):  # noqa: F811
    r = _scan(_files(case / "evidence" / "flat", ["a.exe", "b.exe"]))
    assert len(ran) == 2 and "subfolder" not in r["note"]


def test_an_exit_code_shows_its_catalog_meaning(case, ran):  # noqa: F811
    r = _scan(_files(case / "evidence" / "mixed", ["evil.exe", "good.exe"]))
    rows = {os.path.basename(row["file"]): row for row in r["results"]}
    assert rows["evil.exe"]["exit_meaning"] == "unsigned files found"
    assert rows["good.exe"]["exit_meaning"] == "all files signed"
    assert r["exit_codes"] == {"0": 1, "1": 1}  # the summary's keys as they were


def test_a_tool_with_no_meanings_shows_the_bare_code(case, ran):  # noqa: F811
    folder = _files(case / "evidence" / "plain", ["evil.exe"])
    fn = srv.create_server()._tool_manager._tools["batch_scan"].fn
    r = fn(tool="densityscout", directory=str(folder))
    (row,) = r["results"]
    assert row["exit_code"] == 1 and "exit_meaning" not in row


@pytest.fixture
def started(monkeypatch):
    """The binaries execute was started with, in order."""
    from wintools_mcp.tools import generic

    binaries: list[str] = []
    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")

    def execute(command, **k):
        binaries.append(os.path.basename(command[0]))
        return {"exit_code": 0, "stdout": "ok\n", "stderr": ""}

    monkeypatch.setattr(generic, "execute", execute)
    return binaries


def test_a_catalog_name_runs_its_binary(case, started):  # noqa: F811
    folder = _files(case / "evidence" / "str", ["a.exe", "b.exe"])
    fn = srv.create_server()._tool_manager._tools["batch_scan"].fn
    r = fn(tool="strings", directory=str(folder))
    assert started == ["strings64.exe", "strings64.exe"]
    assert r["errors"] == [] and all("error" not in row for row in r["results"])


def test_an_entry_that_cant_be_read_is_an_error_and_the_rest_are_scanned(case, ran):  # noqa: F811
    folder = _files(case / "evidence" / "loop", ["good.exe"])
    os.symlink("loop_b", folder / "loop_a")
    os.symlink("loop_a", folder / "loop_b")
    r = _scan(folder)
    assert [os.path.basename(f) for f in ran] == ["good.exe"]
    assert len(r["errors"]) == 2 and all("[Errno 40]" in e for e in r["errors"])
    assert {e.split(":")[0] for e in r["errors"]} == {
        str(folder / "loop_a"),
        str(folder / "loop_b"),
    }


@pytest.fixture
def quiet(monkeypatch):
    """sigcheck's output, which never names the file it read."""
    from wintools_mcp.tools import generic

    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")
    monkeypatch.setattr(generic, "execute",
                        lambda command, **k: {"exit_code": 0, "stdout": "Verified: Signed\n",
                                              "stderr": ""})  # fmt: skip


@pytest.mark.parametrize("save", [False, True], ids=["inline", "saved"])
def test_a_reply_naming_an_undecodable_file_can_be_sent(case, quiet, save):  # noqa: F811
    folder = case / "evidence"
    folder.mkdir()
    raw = os.fsencode(str(folder)) + b"/bad\xff.exe"
    with open(raw, "wb") as f:
        f.write(b"MZbad")
    fn = srv.create_server()._tool_manager._tools["run_windows_command"].fn
    r = fn(command=["sigcheck", os.fsdecode(raw)], purpose="check", save_output=save)
    sent = json.loads(pydantic_core.to_json(r))
    assert sent["success"] is True and sent.get("audit_id")


@pytest.mark.parametrize(
    "error", [ValueError, RuntimeError], ids=["refused", "unexpected"]
)
def test_an_error_naming_an_undecodable_file_can_be_sent(case, monkeypatch, error):  # noqa: F811
    """The tool's run fails with an error whose text names the file."""
    from wintools_mcp.tools import generic

    def execute(command, **k):
        raise error(f"cannot read {command[-1]}")

    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")
    monkeypatch.setattr(generic, "execute", execute)
    folder = case / "evidence"
    folder.mkdir()
    raw = os.fsencode(str(folder)) + b"/bad\xff.exe"
    with open(raw, "wb") as f:
        f.write(b"MZbad")
    fn = srv.create_server()._tool_manager._tools["run_windows_command"].fn
    r = fn(command=["sigcheck", os.fsdecode(raw)], purpose="check")
    sent = json.loads(pydantic_core.to_json(r))
    assert (
        sent["success"] is False and "bad<U+DCFF>.exe" in sent["error"]
    )  # the byte, as its code point


def _loop(folder):
    os.symlink("loop_b", folder / "loop_a")
    os.symlink("loop_a", folder / "loop_b")


def test_a_folder_of_only_unreadable_entries_names_them(case, ran):  # noqa: F811
    folder = case / "evidence" / "only-loop"
    folder.mkdir(parents=True)
    _loop(folder)
    r = _scan(folder)
    assert ran == [] and r["error"].startswith("No files matching")
    assert len(r["errors"]) == 2 and all("[Errno 40]" in e for e in r["errors"])


def test_unreadable_entries_beside_files_the_filter_leaves_out_are_named(case, ran):  # noqa: F811
    folder = _files(case / "evidence" / "loop-and-text", ["notes.txt"])
    _loop(folder)
    r = _scan(folder, filter_pattern="*.exe")
    assert ran == [] and r["error"].startswith("No files matching '*.exe'")
    assert {e.split(":")[0] for e in r["errors"]} == {
        str(folder / "loop_a"),
        str(folder / "loop_b"),
    }


def test_a_folder_with_no_match_says_which_subfolders_it_left(case, ran):  # noqa: F811
    folder = _files(case / "evidence" / "no-match", ["notes.txt"])
    _files(folder / "sub", ["deep.exe"])
    r = _scan(folder, filter_pattern="*.exe")
    assert ran == [] and r["note"] == "1 subfolder not scanned"
