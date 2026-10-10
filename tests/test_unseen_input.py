"""A path on the share that the command names but the share doesn't show is
refused, loudly and on the record, before anything runs.

Over the share, a link to a file outside the case isn't followed, so the
file isn't there for the tool: run anyway, the tool finds nothing and the
call reads as a success with no input. Only paths on the share are checked,
and never what the command writes (an output flag's value, an acquisition's
destination). The share is a local folder that is the active case; a link
whose target is gone stands in for one the share doesn't follow. Popen is
replaced, and no process starts.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from test_run_records import (  # noqa: F401  (fixtures)
    _entries,
    _evtx,
    _run,
    case,
    tools,
)


def test_a_link_out_of_the_case_is_refused_and_recorded(case, tools, tmp_path):  # noqa: F811
    link = case / "evidence" / "triage-link.csv"  # registered where it lies
    link.symlink_to(tmp_path / "srv" / "triage.csv")  # not there for the share
    calls: list = []
    resp = _run(tools, "sigcheck", calls=calls, command=["sigcheck", "-h", str(link)])
    assert resp["success"] is False and calls == []  # nothing ran
    assert f"Can't see {link} over the share" in resp["error"]
    assert any("Copy the file into the case" in s for s in resp["suggestions"])
    (entry,) = _entries(case)
    assert entry["result_summary"]["error"] == resp["error"]
    assert entry["params"]["command"] == ["sigcheck", "-h", str(link)]


@pytest.mark.parametrize(
    "tool, command",
    [
        ("winpmem", ["winpmem", "C:\\Evidence\\rd01-mem.raw"]),
        ("evtxecmd", ["EvtxECmd", "-f", "EVTX", "--csv", "C:\\vhir-out\\evtx-run1"]),
        ("winpmem", ["winpmem", "-o", "S:\\extractions\\new-memory.raw"]),
    ],
)
def test_outputs_and_local_paths_are_never_checked(case, tools, tool, command):  # noqa: F811
    """A destination not there yet, or a path off the share, runs as before."""
    ev = _evtx(case)
    command = [str(ev) if a == "EVTX" else a for a in command]
    calls: list = []
    resp = _run(tools, tool, calls=calls, command=command)
    assert resp["success"] is True and len(calls) == 1, resp


def test_an_output_on_the_share_not_there_yet_runs(case, tools):  # noqa: F811
    ev = _evtx(case)
    out = case / "extractions" / "evtx-run1"  # on the share, not made yet
    dest = case / "evidence" / "new-memory.raw"
    calls: list = []
    command = ["EvtxECmd", "-f", str(ev), "--csv", str(out)]
    resp = _run(tools, "evtxecmd", calls=calls, command=command)
    assert resp["success"] is True and len(calls) == 1, resp
    resp = _run(tools, "winpmem", calls=calls, command=["winpmem", str(dest)])
    assert resp["success"] is True and len(calls) == 2, resp


def test_a_missing_path_off_the_share_is_not_checked(case, tools, tmp_path):  # noqa: F811
    local = tmp_path / "elsewhere" / "missing.csv"
    calls: list = []
    resp = _run(tools, "sigcheck", calls=calls, command=["sigcheck", "-h", str(local)])
    assert resp["success"] is True and len(calls) == 1, resp


def test_a_named_input_that_is_not_there_is_refused_on_the_record(case, tools):  # noqa: F811
    gone = case / "evidence" / "Gone.evtx"
    calls: list = []
    resp = _run(tools, "evtxecmd", calls=calls, command=["EvtxECmd", "-f", str(gone)])
    assert resp["success"] is False and calls == []
    assert resp["error"] == f"Evidence path not accessible: {gone}"
    (entry,) = _entries(case)
    assert entry["result_summary"]["error"] == resp["error"]


def test_a_file_the_share_shows_still_runs(case, tools):  # noqa: F811
    ev = _evtx(case)
    calls: list = []
    resp = _run(tools, "sigcheck", calls=calls, command=["sigcheck", "-h", str(ev)])
    assert resp["success"] is True and len(calls) == 1


def test_a_path_that_errors_over_the_share_is_refused_not_run(case, tools, monkeypatch):  # noqa: F811
    """Windows can fail to stat a share path with an unexpected network error
    (WinError 59): it isn't a file the tool can be given, and it isn't seen,
    so nothing runs."""
    target = case / "evidence" / "flaky.csv"
    real_exists, real_is_file = Path.exists, Path.is_file

    def exists(self, *a, **k):
        if str(self) == str(target):
            raise OSError(22, "An unexpected network error occurred", str(target), 59)
        return real_exists(self, *a, **k)

    def is_file(self, *a, **k):
        return False if str(self) == str(target) else real_is_file(self, *a, **k)

    monkeypatch.setattr(Path, "exists", exists)
    monkeypatch.setattr(Path, "is_file", is_file)
    calls: list = []
    resp = _run(tools, "sigcheck", calls=calls, command=["sigcheck", "-h", str(target)])
    assert resp["success"] is False and calls == []
    assert f"Can't see {target}" in resp["error"]


def test_a_path_by_another_name_for_the_share_is_checked(case, tools, tmp_path):  # noqa: F811
    """A mapped drive is the share by another name: what it resolves to is
    on the share (here a folder linked to it stands in for the drive)."""
    drive = tmp_path / "S"
    drive.symlink_to(case, target_is_directory=True)
    missing = drive / "evidence" / "triage.csv"
    calls: list = []
    resp = _run(
        tools, "sigcheck", calls=calls, command=["sigcheck", "-h", str(missing)]
    )
    assert resp["success"] is False and calls == []
    assert f"Can't see {missing} over the share" in resp["error"]
