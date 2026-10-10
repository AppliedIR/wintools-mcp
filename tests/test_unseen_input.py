"""A path the command names that the share doesn't show is refused, loudly
and on the record, before anything runs.

Over the share, a link to a file outside the case isn't followed, so the
file isn't there for the tool: run anyway, the tool finds nothing and the
call reads as a success with no input. The share is a local folder that is
the active case; Popen is replaced, and no process starts.
"""

from __future__ import annotations

import pytest
from test_run_records import (  # noqa: F401  (fixtures)
    _entries,
    _evtx,
    _run,
    case,
    tools,
)


@pytest.mark.parametrize(
    "missing",
    [r"\\sift\vhir-cases\evidence\triage-link.csv", r"S:\evidence\triage-link.csv"],
)
def test_a_path_the_share_does_not_show_is_refused_and_recorded(case, tools, missing):  # noqa: F811
    calls: list = []
    resp = _run(tools, "sigcheck", calls=calls, command=["sigcheck", "-h", missing])
    assert resp["success"] is False and calls == []  # nothing ran
    assert f"Can't see {missing} over the share" in resp["error"]
    assert any("Copy the file into the case" in s for s in resp["suggestions"])
    (entry,) = _entries(case)
    assert entry["result_summary"]["error"] == resp["error"]
    assert entry["params"]["command"] == ["sigcheck", "-h", missing]


def test_a_named_input_that_is_not_there_is_refused_on_the_record(case, tools):  # noqa: F811
    gone = case / "evidence" / "Gone.evtx"
    calls: list = []
    resp = _run(tools, "evtxecmd", calls=calls, command=["EvtxECmd", "-f", str(gone)])
    assert resp["success"] is False and calls == []
    assert resp["error"] == f"Evidence path not accessible: {gone}"
    (entry,) = _entries(case)
    assert entry["result_summary"]["error"] == resp["error"]


def test_a_file_the_share_shows_still_runs(case, tools, tmp_path, monkeypatch):  # noqa: F811
    """A drive path that is there (a name this test makes) and a regular case
    file both run as before."""
    monkeypatch.chdir(tmp_path)
    shown = r"S:\evidence\a.csv"
    (tmp_path / shown).write_text("a,b\n")  # one file of that literal name here
    calls: list = []
    resp = _run(tools, "sigcheck", calls=calls, command=["sigcheck", "-h", shown])
    assert resp["success"] is True and len(calls) == 1
    ev = _evtx(case)
    resp = _run(tools, "evtxecmd", calls=calls, command=["EvtxECmd", "-f", str(ev)])
    assert resp["success"] is True and len(calls) == 2


def test_a_path_that_errors_over_the_share_is_refused_not_run(case, tools, monkeypatch):  # noqa: F811
    """Windows can fail to stat a share path with an unexpected network error
    (WinError 59): the path isn't seen, so nothing runs."""
    from pathlib import Path

    link = r"\\sift\vhir-cases\evidence\triage-link.csv"
    real = Path.exists

    def exists(self, *a, **k):
        if str(self) == link:
            raise OSError(22, "An unexpected network error occurred", link, 59)
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "exists", exists)
    calls: list = []
    resp = _run(tools, "sigcheck", calls=calls, command=["sigcheck", "-h", link])
    assert resp["success"] is False and calls == []
    assert f"Can't see {link}" in resp["error"]
