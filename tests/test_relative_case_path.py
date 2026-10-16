"""A relative path is read from the run's own new folder in extractions, not
from the case folder. One that isn't there but that the case folder has was
meant from the case: it is refused, on the record and before anything runs,
naming the full path. A tool that then matches no file (Sysinternals'
"No matching files were found.", exit code 0) with no input read is no
result: success is false and the tool's own line stays in its stderr.

The share is a local folder that is the active case; the tool is a stand-in
file, and Popen is replaced by a function that prints what the tool would.
No process starts. Values are synthetic.
"""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import MagicMock, patch

from test_run_records import (  # noqa: F401  (fixtures)
    _entries,
    _evtx,
    case,
    tools,
)

from wintools_mcp import server as srv
from wintools_mcp.config import get_config

NO_MATCH = b"\r\nNo matching files were found.\r\n"
REL = "evidence/kansa-by-host/rd01/rd01-Autorunsc.csv"


def _run(tools, tool, command, stderr=b"", calls=None, **args):  # noqa: F811
    def popen(cmd, **kw):
        if calls is not None:
            calls.append((list(cmd), kw.get("cwd")))
        proc = MagicMock()
        proc.stdout = io.BytesIO(b"tool output line\n")
        proc.stderr = io.BytesIO(stderr)
        proc.returncode = 0
        proc.wait.return_value = 0
        proc.poll.return_value = 0
        proc.pid = 4242
        return proc

    run = srv.create_server()._tool_manager._tools["run_windows_command"].fn.__wrapped__
    with (
        patch(
            "wintools_mcp.tools.generic.find_tool", side_effect=lambda n: tools[tool]
        ),
        patch("wintools_mcp.executor.subprocess.Popen", side_effect=popen),
        # sigcheck has a EULA: accepted for the account, so no whoami runs
        patch("wintools_mcp.tools.generic.eula_accepted", return_value=True),
    ):
        return run(purpose="row", command=command, **args)


def _kansa(share: Path) -> Path:
    csv = share / REL
    csv.parent.mkdir(parents=True)
    csv.write_text("Time,Entry Location,Entry\n")
    return csv


def test_a_path_relative_to_the_case_is_refused_naming_the_full_path(case, tools):  # noqa: F811
    csv = _kansa(case)
    calls: list = []
    resp = _run(tools, "sigcheck", ["sigcheck", "-h", REL], calls=calls)
    assert resp["success"] is False and calls == []  # nothing ran
    (entry,) = _entries(case)
    assert resp["error"] == (
        f"{REL} is read from this run's own folder "
        f"(extractions/{entry['audit_id']}), and it isn't there. "
        f"The case has it at {csv}"
    )
    assert resp["suggestions"] == [f"Give the full path: {csv}"]
    assert entry["result_summary"]["error"] == resp["error"]
    assert entry["params"]["command"] == ["sigcheck", "-h", REL]


def test_a_catalog_input_flag_relative_to_the_case_gets_the_same_answer(case, tools):  # noqa: F811
    """Before, it was "Evidence path not accessible: <op folder>\\evidence\\…"."""
    ev = _evtx(case)
    calls: list = []
    rel = "evidence/Security.evtx"
    resp = _run(tools, "evtxecmd", ["EvtxECmd", "-f", rel], calls=calls)
    assert resp["success"] is False and calls == []
    assert resp["error"].endswith(f"The case has it at {ev}")
    assert "Evidence path not accessible" not in resp["error"]


def test_the_full_path_runs_and_names_its_input(case, tools):  # noqa: F811
    csv = _kansa(case)
    calls: list = []
    resp = _run(tools, "sigcheck", ["sigcheck", "-h", str(csv)], calls=calls)
    assert resp["success"] is True and len(calls) == 1, resp
    assert [i["path"] for i in resp["inputs"]] == [str(csv.resolve())]
    assert "error" not in resp


def test_an_output_flag_value_the_case_has_is_not_refused(case, tools):  # noqa: F811
    """What the command writes is never checked: --csv evidence writes into
    the run's folder."""
    ev = _evtx(case)
    calls: list = []
    command = ["EvtxECmd", "-f", str(ev), "--csv", "evidence"]
    resp = _run(tools, "evtxecmd", command, calls=calls)
    assert resp["success"] is True and len(calls) == 1, resp


def test_a_relative_path_nothing_has_runs_and_no_match_is_no_result(case, tools):  # noqa: F811
    calls: list = []
    resp = _run(
        tools, "sigcheck", ["sigcheck", "-h", REL], stderr=NO_MATCH, calls=calls
    )
    assert len(calls) == 1  # neither the run's folder nor the case has it
    (entry,) = _entries(case)
    assert resp["success"] is False and resp["metadata"]["exit_code"] == 0
    assert resp["inputs"] == []
    assert resp["error"] == (
        "sigcheck found no file to read, and no input was read. A relative "
        f"path is read from this run's own folder (extractions/{entry['audit_id']}): "
        "give the full path, from get_share_info's case_dir"
    )
    assert "No matching files were found." in resp["data"]["stderr"]
    assert entry["result_summary"]["error"] == resp["error"]


def test_no_match_with_an_input_read_or_without_the_line_is_unchanged(case, tools):  # noqa: F811
    csv = _kansa(case)
    resp = _run(tools, "sigcheck", ["sigcheck", "-h", str(csv)], stderr=NO_MATCH)
    assert resp["success"] is True and "error" not in resp, resp
    resp = _run(tools, "sigcheck", ["sigcheck", "-h", REL + ".missing"])
    assert resp["success"] is True and "error" not in resp, resp
    entries = _entries(case)
    assert [("error" in e["result_summary"]) for e in entries] == [False, False]


def test_a_declared_input_is_not_a_read_one(case, tools):  # noqa: F811
    """The caller's list says what it meant to read, not what the tool read."""
    csv = _kansa(case)
    resp = _run(
        tools,
        "sigcheck",
        ["sigcheck", "-h", "rd01-*.csv"],
        stderr=NO_MATCH,
        input_files=[str(csv)],
    )
    assert [i["found"] for i in resp["inputs"]] == ["declared"]
    assert resp["success"] is False
    assert resp["error"].startswith("sigcheck found no file to read")


def test_with_no_case_nothing_is_refused_and_no_match_is_no_result(
    case,  # noqa: F811
    tools,  # noqa: F811
    monkeypatch,
):
    _kansa(case)
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    get_config().case_dir = ""
    calls: list = []
    resp = _run(
        tools, "sigcheck", ["sigcheck", "-h", REL], stderr=NO_MATCH, calls=calls
    )
    assert len(calls) == 1, resp
    assert resp["success"] is False
    assert "this run's own folder (the tool's working folder)" in resp["error"]
