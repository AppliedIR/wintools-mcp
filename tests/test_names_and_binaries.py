"""A tool is known by its catalog name or by its binary, wherever it's named.

`list_windows_tools` shows names (strings, procdump), and a name runs as its
binary (strings64.exe). A caller that names the binary (PECmd.exe, as the
ingest does) gets the tool's catalog behaviour, its --csv output folder
included, so the CSVs are made. Popen is replaced; no process starts.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from test_run_records import _evtx, _popen, case  # noqa: F401  (fixture)

from wintools_mcp import server as srv


def _call(tmp_path, command, write=None):
    """run_windows_command with a stand-in for every tool: (response, the
    names find_tool was asked for, the argv that ran)."""
    exe = tmp_path / "Tools" / "tool.exe"
    exe.parent.mkdir(exist_ok=True)
    exe.write_bytes(b"MZ-tool")
    asked: list = []
    calls: list = []
    run = srv.create_server()._tool_manager._tools["run_windows_command"].fn
    with (
        patch(
            "wintools_mcp.tools.generic.find_tool",
            side_effect=lambda name: asked.append(name) or str(exe),
        ),
        patch(
            "wintools_mcp.executor.subprocess.Popen",
            side_effect=_popen(write, calls=calls),
        ),
    ):
        resp = run(purpose="row", command=command)
    return resp, asked, [c[0] for c in calls]


@pytest.mark.parametrize(
    "name, binary",
    [
        ("strings", "strings64.exe"),
        ("procdump", "procdump64.exe"),
        ("handle", "handle64.exe"),
        ("moneta", "moneta64.exe"),
    ],
)
def test_a_catalog_name_runs_as_its_binary(case, tmp_path, name, binary):  # noqa: F811
    args = ["--pid", "1234"] if name == "moneta" else ["-accepteula", "-nobanner"]
    resp, asked, ran = _call(tmp_path, [name, *args])
    assert resp["success"] is True, resp
    assert asked == [binary] and ran[0][1:] == args


@pytest.mark.parametrize(
    "binary, flag",
    [("PECmd.exe", "-d"), ("SrumECmd.exe", "-f")],
)
def test_a_tool_named_by_its_binary_gets_its_csv_folder(case, tmp_path, binary, flag):  # noqa: F811
    """The ingest's own call form: the tool writes its CSVs into the run's
    folder, which the response names."""
    ev = _evtx(case)
    resp, asked, ran = _call(tmp_path, [binary, flag, str(ev)])
    assert resp["success"] is True, resp
    argv = ran[0]
    assert "--csv" in argv, argv  # without its catalog entry, no CSV folder
    assert argv[argv.index("--csv") + 1] == str(case / resp["op_folder"])
    assert resp["csv_output_dir"] == resp["op_folder"]


def test_the_catalog_resolves_a_name_or_a_binary_in_any_folder():
    from wintools_mcp.catalog import get_tool_def

    assert get_tool_def("strings").binary == "strings64.exe"
    assert get_tool_def("strings64.exe").name == "strings"
    assert get_tool_def("C:\\Tools\\EZ\\PECmd.exe").name == "PECmd"
    assert get_tool_def("powershell.exe") is None  # a script's interpreter is no tool


def test_a_script_named_by_its_catalog_name_is_never_run_as_its_interpreter(
    case,  # noqa: F811
    tmp_path,
):
    resp, _, _ = _call(tmp_path, ["Get-InjectedThreadEx", "-Aggressive"])
    assert "Arbitrary PowerShell" not in str(resp)
