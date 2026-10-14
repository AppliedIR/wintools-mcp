"""A run's `success` says it completed; its exit code is given bare.

What an exit code means differs by tool and version (an EZ tool exits 0 on
a bad argument; ProcDump exits with the number of dumps it wrote; sigcheck
exits 1 for unsigned files), so wintools reads none of them. A run is a
success when it started, wintools didn't stop it, and no EULA screen took
its place. The code is the tool's own, read as signed 32-bit: Windows hands
-2 to Python as 4294967294. No reply carries an exit-code label, from the
catalog or from the tool's knowledge. Tools are stand-ins; values are
synthetic.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pydantic_core
import pytest
from test_batch_scan import _files, case  # noqa: F401 - fixtures

from wintools_mcp import executor
from wintools_mcp import server as srv
from wintools_mcp.tools import generic

USAGE = "PECmd version 1.5.0.0\n\nUsage: PECmd [options]\n\nOptions:\n  -f <f>  File to process\n"


def _tool(name):
    return srv.create_server()._tool_manager._tools[name].fn


def _sent(r):
    return json.loads(pydantic_core.to_json(r))


@pytest.fixture
def stand_in(monkeypatch):
    """Each run exits with `code` and prints `out`; EULAs read as accepted."""
    state = {"code": 0, "out": "", "err": ""}
    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")
    monkeypatch.setattr(generic, "eula_accepted", lambda key: True, raising=False)

    def execute(command, **k):
        out = state["out"]
        return {"exit_code": state["code"], "stdout": out, "stderr": state["err"],
                "stdout_total_bytes": len(out.encode()), "command": list(command)}  # fmt: skip

    monkeypatch.setattr(generic, "execute", execute)
    return state


@pytest.fixture
def fk(monkeypatch):
    """Every tool's knowledge carries exit-code hints, as FK data does today."""
    from wintools_mcp import response

    hints = {"exit_code_hints": {0: "success", 1: "error", 2: "suspicious detected"},
             "caveats": ["a caveat"]}  # fmt: skip
    loader = type("FK", (), {"get_tool": staticmethod(lambda name: hints),
                             "get_artifact": staticmethod(lambda name: None)})  # fmt: skip
    monkeypatch.setattr(response, "fk_loader", loader)
    response.reset_call_counter()


def _run(*command):
    return _sent(_tool("run_windows_command")(command=list(command), purpose="run"))


def test_a_bad_argument_run_completed_with_its_output_and_no_label(case, stand_in, fk):  # noqa: F811
    """An EZ tool given a bad argument prints its usage and exits 0."""
    stand_in.update(code=0, out=USAGE)
    r = _run("PECmd.exe", "--nope")
    assert r["success"] is True and r["metadata"]["exit_code"] == 0, r
    assert "Usage: PECmd" in json.dumps(r["data"])
    assert "exit_code_meaning" not in r["metadata"], r["metadata"]


def test_procdumps_dump_count_exit_is_a_completed_run(case, stand_in):  # noqa: F811
    stand_in.update(
        code=1, out="[22:10:02] Dump 1 complete: 5 MB written in 0.4 seconds\n"
    )
    r = _run("procdump", "-ma", "4242")
    assert r["success"] is True and r["metadata"]["exit_code"] == 1, r


@pytest.mark.parametrize("tool, code", [("hollows_hunter", 2), ("sigcheck", 1)])
def test_no_exit_code_is_labelled_even_with_knowledge_hints(
    case,  # noqa: F811
    stand_in,
    fk,
    tool,
    code,
):
    stand_in.update(code=code, out="result\n")
    r = _run(tool, "C:\\x")
    assert r["metadata"]["exit_code"] == code
    assert "exit_code_meaning" not in r["metadata"], r["metadata"]


def test_a_batch_row_has_no_exit_label(case, stand_in):  # noqa: F811
    stand_in.update(code=1, out="c:\\x\\evil.exe:\n\tVerified:\tUnsigned\n")
    folder = _files(case / "evidence" / "mixed", ["evil.exe"])
    r = _sent(_tool("batch_scan")(tool="sigcheck", directory=str(folder)))
    (row,) = r["results"]
    assert row["exit_code"] == 1 and "exit_meaning" not in row, row


def test_a_negative_exit_code_is_recorded_as_the_tool_set_it(case, monkeypatch):  # noqa: F811
    """Through the executor: Windows gives -2 as 4294967294."""

    class Windows(subprocess.Popen):
        def __init__(self, cmd, **kw):
            super().__init__([sys.executable, "-c", "print('no such process')"], **kw)

        def wait(self, timeout=None):
            super().wait(timeout)
            self.returncode = 4294967294
            return self.returncode

    monkeypatch.setattr(executor.subprocess, "Popen", Windows)
    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")
    monkeypatch.setattr(generic, "eula_accepted", lambda key: True, raising=False)
    r = _run("procdump", "-ma", "99999")
    assert r["metadata"]["exit_code"] == -2, r["metadata"]
    assert r["success"] is True  # it ran; its own output says what happened
