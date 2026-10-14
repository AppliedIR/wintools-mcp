"""A run wintools stopped at its output limit is never a success.

The executor kills a tool whose output passes max_output_bytes. On Windows
that kill is TerminateProcess with exit code 1, so the recorded exit code is
the stop's, not the tool's: sigcheck would read it as "unsigned files found".
The reply and its audit entry name the stop, and no exit meaning is given.
These rows go through the real executor: Popen runs a small script in place
of the tool, and its kill() leaves exit code 1 as Windows does. Values are
synthetic.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pydantic_core
import pytest
from test_batch_scan import _entries, case  # noqa: F401 - fixtures

from wintools_mcp import executor
from wintools_mcp import server as srv
from wintools_mcp.config import get_config
from wintools_mcp.tools import generic

SPILL = "import sys\nwhile True: sys.stdout.write('line of output\\n')"
UNSIGNED = "print('c:\\\\x\\\\a.exe: Unsigned'); raise SystemExit(1)"


def _as_windows_runs(monkeypatch, script):
    """Popen as the executor calls it, running `script` in place of the tool;
    kill() leaves exit code 1, as TerminateProcess does on Windows."""

    class Windows(subprocess.Popen):
        def __init__(self, cmd, **kw):
            super().__init__([sys.executable, "-c", script], **kw)

        def kill(self):
            super().kill()
            super().wait()
            self.returncode = 1

    monkeypatch.setattr(executor.subprocess, "Popen", Windows)
    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")
    monkeypatch.setattr(generic, "eula_accepted", lambda key: True, raising=False)
    monkeypatch.setattr(get_config(), "max_output_bytes", 4096)


def _run(tool, *args):
    fn = srv.create_server()._tool_manager._tools["run_windows_command"].fn.__wrapped__
    return json.loads(pydantic_core.to_json(fn(command=[tool, *args], purpose="limit")))


@pytest.mark.parametrize("tool", ["sigcheck", "procdump"])
def test_a_run_stopped_at_the_output_limit_is_no_success(case, monkeypatch, tool):  # noqa: F811
    """Its exit 1 is the stop's: never "unsigned files found"."""
    _as_windows_runs(monkeypatch, SPILL)
    r = _run(tool, "C:\\x")
    assert r["metadata"]["exit_code"] == 1, r
    assert r["success"] is False, r
    assert "stopped by wintools at its output limit (4096 bytes)" in r["error"], r
    assert "exit_code_meaning" not in r["metadata"], r
    assert r["stopped"] == "output limit", r
    (entry,) = [e for e in _entries(case) if e["tool"] == "run_windows_command"]
    assert "output limit (4096 bytes)" in entry["result_summary"]["error"]
    assert entry["result_summary"]["stopped"] == "output limit"


def test_a_stop_whose_taskkill_failed_says_part_of_the_tree_may_run_on(
    case,  # noqa: F811
    monkeypatch,
):
    _as_windows_runs(monkeypatch, SPILL)
    monkeypatch.setattr(executor, "_WINDOWS", True, raising=False)
    monkeypatch.setattr(
        executor.subprocess,
        "run",
        lambda argv, **kw: subprocess.CompletedProcess(argv, 1),
    )
    r = _run("sigcheck", "C:\\x")
    assert r["stopped"] == "output limit", r
    assert r["stop_note"].startswith("taskkill exit 1: a process the tool started may")


def test_a_run_that_ends_under_the_limit_is_read_as_before(case, monkeypatch):  # noqa: F811
    _as_windows_runs(monkeypatch, UNSIGNED)
    r = _run("sigcheck", "C:\\x")
    assert r["success"] is True and "error" not in r and "stopped" not in r, r
    assert r["metadata"]["exit_code"] == 1, r


def test_a_run_stopped_at_its_deadline_says_so(case, monkeypatch):  # noqa: F811
    from wintools_mcp.exceptions import ExecutionTimeoutError

    def timed_out(command, **k):
        raise ExecutionTimeoutError("Command timed out after 300s")

    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")
    monkeypatch.setattr(generic, "eula_accepted", lambda key: True, raising=False)
    monkeypatch.setattr(generic, "execute", timed_out)
    r = _run("procdump", "-ma", "4242")
    assert r["success"] is False and r["stopped"] == "timeout", r
    (entry,) = [e for e in _entries(case) if e["tool"] == "run_windows_command"]
    assert entry["result_summary"]["stopped"] == "timeout"
