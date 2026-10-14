"""A run wintools stops ends every process the tool started.

On Windows proc.kill() ends only the tool. A child it started (KAPE's
EvtxECmd) runs on with its parent gone, holds the output and evidence files
open, and keeps the pipes open, so the call waits for it. At the output limit
and at the deadline the executor first runs taskkill /T /F on the tool's PID,
then kills the tool as before. These rows run the real executor on a small
script; subprocess.run records the taskkill call in place of running it.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from wintools_mcp import executor
from wintools_mcp.exceptions import ExecutionTimeoutError
from wintools_mcp.executor import execute

SPILL = "import sys\nwhile True: sys.stdout.buffer.write(b'A' * 1024)"
SLEEP = "import time\ntime.sleep(30)"
QUICK = "print('done')"
TASKKILL = "C:\\Windows\\System32\\taskkill.exe"


@pytest.fixture
def stops(monkeypatch):
    """Record, in order, each taskkill call and each kill of the tool."""
    events: list = []
    pids: list[int] = []
    real_popen = subprocess.Popen

    class Tool(real_popen):
        def __init__(self, cmd, **kw):
            super().__init__(cmd, **kw)
            pids.append(self.pid)

        def kill(self):
            events.append(("kill", self.pid))
            super().kill()

    def run(argv, **kw):
        events.append(("taskkill", list(argv), kw))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(executor.subprocess, "Popen", Tool)
    monkeypatch.setattr(executor.subprocess, "run", run)
    monkeypatch.setattr(executor, "_WINDOWS", True, raising=False)
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    monkeypatch.setenv("WINTOOLS_MAX_OUTPUT", "2000")
    return events, pids


def _check_tree_then_tool(events, pids):
    assert [e[0] for e in events] == ["taskkill", "kill"], events
    _, argv, kw = events[0]
    assert argv == [TASKKILL, "/T", "/F", "/PID", str(pids[0])]
    assert kw["stdin"] is subprocess.DEVNULL
    assert kw["stdout"] is subprocess.DEVNULL
    assert kw["stderr"] is subprocess.DEVNULL
    assert kw["timeout"] > 0
    assert kw["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0)
    assert events[1] == ("kill", pids[0])


def test_a_run_stopped_at_the_output_limit_ends_its_whole_tree(stops):
    events, pids = stops
    result = execute([sys.executable, "-c", SPILL], timeout=30)
    assert result["truncated"] is True
    _check_tree_then_tool(events, pids)


def test_a_run_stopped_at_its_deadline_ends_its_whole_tree(stops):
    events, pids = stops
    with pytest.raises(ExecutionTimeoutError):
        execute([sys.executable, "-c", SLEEP], timeout=1)
    _check_tree_then_tool(events, pids)


@pytest.mark.parametrize(
    "failure",
    [
        FileNotFoundError(2, "not found"),
        PermissionError(13, "denied"),
        subprocess.TimeoutExpired(TASKKILL, 10),
    ],
    ids=["missing", "denied", "hung"],
)
def test_a_taskkill_that_fails_still_stops_the_tool(stops, monkeypatch, failure):
    events, pids = stops

    def run(argv, **kw):
        events.append(("taskkill", list(argv), kw))
        raise failure

    monkeypatch.setattr(executor.subprocess, "run", run)
    result = execute([sys.executable, "-c", SPILL], timeout=30)
    assert result["truncated"] is True
    assert [e[0] for e in events] == ["taskkill", "kill"], events
    assert events[1] == ("kill", pids[0])


def test_off_windows_only_the_tool_is_killed(stops, monkeypatch):
    events, pids = stops
    monkeypatch.setattr(executor, "_WINDOWS", False, raising=False)
    result = execute([sys.executable, "-c", SPILL], timeout=30)
    assert result["truncated"] is True
    assert events == [("kill", pids[0])]


def test_a_run_that_ends_by_itself_runs_no_taskkill(stops):
    events, _ = stops
    result = execute([sys.executable, "-c", QUICK], timeout=30)
    assert result["exit_code"] == 0
    assert "done" in result["stdout"]
    assert events == []
