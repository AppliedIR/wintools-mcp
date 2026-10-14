"""A long run in a case: answered within a wait, then polled with
get_windows_run; its result is kept in wintools' memory.

- A run longer than the wait answers {state: running, run_id, op_folder,
  message}; get_windows_run(run_id) gives its reply once done, under the
  run's own audit id. A run done within the wait answers as before.
- A done run gives its reply whatever the wait, even one that ends just as
  the wait runs out.
- A poll after a gateway reconnect still gets the reply. After a wintools
  restart, or once the run is no longer kept, the poll says wintools has no
  record of it. Finished runs are kept up to a cap, delivered ones go first.
- Polls write nothing to the audit; only the run's own entry is there. The
  pending-hash markers come with the first delivery only.
- Runs go one at a time: a second is queued, a poll answers at once while
  the first runs, and a run past the queue's limit is refused and never
  runs.
- A catalog tool's own time limit (KAPE's 1800 s) is the run's.
Tools are stand-ins that sleep; values are synthetic.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import anyio
import pytest
from test_batch_scan import _entries, case  # noqa: F401 - fixtures

from wintools_mcp import jobs, operation
from wintools_mcp import server as srv
from wintools_mcp.tools import generic


@pytest.fixture(autouse=True)
def _short_wait(monkeypatch):
    monkeypatch.setattr(jobs, "WAIT_SECONDS", 0.5)
    jobs.clear()
    yield
    jobs.clear()


@pytest.fixture
def runs(monkeypatch):
    """Each run sleeps `seconds[tag]` (default 1.5) in its thread and writes
    one output file; spans and timeouts are recorded per tag."""
    state = {"seconds": {}, "spans": {}, "timeouts": {}, "lock": threading.Lock()}
    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")
    monkeypatch.setattr(generic, "eula_accepted", lambda key: True, raising=False)

    def execute(command, **k):
        tag = command[-1]
        state["timeouts"][tag] = k.get("timeout")
        start = time.monotonic()
        time.sleep(state["seconds"].get(tag, 1.5))
        if k.get("save_dir"):
            (Path(k["save_dir"]) / f"{tag}.out").write_bytes(b"x" * 100)
        with state["lock"]:
            state["spans"][tag] = (start, time.monotonic())
        out = f"ran {tag}\n"
        return {"exit_code": 0, "stdout": out, "stderr": "", "command": list(command),
                "stdout_total_bytes": len(out)}  # fmt: skip

    monkeypatch.setattr(generic, "execute", execute)
    return state


def _text(result):
    return json.loads(result[0].text)


async def _run(server, tag, tool="strings"):
    return _text(await server.call_tool(
        "run_windows_command", {"command": [tool, tag], "purpose": "run"}))  # fmt: skip


async def _poll(server, run_id, wait=5):
    return _text(
        await server.call_tool("get_windows_run", {"run_id": run_id, "wait": wait})
    )


async def _done(server, run_id):
    """Poll (each waits at most jobs.WAIT_SECONDS) until the reply is in."""
    for _ in range(40):
        got = await _poll(server, run_id)
        if got.get("state") not in ("queued", "running"):
            return got
    raise AssertionError(f"{run_id} never finished")


def test_a_long_run_answers_running_then_its_reply(case, runs):  # noqa: F811
    server = srv.create_server()
    seen = {}

    async def main():
        seen["first"] = await _run(server, "A")
        seen["final"] = await _done(server, seen["first"]["run_id"])

    anyio.run(main)
    first, final = seen["first"], seen["final"]
    assert first["state"] == "running" and first["op_folder"].endswith(first["run_id"])
    assert (
        "get_windows_run" in first["message"]
        and "survives a gateway restart" in first["message"]
    )
    assert final["success"] is True and final["audit_id"] == first["run_id"]
    (entry,) = [e for e in _entries(case) if e["tool"] == "run_windows_command"]
    assert entry["audit_id"] == first["run_id"]


def test_a_short_run_answers_as_before(case, runs):  # noqa: F811
    runs["seconds"]["A"] = 0.05
    server = srv.create_server()
    got = anyio.run(_run, server, "A")
    assert got["success"] is True and "state" not in got and "run_id" not in got
    assert got["data"]["stdout"] == "ran A\n"


def test_a_gateway_reconnect_gets_the_reply_and_a_wintools_restart_is_named(
    case,  # noqa: F811
    runs,
):
    server = srv.create_server()
    seen = {}

    async def main():
        seen["first"] = await _run(server, "A")
        run_id = seen["first"]["run_id"]
        await jobs._jobs[run_id].done.wait()
        seen["reconnect"] = await _poll(srv.create_server(), run_id)
        jobs.clear()  # wintools restarted
        seen["restart"] = await _poll(srv.create_server(), run_id)

    anyio.run(main)
    run_id = seen["first"]["run_id"]
    message = seen["first"]["message"]
    assert "survives a gateway restart, but not a wintools restart" in message
    assert seen["reconnect"].get("success") is True
    assert seen["reconnect"]["audit_id"] == run_id
    assert seen["restart"]["state"] == "unknown" and seen["restart"]["error"] == (
        "wintools has no record of this run. It may have restarted. "
        f"Check extractions/{run_id}/ and re-run if needed."
    )
    assert not list((case / "extractions").glob("*.state.json"))


def test_a_done_run_gives_its_reply_even_with_no_wait(case, runs):  # noqa: F811
    server = srv.create_server()
    seen = {}

    async def main():
        seen["first"] = await _run(server, "A")
        await jobs._jobs[seen["first"]["run_id"]].done.wait()
        seen["poll"] = await _poll(server, seen["first"]["run_id"], wait=0)

    anyio.run(main)
    assert seen["first"]["state"] == "running"
    assert seen["poll"].get("success") is True
    assert seen["poll"]["audit_id"] == seen["first"]["run_id"]


def test_a_run_ending_as_the_wait_runs_out_gives_its_reply(case, runs, monkeypatch):  # noqa: F811
    server = srv.create_server()
    seen = {}
    real = jobs.asyncio

    async def wait_for(aw, timeout):  # the run ends just as the wait's time is up
        await aw
        raise real.TimeoutError

    async def main():
        seen["first"] = await _run(server, "A")
        monkeypatch.setattr(jobs, "asyncio", SimpleNamespace(
            wait_for=wait_for, shield=real.shield, TimeoutError=real.TimeoutError))  # fmt: skip
        seen["poll"] = await _poll(server, seen["first"]["run_id"])

    anyio.run(main)
    assert seen["first"]["state"] == "running"
    assert seen["poll"].get("success") is True, seen["poll"]
    assert seen["poll"]["audit_id"] == seen["first"]["run_id"]


def test_finished_runs_are_kept_up_to_a_cap_delivered_ones_go_first(
    case,  # noqa: F811
    runs,
    monkeypatch,
):
    monkeypatch.setattr(jobs, "KEEP", 2)
    runs["seconds"].update(A=0.05, C=0.05)
    server = srv.create_server()
    seen = {}

    async def main():
        seen["B"] = await _run(server, "B")  # running: its reply not delivered yet
        await jobs._jobs[seen["B"]["run_id"]].done.wait()
        seen["A"] = await _run(server, "A")  # done within the wait: delivered
        seen["C"] = await _run(server, "C")
        seen["kept"] = set(jobs._jobs)
        seen["A again"] = await _poll(server, seen["A"]["audit_id"])
        seen["B2"] = await _poll(server, seen["B"]["run_id"])

    anyio.run(main)
    b, c = seen["B"]["run_id"], seen["C"]["audit_id"]
    assert seen["kept"] == {b, c}  # A, delivered, went before the older B
    assert seen["A again"]["state"] == "unknown"
    assert "no record of this run" in seen["A again"]["error"]
    assert seen["B2"].get("success") is True and seen["B2"]["audit_id"] == b


def test_polls_write_no_entries_and_pending_hashes_come_once(case, runs, monkeypatch):  # noqa: F811
    monkeypatch.setattr(operation, "HASH_LIMIT", 10)  # the 100-byte output is "pending"
    server = srv.create_server()
    seen = {}

    async def main():
        seen["first"] = await _run(server, "A")
        seen["first_final"] = await _done(server, seen["first"]["run_id"])
        seen["polls"] = [await _poll(server, seen["first"]["run_id"]) for _ in range(4)]

    anyio.run(main)
    first = seen["first_final"]
    assert [o.get("hash_state") for o in first["outputs"]] == ["pending"]
    marks = [[o.get("hash_state") for o in p["outputs"]] for p in seen["polls"]]
    assert all(m == [jobs.DELIVERED] for m in marks), marks
    tools = [e["tool"] for e in _entries(case)]
    assert tools == ["run_windows_command"]  # the run's own entry, no poll's


def test_runs_queue_never_overlap_and_a_poll_answers_at_once(case, runs):  # noqa: F811
    server = srv.create_server()
    seen = {}

    async def main():
        seen["A"] = await _run(server, "A")  # running after the wait
        seen["B"] = await _run(server, "B")  # queued behind A
        start = time.monotonic()
        seen["poll"] = await _poll(server, seen["B"]["run_id"], wait=0)
        seen["poll_seconds"] = time.monotonic() - start
        seen["A2"] = await _done(server, seen["A"]["run_id"])
        seen["B2"] = await _done(server, seen["B"]["run_id"])

    anyio.run(main)
    assert seen["A"]["state"] == "running" and seen["B"]["state"] == "queued"
    assert seen["poll"]["state"] in ("queued", "running") and seen["poll_seconds"] < 1
    a, b = runs["spans"]["A"], runs["spans"]["B"]
    assert b[0] >= a[1]  # never overlapping
    assert seen["A2"]["success"] is True and seen["B2"]["success"] is True


def test_a_run_past_the_queues_limit_is_refused_and_never_runs(case, runs, monkeypatch):  # noqa: F811
    monkeypatch.setattr(jobs, "QUEUE_LIMIT", 1)
    server = srv.create_server()
    seen = {}

    async def main():
        seen["A"] = await _run(server, "A")
        seen["B"] = await _run(server, "B")
        seen["C"] = await _run(server, "C")
        await _done(server, seen["A"]["run_id"])
        await _done(server, seen["B"]["run_id"])

    anyio.run(main)
    assert seen["C"]["state"] == "failed" and "waiting already" in seen["C"]["error"]
    assert "C" not in runs["spans"]  # reported failed: never ran


@pytest.mark.parametrize(
    "reply, state",
    [({"success": True}, "finished"), ({"success": False, "error": "x"}, "failed"),
     ({"success": False, "stopped": "output limit"}, "stopped"),
     ({"results": [], "files_processed": 0}, "finished")],
)  # fmt: skip
def test_a_runs_state_from_its_reply(reply, state):
    assert jobs.outcome(reply) == state


def test_a_catalog_tools_own_time_limit_is_the_runs(case, runs):  # noqa: F811
    runs["seconds"]["C:\\"] = 0.05
    server = srv.create_server()
    anyio.run(_run, server, "C:\\", "kape")
    assert runs["timeouts"]["C:\\"] == 1800


def test_a_long_batch_is_a_job_too(case, runs):  # noqa: F811
    from test_batch_scan import _files

    runs["seconds"]["a.exe"] = 0.4
    runs["seconds"]["b.exe"] = 0.4
    folder = _files(case / "evidence" / "two", ["a.exe", "b.exe"])
    server = srv.create_server()
    seen = {}

    async def main():
        seen["first"] = _text(await server.call_tool(
            "batch_scan", {"tool": "strings", "directory": str(folder)}))  # fmt: skip
        seen["final"] = await _done(server, seen["first"]["run_id"])

    anyio.run(main)
    assert seen["first"]["state"] == "running"
    assert seen["final"]["files_processed"] == 2
    assert seen["final"]["audit_id"] == seen["first"]["run_id"]


def test_without_a_case_a_long_run_answers_when_done(case, runs, monkeypatch):  # noqa: F811
    from wintools_mcp.config import get_config

    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    get_config().case_dir = ""
    server = srv.create_server()
    got = anyio.run(_run, server, "A")  # 1.5 s, past the 0.5 s wait
    assert got["success"] is True and "state" not in got
