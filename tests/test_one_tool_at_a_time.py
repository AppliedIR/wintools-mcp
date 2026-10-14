"""A tool runs in a worker thread, one at a time, so the server keeps
answering while it runs.

wintools' tools are sync. Run on the event loop, a long one blocks it, so
the server answers no ping until the run ends: the gateway calls the backend
unreachable and tears the session down, losing the run's result (measured
on a stand-in with wintools' own wiring, a 60 s run). Each tool now runs in
a worker thread under a limit of one: the loop stays free, a second call
waits for the first, and both results come back. An async tool is left as
it is. The tool's work here is a stand-in that sleeps.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time

import anyio
from test_batch_scan import case  # noqa: F401 - fixtures

from wintools_mcp import server as srv
from wintools_mcp.tools import generic

RUN_SECONDS = 1.0


def _slow_runs(monkeypatch):
    """Each run sleeps RUN_SECONDS in its thread; (start, end) per run."""
    spans: list[tuple[float, float]] = []
    lock = threading.Lock()
    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")
    monkeypatch.setattr(generic, "eula_accepted", lambda key: True, raising=False)

    def execute(command, **k):
        start = time.monotonic()
        time.sleep(RUN_SECONDS)
        with lock:
            spans.append((start, time.monotonic()))
        out = f"ran {command[-1]}\n"
        return {"exit_code": 0, "stdout": out, "stderr": "", "command": list(command),
                "stdout_total_bytes": len(out)}  # fmt: skip

    monkeypatch.setattr(generic, "execute", execute)
    return spans


def _call(server, tag):
    return server.call_tool(
        "run_windows_command", {"command": ["strings", tag], "purpose": "run"}
    )


def test_the_loop_keeps_answering_while_a_tool_runs(case, monkeypatch):  # noqa: F811
    _slow_runs(monkeypatch)
    server = srv.create_server()
    ticks = []

    async def main():
        async with anyio.create_task_group() as tg:
            done = anyio.Event()

            async def run():
                await _call(server, "A")
                done.set()

            tg.start_soon(run)
            while not done.is_set():  # what answers pings: the loop itself
                ticks.append(time.monotonic())
                await anyio.sleep(0.05)

    anyio.run(main)
    # a free loop ticks ~20 times in a 1 s run; a blocked one about once
    assert len(ticks) >= 10, len(ticks)


def test_a_second_call_waits_and_both_results_come_back(case, monkeypatch):  # noqa: F811
    spans = _slow_runs(monkeypatch)
    server = srv.create_server()
    results = {}

    async def main():
        async def one(tag):
            results[tag] = await _call(server, tag)

        async with anyio.create_task_group() as tg:
            tg.start_soon(one, "A")
            await anyio.sleep(0.1)
            tg.start_soon(one, "B")

    anyio.run(main)
    text = {tag: json.dumps(json.loads(r[0].text)) for tag, r in results.items()}
    assert "ran A" in text["A"] and "ran B" in text["B"]  # nothing lost
    (a, b) = sorted(spans)
    assert b[0] >= a[1]  # one at a time: B started once A ended


def test_an_async_tool_is_left_as_it_is():
    async def already_async():
        return "ok"

    assert srv.offload(already_async, []) is already_async


def test_a_queued_call_whose_caller_gave_up_never_runs(case, monkeypatch):  # noqa: F811
    """B waits behind A; its caller gives up (a timeout) before A ends. B's
    tool never starts afterwards: its caller was told it failed. (No active
    case: a run in a case is a job, which runs whatever its caller does.)"""
    from wintools_mcp.config import get_config

    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    get_config().case_dir = ""
    ran: list = []
    _slow_runs(monkeypatch)
    real = generic.execute

    def execute(command, **k):
        ran.append(command[-1])
        return real(command, **k)

    monkeypatch.setattr(generic, "execute", execute)
    server = srv.create_server()
    gave_up = []

    async def main():
        async def b():
            with anyio.move_on_after(0.3) as scope:
                await _call(server, "B")
            gave_up.append(scope.cancelled_caught)

        async with anyio.create_task_group() as tg:
            tg.start_soon(_call, server, "A")
            await anyio.sleep(0.1)
            tg.start_soon(b)

    anyio.run(main)
    assert gave_up == [True] and ran == ["A"], (gave_up, ran)


def test_a_directly_cancelled_tool_holds_the_limit_until_its_thread_ends():
    """asyncio's own Task.cancel() mid-run: the next tool starts only once
    the cancelled one's thread has ended."""
    limiter: list = []
    started = threading.Event()
    order: list = []

    def slow():
        started.set()
        time.sleep(0.5)
        order.append("cancelled tool ended")

    def quick():
        order.append("next tool ran")

    seen: dict = {}

    async def main():
        task = asyncio.ensure_future(srv.offload(slow, limiter)())
        while not started.is_set():
            await anyio.sleep(0.01)
        task.cancel()
        await anyio.sleep(0.05)
        await srv.offload(quick, limiter)()
        try:
            await task
        except asyncio.CancelledError:
            seen["cancelled"] = True

    anyio.run(main)
    assert order == ["cancelled tool ended", "next tool ran"], order
    assert seen == {"cancelled": True}
