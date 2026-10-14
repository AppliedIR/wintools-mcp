"""Long runs in a case: started, answered within a wait, and polled after.

run_windows_command and batch_scan, in an active case, run as jobs. The call
waits up to WAIT_SECONDS: a run done by then gets its reply as before. A
longer one answers {state: running, run_id, op_folder, message}, keeps
running, and get_windows_run(run_id, wait) returns its reply once it's done
(or running, queued, stopped, failed). Runs go one at a time, as every tool
does; a call that finds QUEUE_LIMIT runs waiting is refused.

Jobs live in this process only. A gateway restart doesn't touch them; a
wintools restart forgets them, and a poll then answers that wintools has no
record of the run. At most KEEP finished jobs are kept, counted as a run
finishes and as a reply is delivered: delivered ones go first, then
undelivered ones, each oldest finished first. A job a call is waiting on is
neither counted nor let go, so a run that just finished is never let go
before its waiting caller has its reply; once delivered it is the first to
go. A caller that times out or is cancelled stops waiting, and its job counts
again. A run let go is answered as an unknown one: its reply and its
pending-hash markers are lost, as they are when wintools restarts.

The pending-hash markers (files over the hash limit) are delivered with the
first delivery of a finished reply only, so the gateway hashes them once.
"""

from __future__ import annotations

import asyncio
import contextvars
import copy
import itertools
import os
from dataclasses import dataclass, field
from typing import Any

WAIT_SECONDS = float(os.environ.get("WINTOOLS_WAIT_SECONDS", "60"))
QUEUE_LIMIT = 4
KEEP = 32  # finished jobs kept for polls
POLL_EVERY = "30 seconds"
DELIVERED = "pending, recorded at this result's first delivery"


@dataclass
class Job:
    run_id: str
    tool: str
    op_folder: str
    state: str = "queued"  # queued, running, finished, stopped, failed
    reply: dict | None = None
    done: asyncio.Event = field(default_factory=asyncio.Event)
    delivered: bool = False
    task: Any = None
    finished: int = 0  # finish order
    waiters: int = 0  # wait() calls blocked on it now


_jobs: dict[str, Job] = {}
_finish_order = itertools.count(1)

# The run id a job's tool body takes as its audit id (set in its thread)
RUN_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "wintools_run_id", default=None
)


def clear() -> None:
    """Forget every job (tests; a wintools restart does the same)."""
    _jobs.clear()


def waiting() -> int:
    return sum(1 for j in _jobs.values() if j.state == "queued")


def _evict() -> None:
    """Keep at most KEEP finished jobs that no call is waiting on: delivered
    ones go first, then undelivered ones, each oldest finished first. Called
    as a run finishes and once a reply is marked delivered."""
    finished = [j for j in _jobs.values() if j.done.is_set() and not j.waiters]
    extra = len(finished) - KEEP
    if extra > 0:
        for job in sorted(finished, key=lambda j: (not j.delivered, j.finished))[
            :extra
        ]:
            del _jobs[job.run_id]


def outcome(reply: dict) -> str:
    """finished, stopped (wintools stopped it) or failed (it didn't run)."""
    if reply.get("stopped"):
        return "stopped"
    return (
        "finished"
        if reply.get("success") or reply.get("results") is not None
        else "failed"
    )


def deliver(job_reply: dict, first: bool) -> dict:
    """The finished reply; after its first delivery, the pending-hash markers
    say they were delivered already, so they're recorded once."""
    if first:
        return job_reply
    reply = copy.deepcopy(job_reply)
    for key in ("inputs", "outputs"):
        for f in reply.get(key) or []:
            if isinstance(f, dict) and f.get("hash_state") == "pending":
                f["hash_state"] = DELIVERED
    return reply


def running_reply(job: Job) -> dict:
    return {
        "state": job.state,
        "run_id": job.run_id,
        "op_folder": job.op_folder,
        "message": (
            f"The {job.tool} run is {job.state}. Call get_windows_run(run_id) every "
            f"{POLL_EVERY} to follow it, and report its progress to the examiner, "
            "until it is finished, stopped or failed. Its result survives a gateway "
            "restart, but not a wintools restart."
        ),
    }


def unknown_reply(run_id: str) -> dict:
    return {
        "success": False,
        "state": "unknown",
        "run_id": run_id,
        "error": (
            "wintools has no record of this run. It may have restarted, or it let "
            f"the run's reply go after {KEEP} newer runs finished. Check "
            f"extractions/{run_id}/ and re-run if needed."
        ),
    }


async def start(tool: str, run_id: str, op_folder: str, work) -> dict:
    """Run ``work`` (an async callable giving the reply) as a job, and answer
    within WAIT_SECONDS: its reply, or that it is still running or queued."""
    if waiting() >= QUEUE_LIMIT:
        return {
            "success": False,
            "state": "failed",
            "error": f"{waiting()} runs are waiting already: try again once one is done "
            "(get_windows_run tells when)",
        }
    job = Job(run_id, tool, op_folder)
    _jobs[run_id] = job

    def began() -> None:  # called in the run's thread, as it starts
        job.state = "running"

    async def run() -> None:
        try:
            reply = await work(began)
        except Exception as e:  # noqa: BLE001 - the run failed: say why
            reply = {"success": False, "error": f"{type(e).__name__}: {e}"}
        job.reply, job.state = reply, outcome(reply)
        job.finished = next(_finish_order)
        job.done.set()
        _evict()

    job.task = asyncio.get_running_loop().create_task(run())
    return await wait(job, WAIT_SECONDS)


async def wait(job: Job, seconds: float) -> dict:
    """The job's reply once it's done, waiting up to ``seconds``; else that it
    is queued or running. A done job always gives its reply, whatever the wait,
    and so does one that ends as the wait runs out: while this waits, the job
    is never let go."""
    job.waiters += 1
    try:
        if not job.done.is_set():
            try:
                await asyncio.wait_for(
                    asyncio.shield(job.done.wait()), timeout=max(0.0, seconds)
                )
            except asyncio.TimeoutError:
                pass
    finally:
        job.waiters -= 1
    if not job.done.is_set():
        return running_reply(job)
    first = not job.delivered
    job.delivered = True
    _evict()
    return deliver(job.reply or {}, first=first)


async def poll(run_id: str, seconds: float) -> dict:
    """get_windows_run: this process's job, waited on up to ``seconds`` (at
    most WAIT_SECONDS); a run it has no record of is named so."""
    job = _jobs.get(run_id)
    if job is None:
        return unknown_reply(run_id)
    return await wait(job, min(seconds, WAIT_SECONDS))
