"""Long runs in a case: started, answered within a wait, and polled after.

run_windows_command and batch_scan, in an active case, run as jobs. The call
waits up to WAIT_SECONDS: a run done by then gets its reply as before. A
longer one answers {state: running, run_id, op_folder, message}, keeps
running, and get_windows_run(run_id, wait) returns its reply once it's done
(or running, queued, stopped, failed). Runs go one at a time, as every tool
does; a call that finds QUEUE_LIMIT runs waiting is refused.

Each run keeps a state file BESIDE its op folder (extractions/<run_id>.state.json:
inside the folder it would be recorded as one of the tool's outputs), written
whole each time (temp file, then replace): {state, started, instance} at the
start and {state, reply} at the end. The reply is saved in the case, so a
gateway restart loses nothing. A running state left by another instance of
wintools means wintools restarted during the run: the run failed, and that is
written to the run's own audit log once.

The pending-hash markers (files over the hash limit) are delivered with the
first delivery of a finished reply only, so the gateway hashes them once.
"""

from __future__ import annotations

import asyncio
import contextvars
import copy
import json
import os
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

INSTANCE = uuid.uuid4().hex  # this process: a run started by another one is lost
WAIT_SECONDS = float(os.environ.get("WINTOOLS_WAIT_SECONDS", "60"))
QUEUE_LIMIT = 4
POLL_EVERY = "30 seconds"
DELIVERED = "pending, recorded at this result's first delivery"


@dataclass
class Job:
    run_id: str
    tool: str
    state_file: Path
    op_folder: str
    state: str = "queued"  # queued, running, finished, stopped, failed
    reply: dict | None = None
    done: asyncio.Event = field(default_factory=asyncio.Event)
    delivered: int = 0
    task: Any = None


_jobs: dict[str, Job] = {}

# The run id a job's tool body takes as its audit id (set in its thread)
RUN_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "wintools_run_id", default=None
)


def clear() -> None:
    """Forget every job (tests)."""
    _jobs.clear()


def waiting() -> int:
    return sum(1 for j in _jobs.values() if j.state == "queued")


def state_file(case_dir: str, run_id: str) -> Path:
    return Path(case_dir) / "extractions" / f"{run_id}.state.json"


def write_state(path: Path, record: dict) -> None:
    """The run's state, written whole: a reader sees the old or the new."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(record, f, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_state(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
            "until it is finished, stopped or failed. The result is saved in the case "
            "and survives a gateway restart."
        ),
    }


async def start(tool: str, run_id: str, case_dir: str, op_folder: str, work) -> dict:
    """Run ``work`` (an async callable giving the reply) as a job, and answer
    within WAIT_SECONDS: its reply, or that it is still running or queued."""
    if waiting() >= QUEUE_LIMIT:
        return {
            "success": False,
            "state": "failed",
            "error": f"{waiting()} runs are waiting already: try again once one is done "
            "(get_windows_run tells when)",
        }
    job = Job(run_id, tool, state_file(case_dir, run_id), op_folder)
    _jobs[run_id] = job
    write_state(job.state_file, {"state": "queued", "started": _now(), "instance": INSTANCE,
                                 "tool": tool})  # fmt: skip

    def began() -> None:  # called in the run's thread, as it starts
        job.state = "running"
        write_state(job.state_file, {"state": "running", "started": _now(),
                                     "instance": INSTANCE, "tool": tool})  # fmt: skip

    async def run() -> None:
        try:
            reply = await work(began)
        except Exception as e:  # noqa: BLE001 - the run failed: say why
            reply = {"success": False, "error": f"{type(e).__name__}: {e}"}
        job.reply, job.state = reply, outcome(reply)
        write_state(job.state_file, {"state": job.state, "finished": _now(),
                                     "instance": INSTANCE, "tool": tool, "reply": reply})  # fmt: skip
        job.done.set()

    job.task = asyncio.get_running_loop().create_task(run())
    return await wait(job, WAIT_SECONDS)


async def wait(job: Job, seconds: float) -> dict:
    try:
        await asyncio.wait_for(
            asyncio.shield(job.done.wait()), timeout=max(0.0, seconds)
        )
    except asyncio.TimeoutError:
        return running_reply(job)
    job.delivered += 1
    return deliver(job.reply or {}, first=job.delivered == 1)


async def poll(run_id: str, seconds: float, case_dir: str, lost) -> dict:
    """get_windows_run: this process's job, else the run's state file (a run
    whose wintools restarted is failed; ``lost`` records that once)."""
    job = _jobs.get(run_id)
    if job is not None:
        return await wait(job, min(seconds, WAIT_SECONDS))
    if not case_dir or "/" in run_id or "\\" in run_id or ".." in run_id:
        return {
            "success": False,
            "state": "failed",
            "error": f"no run {run_id!r} in the active case",
        }
    path = state_file(case_dir, run_id)
    record = read_state(path)
    if record is None:
        return {
            "success": False,
            "state": "failed",
            "error": f"no run {run_id!r} in the active case",
        }
    if (
        record.get("state") in ("queued", "running")
        and record.get("instance") != INSTANCE
    ):
        why = "wintools restarted during the run: its result was never written"
        record = {**record, "state": "failed", "failed": _now(), "error": why}
        write_state(path, record)
        lost(run_id, record)  # its audit entry, once: the state is failed from now on
    if "reply" in record:
        first = not record.get("delivered")
        if first:
            write_state(path, {**record, "delivered": True})
        return deliver(record["reply"], first=first)
    out = {"state": record.get("state"), "run_id": run_id}
    if record.get("error"):
        out.update(success=False, error=record["error"])
    return out
