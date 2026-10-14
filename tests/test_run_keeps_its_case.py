"""A run keeps the case it started in, and an SMB update waits for it.

With each tool in a worker thread, the server answers other requests while a
tool runs. A case deactivated (or another activated) mid-run must not move
the run's audit entry: the run pins the case active when it starts, and
writes its entry there. An SMB credentials update can drop the share a
running tool reads (`net use … /delete`), so it waits for the run, on the
tools' own limit of one. Both requests go through their real handlers; the
tool's work is a stand-in that sleeps. Values are synthetic.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from types import SimpleNamespace

import anyio
from starlette.applications import Starlette
from starlette.requests import Request
from test_batch_scan import _entries, case  # noqa: F401 - fixtures

from wintools_mcp import config, http_server
from wintools_mcp import server as srv
from wintools_mcp.config import get_config
from wintools_mcp.tools import generic

KEY = "vhir_wt_000000000000000000000000"
RUN_SECONDS = 1.0


def _slow_run(monkeypatch, ended: list):
    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")
    monkeypatch.setattr(generic, "eula_accepted", lambda key: True, raising=False)

    def execute(command, **k):
        time.sleep(RUN_SECONDS)
        ended.append(time.monotonic())
        return {"exit_code": 0, "stdout": "done\n", "stderr": "", "command": list(command),
                "stdout_total_bytes": 5}  # fmt: skip

    monkeypatch.setattr(generic, "execute", execute)


def _request(server, path: str, body: dict | None = None) -> Request:
    """A POST to the HTTP app's handler, as the gateway sends it."""
    app = Starlette()
    app.state.smb_update_lock = anyio.Lock()
    app.state.one_at_a_time = getattr(server, "one_at_a_time", [])
    raw = json.dumps(body or {}).encode()

    async def receive():
        return {"type": "http.request", "body": raw, "more_body": False}

    scope = {"type": "http", "method": "POST", "path": path, "query_string": b"",
             "headers": [(b"authorization", f"Bearer {KEY}".encode())], "app": app}  # fmt: skip
    return Request(scope, receive)


def test_a_case_deactivated_mid_run_keeps_the_runs_entry_in_its_case(case, monkeypatch):  # noqa: F811
    ended: list = []
    _slow_run(monkeypatch, ended)
    get_config().api_keys = {KEY: {"examiner": "t"}}
    server = srv.create_server()
    replies = {}

    async def main():
        async def run():
            replies["run"] = await server.call_tool(
                "run_windows_command", {"command": ["strings", "x"], "purpose": "run"}
            )

        async with anyio.create_task_group() as tg:
            tg.start_soon(run)
            await anyio.sleep(0.3)
            r = await http_server.deactivate_case(_request(server, "/cases/deactivate"))
            replies["deactivate"] = json.loads(r.body)

    anyio.run(main)
    assert replies["deactivate"] == {"status": "deactivated"}
    (entry,) = [e for e in _entries(case) if e["tool"] == "run_windows_command"]
    assert entry["params"]["command"][1:] == ["x"]


def test_an_smb_update_mid_run_waits_for_the_run(case, monkeypatch):  # noqa: F811
    ended: list = []
    _slow_run(monkeypatch, ended)
    get_config().api_keys = {KEY: {"examiner": "t"}}
    updated: list = []
    import wintools_mcp.smb as smb

    monkeypatch.setattr(
        smb,
        "establish_smb_session",
        lambda cfg: updated.append(time.monotonic()) or True,
    )
    server = srv.create_server()

    async def main():
        async def run():
            await server.call_tool(
                "run_windows_command", {"command": ["strings", "x"], "purpose": "run"}
            )

        async with anyio.create_task_group() as tg:
            tg.start_soon(run)
            await anyio.sleep(0.3)
            r = await http_server.update_smb_credentials(
                _request(server, "/config/update-smb", {"smb_password": "pw"})
            )
            assert r.status_code == 200

    anyio.run(main)
    assert updated and ended and updated[0] >= ended[0]  # after the run, never during


def test_a_case_deactivated_while_the_run_reads_it_never_splits_its_pin(
    case,  # noqa: F811
    monkeypatch,
):
    """A deactivation that lands between the pin's config copy and its
    VHIR_CASE_DIR read (the copy waits up to 1 s for one) must not give the
    run one case in its config and none in its environment."""
    get_config().api_keys = {KEY: {"examiner": "t"}}
    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")
    monkeypatch.setattr(generic, "eula_accepted", lambda key: True, raising=False)
    pins: list = []

    def execute(command, **k):
        pins.append(config.pinned())
        return {"exit_code": 0, "stdout": "done\n", "stderr": "", "command": list(command),
                "stdout_total_bytes": 5}  # fmt: skip

    monkeypatch.setattr(generic, "execute", execute)
    copied, deactivated = threading.Event(), threading.Event()
    real_copy = config.copy.copy

    def copy_then_switch(obj):
        out = real_copy(obj)
        if not copied.is_set():
            copied.set()
            deactivated.wait(1.0)  # a deactivation, if the loop is free to run one
        return out

    monkeypatch.setattr(config, "copy", SimpleNamespace(copy=copy_then_switch))
    server = srv.create_server()

    async def main():
        async def run():
            await server.call_tool(
                "run_windows_command", {"command": ["strings", "x"], "purpose": "run"}
            )

        async with anyio.create_task_group() as tg:
            tg.start_soon(run)
            while not copied.is_set():
                await anyio.sleep(0.01)
            await http_server.deactivate_case(_request(server, "/cases/deactivate"))
            deactivated.set()

    anyio.run(main)
    (pin,) = pins
    assert bool(pin.config.case_dir) == bool(pin.case_dir_env), pin
    assert pin.case_dir_env  # the case active as the run started


def test_a_cancelled_smb_update_holds_the_tools_until_its_worker_ends(
    case,  # noqa: F811
    monkeypatch,
):
    get_config().api_keys = {KEY: {"examiner": "t"}}
    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")
    monkeypatch.setattr(generic, "eula_accepted", lambda key: True, raising=False)
    times: dict = {}

    def execute(command, **k):
        times["tool"] = time.monotonic()
        return {"exit_code": 0, "stdout": "done\n", "stderr": "", "command": list(command),
                "stdout_total_bytes": 5}  # fmt: skip

    monkeypatch.setattr(generic, "execute", execute)
    started = threading.Event()
    import wintools_mcp.smb as smb

    def establish(cfg):
        started.set()
        time.sleep(1.0)
        times["smb_end"] = time.monotonic()
        return True

    monkeypatch.setattr(smb, "establish_smb_session", establish)
    server = srv.create_server()

    async def main():
        scope = anyio.CancelScope()

        async def update():
            with scope:
                await http_server.update_smb_credentials(
                    _request(server, "/config/update-smb", {"smb_password": "pw"})
                )

        async with anyio.create_task_group() as tg:
            tg.start_soon(update)
            while not started.is_set():
                await anyio.sleep(0.01)
            scope.cancel()  # the caller gave up: net use is still running
            await anyio.sleep(0.05)
            await server.call_tool(
                "run_windows_command", {"command": ["strings", "x"], "purpose": "run"}
            )

    anyio.run(main)
    assert times["tool"] >= times["smb_end"], times  # never under the update


def test_a_directly_cancelled_smb_update_holds_the_tools_and_is_still_saved(
    case,  # noqa: F811
    monkeypatch,
):
    """asyncio's own Task.cancel(), which anyio's thread call does not
    outlast: no tool runs until net use ends, and the update is still saved
    and audited before the cancel goes on."""
    get_config().api_keys = {KEY: {"examiner": "t"}}
    monkeypatch.setattr(generic, "find_tool", lambda name: f"C:/Tools/{name}")
    monkeypatch.setattr(generic, "eula_accepted", lambda key: True, raising=False)
    order: list = []

    def execute(command, **k):
        order.append("tool ran")
        return {"exit_code": 0, "stdout": "done\n", "stderr": "", "command": list(command),
                "stdout_total_bytes": 5}  # fmt: skip

    monkeypatch.setattr(generic, "execute", execute)
    started = threading.Event()
    import wintools_mcp.smb as smb

    def establish(cfg):
        started.set()
        time.sleep(1.0)
        order.append("net use ended")
        return True

    monkeypatch.setattr(smb, "establish_smb_session", establish)
    saved: list = []
    logged: list = []
    monkeypatch.setattr(
        http_server, "_persist_config_fields", lambda c, fields: saved.append(fields)
    )
    monkeypatch.setattr(http_server._control_audit, "log", lambda **k: logged.append(k))
    server = srv.create_server()
    seen: dict = {}

    async def main():
        task = asyncio.ensure_future(
            http_server.update_smb_credentials(
                _request(server, "/config/update-smb", {"smb_password": "pw"})
            )
        )
        while not started.is_set():
            await anyio.sleep(0.01)
        task.cancel()  # net use is still running
        await anyio.sleep(0.05)
        await server.call_tool(
            "run_windows_command", {"command": ["strings", "x"], "purpose": "run"}
        )
        try:
            await task
        except asyncio.CancelledError:
            seen["cancelled"] = True

    anyio.run(main)
    assert order == ["net use ended", "tool ran"], order  # never under the update
    assert seen == {"cancelled": True}
    assert [f["smb_password"] for f in saved] == ["pw"]
    assert [e["tool"] for e in logged] == ["update_smb_credentials"]
