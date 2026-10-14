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

import json
import time

import anyio
from starlette.applications import Starlette
from starlette.requests import Request
from test_batch_scan import _entries, case  # noqa: F401 - fixtures

from wintools_mcp import http_server
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
