"""sigcheck's and autorunsc's -c is a switch (print CSV), not an output
folder: in a case, nothing is appended to their command, so the file named
stays their only argument and they run instead of printing their usage. A
user's own -c passes through as given. Popen is replaced; no process starts.
"""

from __future__ import annotations

import pytest
from test_run_records import _evtx, _run, case, tools  # noqa: F401  (fixtures)


@pytest.fixture
def more_tools(tools, tmp_path):  # noqa: F811
    autorunsc = tmp_path / "Tools" / "autorunsc.exe"
    autorunsc.write_bytes(b"MZ-autorunsc")
    return {**tools, "autorunsc": str(autorunsc)}


def _offline_system(case):  # noqa: F811
    """autorunsc -z's folders: a Windows system's in the case."""
    win, user = case / "evidence" / "Windows", case / "evidence" / "Users" / "u"
    user.mkdir(parents=True, exist_ok=True)
    win.mkdir(exist_ok=True)
    return {"WIN": str(win), "USER": str(user)}


@pytest.mark.parametrize(
    "tool, args",
    [
        ("sigcheck", ["-h", "-nobanner", "FILE"]),
        ("sigcheck", ["-accepteula", "-nobanner", "-h", "-c", "FILE"]),
        ("autorunsc", ["-accepteula", "-c", "-h", "-s", "-z", "WIN", "USER"]),
        ("autorunsc", ["-accepteula", "-h", "-s", "-z", "WIN", "USER"]),
    ],
)
def test_nothing_is_appended_to_the_command(case, more_tools, tool, args, monkeypatch):  # noqa: F811
    # the account has accepted the EULA: no -accepteula is added either
    from wintools_mcp.tools import generic

    monkeypatch.setattr(generic, "eula_accepted", lambda key: True)
    ev = str(_evtx(case))
    system = {"FILE": ev, **_offline_system(case)}
    args = [system.get(a, a) for a in args]
    calls: list = []
    resp = _run(more_tools, tool, calls=calls, command=[tool, *args])
    assert resp["success"] is True, resp
    ((argv, _),) = calls
    assert argv[1:] == args  # exactly as given: no "-c <folder>" after the file
