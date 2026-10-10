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


@pytest.mark.parametrize(
    "tool, args",
    [
        ("sigcheck", ["-h", "-nobanner", "FILE"]),
        ("sigcheck", ["-accepteula", "-nobanner", "-h", "-c", "FILE"]),
        ("autorunsc", ["-accepteula", "-c", "-h", "-s"]),
        ("autorunsc", ["-accepteula", "-h", "-s"]),
    ],
)
def test_nothing_is_appended_to_the_command(case, more_tools, tool, args):  # noqa: F811
    ev = str(_evtx(case))
    args = [ev if a == "FILE" else a for a in args]
    calls: list = []
    resp = _run(more_tools, tool, calls=calls, command=[tool, *args])
    assert resp["success"] is True, resp
    ((argv, _),) = calls
    assert argv[1:] == args  # exactly as given: no "-c <folder>" after the file
