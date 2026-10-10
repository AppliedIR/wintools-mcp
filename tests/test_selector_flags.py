"""A flag that picks what a tool scans (autorunsc's -a categories,
hollows_hunter's /pid) takes no path: its value isn't an input file, so it
isn't refused as one that can't be found, and the tool runs. Popen is
replaced; no process starts.
"""

from __future__ import annotations

import pytest
from test_run_records import _entries, _run, case, tools  # noqa: F401  (fixtures)


@pytest.fixture
def more_tools(tools, tmp_path):  # noqa: F811
    out = dict(tools)
    for name in ("autorunsc", "hollows_hunter"):
        exe = tmp_path / "Tools" / f"{name}.exe"
        exe.write_bytes(b"MZ-" + name.encode())
        out[name] = str(exe)
    return out


@pytest.mark.parametrize(
    "tool, args",
    [
        ("autorunsc", ["-accepteula", "-a", "*", "-c", "-h"]),
        ("hollows_hunter", ["/pid", "1234", "/json"]),
    ],
)
def test_a_selector_flags_value_is_not_an_input(case, more_tools, tool, args):  # noqa: F811
    calls: list = []
    resp = _run(more_tools, tool, calls=calls, command=[tool, *args])
    assert resp["success"] is True and len(calls) == 1, resp
    (entry,) = _entries(case)
    assert entry.get("inputs", []) == []  # nothing read from the case
