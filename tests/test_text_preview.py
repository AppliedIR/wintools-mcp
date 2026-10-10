"""sigcheck and autorunsc print text unless given -c, so a long output is
previewed as text: a comma in a publisher's name isn't a field separator.
With -c the CSV arrives as the tool printed it. Popen is replaced; no
process starts.
"""

from __future__ import annotations

import json

import pytest
from test_run_records import _evtx, _run, case, tools  # noqa: F401  (fixtures)

ENTRY = "c:\\tools\\a{n}.exe:\n\tVerified:\tUnsigned\n\tPublisher:\tExample, Inc.\n"


@pytest.mark.parametrize(
    "tool, args",
    [
        ("sigcheck", ["-nobanner", "-s", "FOLDER"]),
        ("autorunsc", ["-accepteula", "-h", "-s"]),
    ],
)
def test_a_long_text_output_is_previewed_as_text(case, tools, tmp_path, tool, args):  # noqa: F811
    folder = str(_evtx(case).parent)
    exe = tmp_path / "Tools" / "autorunsc.exe"
    exe.write_bytes(b"MZ-autorunsc")
    stdout = "".join(ENTRY.format(n=n) for n in range(4000)).encode()
    command = [tool, *(folder if a == "FOLDER" else a for a in args)]
    resp = _run({**tools, "autorunsc": str(exe)}, tool, stdout=stdout, command=command)
    assert resp["success"] is True, resp
    assert resp.get("output_format") != "parsed_csv"
    assert "Example, Inc." in json.dumps(resp)  # not cut at the comma
