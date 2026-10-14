"""Every run names the file that ran and its version; a tool update is seen
on the next run; a second copy of a tool is never silent.

- The version is read from the file's own VERSIONINFO (no run, so no EULA
  screen); a file without one is asked by its catalog probe (Hayabusa's
  `help`); one that can't be read is "unknown", and the run goes ahead.
- It is kept per file and read again when the file's size or time changes.
- `tool_version` and `resolved_path` are in the reply's metadata, in every
  reply shape (small output, the parsed CSV of a large one, parsed text, a
  stopped run), and in the run's audit entry.
- A cached result (no case) is never an older tool's: the tool file's size
  and time are in the cache key.
- A PATH hit kept by the binary search is checked on each call: a copy
  since removed is looked for again.
- check_windows_tools and get_windows_tool_help name every copy found, with
  its version, and which one runs (the search takes the first: a KAPE copy
  can sit before an updated ZimmermanTools one).

Tools are stand-ins; versions and paths are synthetic.
"""

from __future__ import annotations

import json
import os
import sys

import pydantic_core
import pytest
from test_batch_scan import _entries, case  # noqa: F401 - fixtures

from wintools_mcp import environment, versions
from wintools_mcp import server as srv
from wintools_mcp.config import get_config
from wintools_mcp.tools import generic

CSV_ROWS = "SourceFile,Url,LastVisited\n" + "".join(
    f"History,https://example.test/{i},2026-10-13 22:00:{i % 60:02d}\n"
    for i in range(400)
)


def _tool(name):
    return srv.create_server()._tool_manager._tools[name].fn.__wrapped__


def _sent(r):
    return json.loads(pydantic_core.to_json(r))


@pytest.fixture
def tool_file(tmp_path):
    p = tmp_path / "Tools" / "tool.exe"
    p.parent.mkdir()
    p.write_bytes(b"MZ-tool")
    return p


@pytest.fixture
def runs(monkeypatch, tool_file):
    """Every catalog binary resolves to `tool_file`, whose VERSIONINFO says
    `version`; each run prints `out` and exits 0. `executed` counts runs."""
    state = {"out": "done\n", "version": "1.5.0.0", "executed": 0, "read": []}
    monkeypatch.setattr(generic, "find_tool", lambda name: str(tool_file))
    monkeypatch.setattr(generic, "eula_accepted", lambda key: True, raising=False)

    def file_version(path):
        state["read"].append(path)
        return state["version"]

    monkeypatch.setattr(versions, "file_version", file_version)

    def execute(command, **k):
        state["executed"] += 1
        out = state["out"]
        return {"exit_code": 0, "stdout": out, "stderr": "", "command": list(command),
                "stdout_total_bytes": len(out.encode())}  # fmt: skip

    monkeypatch.setattr(generic, "execute", execute)
    return state


def _run(*command):
    return _sent(_tool("run_windows_command")(command=list(command), purpose="run"))


def _named(r, tool_file, version="1.5.0.0"):
    assert r["metadata"]["tool_version"] == version, r["metadata"]
    assert r["metadata"]["resolved_path"] == str(tool_file), r["metadata"]


def test_a_small_reply_names_the_file_and_its_version(case, runs, tool_file):  # noqa: F811
    r = _run("strings", "C:\\x")
    _named(r, tool_file)
    (entry,) = [e for e in _entries(case) if e["tool"] == "run_windows_command"]
    assert entry["result_summary"]["tool_version"] == "1.5.0.0"
    assert entry["result_summary"]["resolved_path"] == str(tool_file)


@pytest.mark.parametrize(
    "tool, out, shape",
    [("SQLECmd.exe", CSV_ROWS, "parsed_csv"), ("strings", "x" * 30000, "parsed_text")],
    ids=["parsed csv", "parsed text"],
)
def test_a_parsed_reply_names_the_file_and_its_version(
    case,  # noqa: F811
    runs,
    tool_file,
    tool,
    out,
    shape,
):
    """Output past the reply's budget is parsed, and stdout dropped."""
    runs["out"] = out
    from test_batch_scan import _files

    r = _run(tool, "-f", str(_files(case / "evidence" / "db", ["History"]) / "History"))
    assert r["output_format"] == shape, r["output_format"]
    _named(r, tool_file)


def test_a_stopped_reply_names_the_file_and_its_version(
    case,  # noqa: F811
    runs,
    tool_file,
    monkeypatch,
):
    def stopped(command, **k):
        return {"exit_code": 1, "stdout": "x\n", "stderr": "", "command": list(command),
                "stdout_total_bytes": 2, "terminated": "output limit (4096 bytes)"}  # fmt: skip

    monkeypatch.setattr(generic, "execute", stopped)
    r = _run("strings", "C:\\x")
    assert r["stopped"] == "output limit"
    _named(r, tool_file)


def test_a_batch_names_the_file_and_its_version(case, runs, tool_file):  # noqa: F811
    from test_batch_scan import _files

    folder = _files(case / "evidence" / "two", ["a.exe", "b.exe"])
    r = _sent(_tool("batch_scan")(tool="sigcheck", directory=str(folder)))
    assert (r["tool_version"], r["resolved_path"]) == ("1.5.0.0", str(tool_file)), r
    (entry,) = [e for e in _entries(case) if e["tool"] == "batch_scan"]
    assert entry["result_summary"]["tool_version"] == "1.5.0.0"


def test_a_file_is_read_once_and_again_when_it_changes(case, runs, tool_file):  # noqa: F811
    _run("strings", "C:\\x")
    _run("strings", "C:\\y")
    assert len(runs["read"]) == 1  # the same file: read once
    runs["version"] = "2026.5.0.0"
    st = tool_file.stat()
    tool_file.write_bytes(b"MZ-tool, updated")
    os.utime(tool_file, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))
    r = _run("strings", "C:\\x")
    _named(r, tool_file, "2026.5.0.0")


def test_without_versioninfo_the_catalog_probe_names_it(
    case,  # noqa: F811
    runs,
    tool_file,
    monkeypatch,
):
    runs["version"] = None
    asked = []

    def run_probe(argv):
        asked.append(argv)
        return "Hayabusa v3.9.0 - Dev Build\nUsage: hayabusa.exe <COMMAND>\n"

    monkeypatch.setattr(versions, "run_probe", run_probe)
    (case / "evidence").mkdir(exist_ok=True)
    r = _run("hayabusa.exe", "csv-timeline", "-d", str(case / "evidence"))
    _named(r, tool_file, "3.9.0")
    assert asked == [[str(tool_file), "help"]]


def test_a_probe_that_fails_is_unknown_and_the_run_goes_ahead(
    case,  # noqa: F811
    runs,
    tool_file,
    monkeypatch,
):
    runs["version"] = None
    monkeypatch.setattr(
        versions, "run_probe", lambda argv: "error: unexpected argument\n"
    )
    (case / "evidence").mkdir(exist_ok=True)
    r = _run("hayabusa.exe", "csv-timeline", "-d", str(case / "evidence"))
    assert r["success"] is True
    _named(r, tool_file, "unknown")
    assert r["metadata"]["version_probe_output"] == "error: unexpected argument"


def test_a_cached_result_is_never_an_older_tools(runs, tool_file, monkeypatch):
    """No case: a repeated call is answered from the cache, until the tool
    file changes."""
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    get_config().case_dir = ""
    _run("strings", "C:\\x")
    _run("strings", "C:\\x")
    assert runs["executed"] == 1  # the cache answered the second
    st = tool_file.stat()
    os.utime(tool_file, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))
    _run("strings", "C:\\x")
    assert runs["executed"] == 2  # the updated tool ran


def test_a_kept_path_hit_is_looked_for_again_once_gone(tmp_path, monkeypatch):
    first, second = tmp_path / "a" / "x.exe", tmp_path / "b" / "x.exe"
    for p in (first, second):
        p.parent.mkdir()
        p.write_bytes(b"MZ")
    on_path = [str(first)]
    monkeypatch.setattr(environment.shutil, "which", lambda name: on_path[0])
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", [])
    environment.clear_binary_cache()
    assert environment.find_binary("x.exe") == str(first)
    first.unlink()
    on_path[0] = str(second)
    assert environment.find_binary("x.exe") == str(second)


def test_every_copy_is_named_with_the_one_that_runs(tmp_path, monkeypatch):
    kape, ez = tmp_path / "KAPE" / "Modules" / "bin", tmp_path / "ZimmermanTools"
    for d in (kape, ez):
        d.mkdir(parents=True)
        (d / "PECmd.exe").write_bytes(b"MZ-" + d.name.encode())
    monkeypatch.setattr(environment.shutil, "which", lambda name: None)
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", [tmp_path / "KAPE", ez])
    environment.clear_binary_cache()
    monkeypatch.setattr(
        versions, "file_version", lambda p: "1.5.0.0" if "KAPE" in p else "2026.5.0.0"
    )
    found = _tool("check_windows_tools")(tool_names=["PECmd"])["pecmd"]
    assert found["installed_version"] == "2026.5.0.0"
    assert found["resolved_path"] == str(ez / "PECmd.exe")
    assert found["copies"] == [
        {"path": str(ez / "PECmd.exe"), "version": "2026.5.0.0", "runs": True},
        {"path": str(kape / "PECmd.exe"), "version": "1.5.0.0", "runs": False},
    ]
    shown = _tool("get_windows_tool_help")(tool_name="PECmd")
    assert shown["installed_version"] == "2026.5.0.0" and len(shown["copies"]) == 2


# The probe's reader as shipped, taken before conftest stands in for it
_READ = getattr(versions, "bounded_output", versions.run_probe)


def test_a_probe_of_a_tool_that_writes_megabytes_keeps_only_its_cap():
    """8 MiB on stdout: at most the cap is ever held, never the whole."""
    import sys
    import tracemalloc

    argv = [sys.executable, "-c", "import sys; sys.stdout.write('x' * 8_000_000)"]
    tracemalloc.start()
    try:
        text = _READ(argv)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert len(text) <= 2 * versions.PROBE_BYTES + 1
    assert peak < 2 * 1024 * 1024, peak


def test_every_path_folders_copy_is_listed(tmp_path, monkeypatch):
    """PATH resolves the first copy; a later PATH folder's copy is listed too."""
    first, later = tmp_path / "p1", tmp_path / "p2"
    for d in (first, later):
        d.mkdir()
        exe = d / "PECmd.exe"
        exe.write_bytes(b"MZ-" + d.name.encode())
        exe.chmod(0o755)
    monkeypatch.setenv("PATH", os.pathsep.join([str(first), str(later), "/usr/bin"]))
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", [])
    environment.clear_binary_cache()
    assert environment.find_all("PECmd.exe") == [
        str(first / "PECmd.exe"),
        str(later / "PECmd.exe"),
    ]
    assert environment.find_binary("PECmd.exe") == str(first / "PECmd.exe")


def test_a_probe_reads_both_streams_and_ends_at_its_deadline(monkeypatch):
    import subprocess
    import sys
    import time

    said = "import sys; print('v1.2.3'); print('warn', file=sys.stderr)"
    text = _READ([sys.executable, "-c", said])
    assert "v1.2.3" in text and "warn" in text
    monkeypatch.setattr(versions, "PROBE_SECONDS", 0.5)
    start = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        _READ([sys.executable, "-c", "import time; time.sleep(30)"])
    assert time.monotonic() - start < 10


def test_a_probe_whose_child_holds_its_pipes_still_ends_at_its_deadline(monkeypatch):
    """The tool ends, but a child it left keeps its stdout open: the probe
    returns what was read by the deadline, and never waits for the child."""
    import time

    monkeypatch.setattr(versions, "PROBE_SECONDS", 1.0)
    start = time.monotonic()
    grandchild = "import time; time.sleep(30)"
    tool = (
        "import subprocess, sys; "
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}]); print('v9.9.9')"
    )
    text = _READ([sys.executable, "-c", tool])
    assert time.monotonic() - start < 5
    assert "v9.9.9" in text
