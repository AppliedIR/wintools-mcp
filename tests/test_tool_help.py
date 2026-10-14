"""get_windows_tool_help gives the installed tool's own help.

It is asked on every call with the tool's catalog help argv. The reply is
what the tool printed, stdout then stderr under "# --- stderr ---", with its
exit code: nothing judges whether it is help. The next argv is asked only
when the tool printed nothing at all. Hayabusa is asked its main help, which
lists its subcommands on 3.x and 4.x. At most 8 KB is inline, and a cut help
says how to read the rest. A script is never run for it, and a EULA screen in place of the help is said, never accepted. The
audit entry carries no help text. Tools are stand-ins; their output is
synthetic, except:
- fixtures/raw_output: Sysinternals output captured on a Windows 11 guest
  (UTF-16LE with a BOM; stderr UTF-8), read through the real probe;
- fixtures/tool_help/autorunsc: autorunsc 14.3's -? on a Windows guest (banner
  on stdout, usage on stderr);
- fixtures/tool_help/winpmem: WinPmem 2.0.1's -h on a Windows guest (exit -1);
- fixtures/main_help: Hayabusa's `help` (exit 0, stdout only), 4.1.0 on
  a Windows guest and 3.9.0 on SIFT.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
from test_batch_scan import _entries, case  # noqa: F401 - fixtures
from test_eula_surrogate import EULA

from wintools_mcp import environment, versions
from wintools_mcp import server as srv

FIXTURES = Path(__file__).parent / "fixtures"
LABEL = "# --- stderr ---"


def _help(name):
    return (
        srv.create_server()
        ._tool_manager._tools["get_windows_tool_help"]
        .fn.__wrapped__(tool_name=name)
    )


@pytest.fixture
def installed(tmp_path, monkeypatch):
    """Every tool is installed (one stand-in file); `said` maps a help argv to
    what the tool prints; `asked` lists the argv asked."""
    exe = tmp_path / "Tools" / "tool.exe"
    exe.parent.mkdir()
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(environment, "find_tool", lambda name: str(exe))
    monkeypatch.setattr("wintools_mcp.tools.discovery.tool_path", lambda td: str(exe))
    monkeypatch.setattr(
        "wintools_mcp.tools.discovery.tool_copies", lambda b: [str(exe)]
    )
    monkeypatch.setattr(versions, "file_version", lambda p: "1.0.0.0")
    state = {"said": {}, "asked": []}

    def run_help(argv):  # said: stdout (exit 0), or (exit code, stdout, stderr)
        state["asked"].append(argv[1:])
        said = state["said"].get(" ".join(argv[1:]), "")
        return (0, said, "") if isinstance(said, str) else said

    monkeypatch.setattr(versions, "run_help", run_help, raising=False)
    return state


def test_the_help_is_the_tools_own(case, installed):  # noqa: F811
    installed["said"]["--help"] = (
        "PECmd version 1.5.0.0\n\nUsage: PECmd [options]\n  -f <f>\n"
    )
    r = _help("PECmd")
    assert (
        r.get("help")
        == f"PECmd version 1.5.0.0\n\nUsage: PECmd [options]\n  -f <f>\n\n{LABEL}"
    )
    assert r["help_argv"] == ["--help"] and r["help_exit_code"] == 0
    assert r["help_source"] == "the installed tool's own output, as text"


@pytest.mark.parametrize(
    "version, timeline", [("3.9.0", "csv-timeline"), ("4.1.0", "dfir-timeline")]
)
def test_hayabusa_is_asked_its_main_help_which_lists_its_subcommands(
    case,  # noqa: F811
    installed,
    version,
    timeline,
):
    printed = (FIXTURES / "main_help" / f"hayabusa-{version}.stdout").read_text()
    installed["said"]["help"] = printed
    r = _help("hayabusa")
    assert installed["asked"] == [["help"]]
    assert r.get("help", "").startswith(f"Hayabusa v{version}")
    assert f"  {timeline}  " in r["help"] and r["help_exit_code"] == 0


def test_a_sysinternals_tool_is_asked_with_its_usage_flag(case, installed):  # noqa: F811
    """-h is a switch for autorunsc and sigcheck (file hashes), never help."""
    installed["said"]["-?"] = "usage: autorunsc [-a <*|bdeghiklmoprsw>] ...\n"
    r = _help("autorunsc")
    assert installed["asked"] == [["-?"]] and r["help"].startswith("usage: autorunsc")


def test_a_long_help_is_cut_and_says_how_to_read_it(case, installed):  # noqa: F811
    installed["said"]["--help"] = "Usage: tool [options]\n" + "  -x  an option\n" * 2000
    r = _help("MFTECmd")
    assert len(r["help"]) == versions.HELP_INLINE
    assert "run_windows_command" in r["help_cut"] and "--help" in r["help_cut"]


def test_a_script_is_never_run_for_help(case, installed):  # noqa: F811
    r = _help("mactime")
    assert (
        installed["asked"] == [] and "isn't run to read its help" in r["help_not_run"]
    )


def test_winpmem_is_asked_only_its_help_switch(case, installed):  # noqa: F811
    """With no argument WinPmem 2.0.1 writes an image: only -h is sent."""
    fixture = FIXTURES / "tool_help" / "winpmem" / "no-version-resource" / "help.txt"
    said = fixture.read_text().split("\n", 1)[1]  # past the fixture's header line
    installed["said"]["-h"] = (-1, said, "")
    r = _help("winpmem")
    assert installed["asked"] == [["-h"]], installed["asked"]
    assert r["help_argv"] == ["-h"] and r["help_exit_code"] == -1
    assert r["help"].startswith("WinPmem64\nWinpmem - A memory imager for windows.")


def test_a_eula_screen_is_said_and_never_accepted(case, installed):  # noqa: F811
    installed["said"]["-?"] = EULA
    r = _help("strings")
    assert "EULA" in r["help_not_run"] and "help" not in r
    assert installed["asked"] == [["-?"]]  # no -accepteula


def test_the_audit_entry_carries_no_help_text(case, installed):  # noqa: F811
    installed["said"]["--help"] = "Usage: tool [options]\n  -f <file>\n"
    _help("PECmd")
    (entry,) = [e for e in _entries(case) if e["tool"] == "get_windows_tool_help"]
    assert "help" not in entry["result_summary"]
    assert entry["result_summary"]["help_chars"] == len(
        f"Usage: tool [options]\n  -f <file>\n\n{LABEL}"
    )


def test_an_error_is_shown_as_printed_with_its_exit_code(case, installed):  # noqa: F811
    """An "invalid option" is the tool's own answer: shown, never judged, and
    no other argv is asked."""
    installed["said"]["--help"] = (
        1, "", "invalid option -- '-'\nTry 'tool -h' for more information.\n"
    )  # fmt: skip
    r = _help("PECmd")
    assert installed["asked"] == [["--help"]]
    assert r.get("help") == (
        f"{LABEL}\ninvalid option -- '-'\nTry 'tool -h' for more information."
    )
    assert r["help_exit_code"] == 1 and r["help_argv"] == ["--help"]


def test_usage_on_stderr_is_kept_under_its_label(case, installed):  # noqa: F811
    """autorunsc -?: its banner on stdout, its usage on stderr; both shown."""
    captured = (FIXTURES / "tool_help" / "autorunsc" / "14.3" / "help.txt").read_text()
    out, err = captured.split("\n", 1)[1].split("\n--- stderr ---\n")
    installed["said"]["-?"] = (0, out, err)
    shown = _help("autorunsc").get("help", "")
    banner = shown.index("Sysinternals Autoruns v14.3")
    usage = shown.index("Usage: C:\\Forensic_Program_Files\\SysinternalsSuite")
    assert banner < shown.index(f"\n{LABEL}\n") < usage
    assert "-nobanner" in shown


def test_the_next_argv_is_asked_only_when_both_streams_are_empty(case, installed):  # noqa: F811
    installed["said"].update({"--help": (1, "", " \n"), "-h": "Usage: PECmd\n"})
    r = _help("PECmd")
    assert installed["asked"] == [["--help"], ["-h"]]
    assert r.get("help_argv") == ["-h"] and r["help"].startswith("Usage: PECmd")


def test_a_tool_that_prints_nothing_names_each_argv(case, installed):  # noqa: F811
    installed["said"].update({"--help": (1, "", ""), "-h": (0, "", "")})
    r = _help("PECmd")
    assert "help" not in r
    assert r["help_error"] == (
        "--help: printed nothing (exit code 1); -h: printed nothing (exit code 0)"
    )


RAW = Path(__file__).parent / "fixtures" / "raw_output"
EMIT = (
    "import sys; out, err = sys.argv[1:3]; "
    "sys.stdout.buffer.write(open(out, 'rb').read()); sys.stdout.flush(); "
    "err and sys.stderr.buffer.write(open(err, 'rb').read())"
)


def _prints(monkeypatch, tmp_path, stdout: bytes, stderr: Path | None = None):
    """The tool prints these bytes: the real probe reads them from a child."""
    out = tmp_path / "out.bin"
    out.write_bytes(stdout)
    argv = [sys.executable, "-c", EMIT, str(out), str(stderr or "")]
    monkeypatch.setattr(versions, "run_help", lambda a: versions.bounded_output(argv))


@pytest.mark.parametrize("bom", [True, False])
def test_a_sysinternals_help_in_utf16_is_read_as_text(
    case,  # noqa: F811
    installed,
    monkeypatch,
    tmp_path,
    bom,
):
    raw = (RAW / "autorunsc-14.3-help.stdout").read_bytes()
    _prints(
        monkeypatch,
        tmp_path,
        raw if bom else raw[2:],
        RAW / "autorunsc-14.3-help.stderr",
    )
    text = _help("autorunsc")["help"]
    assert "\x00" not in text and "\ufffd" not in text
    assert "Sysinternals Autoruns v14.3" in text and "Copyright © 2002-2026" in text
    assert "Autorunsc shows programs configured to autostart" in text


@pytest.mark.parametrize("bom", [True, False])
def test_a_eula_screen_in_utf16_is_said_and_never_accepted(
    case,  # noqa: F811
    installed,
    monkeypatch,
    tmp_path,
    bom,
):
    raw = (RAW / "sigcheck-2.90-eula.stdout").read_bytes()
    _prints(monkeypatch, tmp_path, raw if bom else raw[2:])
    r = _help("sigcheck")
    assert "EULA" in r.get("help_not_run", "") and "help" not in r, r.get("help", "")[
        :200
    ]


def test_a_tool_stopped_at_the_probe_cap_has_no_exit_code():
    """Its code would be the kill's (-9 here, 1 on Windows): read as the tool
    failing. A tool that ends by itself keeps its own."""
    spill = "import sys\nwhile True: sys.stdout.write('usage line\\n')"
    code, out, _ = versions.bounded_output([sys.executable, "-c", spill])
    assert code is None and len(out) >= versions.PROBE_BYTES
    ends = "import sys\nsys.stdout.write('usage\\n'); raise SystemExit(3)"
    assert versions.bounded_output([sys.executable, "-c", ends])[0] == 3


def test_a_tool_that_closes_its_pipes_before_it_exits_keeps_its_code():
    """Both pipes end a moment before the process does: it is waited for,
    never killed and read as stopped."""
    late = (
        "import os, sys, time\nsys.stdout.write('usage\\n'); sys.stdout.flush()\n"
        "os.close(1); os.close(2); time.sleep(0.5); os._exit(3)"
    )
    assert versions.bounded_output([sys.executable, "-c", late])[0] == 3


def test_a_help_past_the_probe_cap_claims_no_length(case, installed):  # noqa: F811
    installed["said"]["--help"] = (None, "  -x  an option\n" * 5000, "")
    r = _help("MFTECmd")
    assert r["help_exit_code"] is None
    assert re.findall(r"\d[\d,]*", r["help_cut"]) == ["8,192"], r["help_cut"]


def test_a_help_read_up_to_the_probe_cap_claims_no_length(case, installed, monkeypatch):  # noqa: F811
    """70,000 bytes and a normal exit: the probe reads 65,536 of them, so
    neither the cut nor the stream's mark gives a length."""
    writer = (
        "import sys\nsys.stderr.write('error: x\\n'); sys.stdout.write('u' * 70000)"
    )
    monkeypatch.setattr(
        versions,
        "run_help",
        lambda argv: versions.bounded_output([sys.executable, "-c", writer]),
    )
    r = _help("MFTECmd")
    assert re.findall(r"\d[\d,]*", r["help_cut"]) == ["8,192"], r["help_cut"]
    assert "\n[stdout cut here]\n" in r["help"], r["help"][-300:]
    assert r["help"].endswith(f"{LABEL}\nerror: x")


def test_a_long_usage_never_hides_the_error(case, installed):  # noqa: F811
    """9,000 characters on stdout, then the error on stderr: the label and the
    error stay inline, and the cut in stdout is marked."""
    installed["said"]["--help"] = (2, "u" * 9000 + "\n", "error: real problem\n")
    r = _help("PECmd")
    assert r["help"].endswith(f"\n{LABEL}\nerror: real problem"), r["help"][-200:]
    assert "[stdout cut here]" in r["help"]
    assert len(r["help"]) <= versions.HELP_INLINE
    assert r["help_exit_code"] == 2 and "run_windows_command" in r["help_cut"]


def test_a_long_stderr_keeps_its_start_inline_and_marks_the_cut(case, installed):  # noqa: F811
    installed["said"]["--help"] = (2, "u" * 9000, "error: first\n" + "e" * 5000)
    r = _help("PECmd")
    head, _, tail = r["help"].partition(f"\n{LABEL}\n")
    assert tail.startswith("error: first")
    assert tail.endswith("[stderr cut here]")
    assert len(tail) == versions.STDERR_INLINE
    assert "[stdout cut here]" in head
    assert len(r["help"]) == versions.HELP_INLINE


def test_a_short_usage_leaves_stderr_the_rest_of_the_room(case, installed):  # noqa: F811
    installed["said"]["--help"] = (1, "usage: tool\n", "e" * 20000)
    r = _help("PECmd")
    assert r["help"].startswith(f"usage: tool\n{LABEL}\neee")
    assert "stdout cut" not in r["help"]
    assert r["help"].endswith("[stderr cut here]")
    assert len(r["help"]) == versions.HELP_INLINE
