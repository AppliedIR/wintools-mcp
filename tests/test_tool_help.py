"""get_windows_tool_help gives the installed tool's own help.

It is asked on every call with the tool's catalog help argv. The reply is
what the tool printed, stdout then stderr under "# --- stderr ---", with its
exit code: nothing judges whether it is help. The next argv is asked only
when the tool printed nothing at all. Hayabusa is asked its main help, which
lists its subcommands on 3.x and 4.x. At most 8 KB is inline, and a cut help
says how to read the rest. An acquisition tool and a script are never run
for it, and a EULA screen in place of the help is said, never accepted. The
audit entry carries no help text. Tools are stand-ins; their output is
synthetic, except:
- fixtures/raw_output: Sysinternals output captured on a Windows 11 guest
  (UTF-16LE with a BOM; stderr UTF-8), read through the real probe;
- fixtures/tool_help/autorunsc: autorunsc 14.3's -? on FOR508-Win (banner on
  stdout, usage on stderr);
- fixtures/main_help: Hayabusa's `help` (exit 0, stdout only), 4.1.0 on
  FOR508-Win and 3.9.0 on SIFT.
"""

from __future__ import annotations

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


@pytest.mark.parametrize("name", ["winpmem", "dumpit", "mactime"])
def test_an_acquisition_tool_or_a_script_is_never_run_for_help(case, installed, name):  # noqa: F811
    r = _help(name)
    assert (
        installed["asked"] == [] and "isn't run to read its help" in r["help_not_run"]
    )


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
