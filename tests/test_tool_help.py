"""get_windows_tool_help gives the installed tool's own help.

It is asked on every call with the tool's catalog help argv, tried in order:
the first that prints usage wins (Hayabusa 4.x answers `dfir-timeline
--help`, 3.x only `csv-timeline --help`); with none, the first that prints
anything. At most 8 KB is inline, and a cut help says how to read the rest.
An acquisition tool and a script are never run for it, and a EULA screen in
place of the help is said, never accepted. The audit entry carries no help
text. Tools are stand-ins; their output is synthetic, except the raw bytes
under fixtures/raw_output: Sysinternals output captured on a Windows 11
guest (UTF-16LE with a BOM; stderr UTF-8), read through the real probe.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from test_batch_scan import _entries, case  # noqa: F401 - fixtures
from test_eula_surrogate import EULA

from wintools_mcp import environment, versions
from wintools_mcp import server as srv

H3 = "Hayabusa v3.9.0\n\nUsage: hayabusa.exe csv-timeline <INPUT> [OPTIONS]\n\nOptions:\n  -d, --directory <DIR>\n  -t, --threads <NUMBER>\n"
# What each version prints for the other's subcommand (clap, on stderr; the probe
# reads stdout, then stderr): Hayabusa 3.9.0 on SIFT, and 4.1.0 on a Windows guest
NO_DFIR_3 = (
    "\nerror: unrecognized subcommand 'dfir-timeline'\n\n"
    "  tip: a similar subcommand exists: 'csv-timeline'\n\n"
    "Usage: hayabusa [COMMAND]\n\nFor more information, try 'help'.\n"
)
NO_CSV_4 = (
    "\nerror: unrecognized subcommand 'csv-timeline'\n\n"
    "  tip: a similar subcommand exists: 'dfir-timeline'\n\n"
    "Usage: hayabusa.exe [COMMAND]\n\nFor more information, try 'help'.\n"
)
H4 = (
    "Hayabusa v4.1.0 - Suzumushi Release\n\nUsage:\n"
    "  hayabusa.exe dfir-timeline <INPUT> [OPTIONS]\n\nOptions:\n  -t, --output-type <TYPE>\n"
)


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

    def run_probe(argv):
        state["asked"].append(argv[1:])
        return state["said"].get(" ".join(argv[1:]), "")

    monkeypatch.setattr(versions, "run_probe", run_probe)
    return state


def test_the_help_is_the_tools_own(case, installed):  # noqa: F811
    installed["said"]["--help"] = (
        "PECmd version 1.5.0.0\n\nUsage: PECmd [options]\n  -f <f>\n"
    )
    r = _help("PECmd")
    assert r["help"].startswith("PECmd version 1.5.0.0") and r["help_argv"] == [
        "--help"
    ]
    assert r["help_source"] == "the installed tool's own output, as text"


def test_hayabusa_3_answers_its_csv_timeline_help(case, installed):  # noqa: F811
    installed["said"].update(
        {"dfir-timeline --help": NO_DFIR_3, "csv-timeline --help": H3}
    )
    r = _help("hayabusa")
    assert r["help_argv"] == ["csv-timeline", "--help"] and "--threads" in r["help"]
    assert installed["asked"] == [
        ["dfir-timeline", "--help"],
        ["csv-timeline", "--help"],
    ]


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
        "Usage: tool [options]\n  -f <file>"
    )


def test_hayabusa_4_answers_its_dfir_timeline_help(case, installed):  # noqa: F811
    installed["said"].update(
        {"dfir-timeline --help": H4, "csv-timeline --help": NO_CSV_4}
    )
    r = _help("hayabusa")
    assert (
        r["help_argv"] == ["dfir-timeline", "--help"] and "--output-type" in r["help"]
    )
    assert installed["asked"] == [["dfir-timeline", "--help"]]


def test_an_argv_refused_with_an_error_is_never_the_help(case, installed):  # noqa: F811
    """Every argv refused: no help, and each error named."""
    installed["said"].update(
        {"dfir-timeline --help": NO_DFIR_3, "csv-timeline --help": NO_CSV_4,
         "help": "error: unexpected argument\n"}
    )  # fmt: skip
    r = _help("hayabusa")
    assert "help" not in r
    assert "dfir-timeline --help: error: unrecognized subcommand" in r["help_error"]


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
    monkeypatch.setattr(versions, "run_probe", lambda a: versions.bounded_output(argv))


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
