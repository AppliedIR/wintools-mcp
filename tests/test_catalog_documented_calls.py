"""Each corrected catalog entry gives its tool's documented call a valid run.

The values are the tools' own help (the installed help captured on a
Windows box, cited per row) or their official docs. A documented call is
run through the real run_windows_command, with Popen replaced: nothing is
appended that the tool doesn't take, and the input the call names is the
one recorded.
"""

from __future__ import annotations

from test_names_and_binaries import _call
from test_run_records import _entries, _evtx, case  # noqa: F401  (fixture)

from wintools_mcp.catalog import get_tool_def


def test_sbecmd_reads_the_folder_its_d_names(case, tmp_path):  # noqa: F811
    """SBECmd help: "-d <d>  Directory to look for registry hives"; no -f."""
    hives = case / "evidence" / "hives"
    hives.mkdir()
    resp, _, ran = _call(tmp_path, ["SBECmd.exe", "-d", str(hives)])
    assert resp["success"] is True, resp
    assert ran[0][1:3] == ["-d", str(hives)]
    entry = _entries(case)[-1]
    assert [i["path"] for i in entry["inputs"]] == [str(hives.resolve())]


def test_bstrings_gets_nothing_appended(case, tmp_path):  # noqa: F811
    """bstrings help: "-o <o>  File to save results to"; there is no --csv."""
    ev = _evtx(case)
    resp, _, ran = _call(tmp_path, ["bstrings.exe", "-f", str(ev)])
    assert resp["success"] is True and ran[0][1:] == ["-f", str(ev)]


def test_hayabusa_runs_its_command_as_given(case, tmp_path):  # noqa: F811
    """hayabusa v4.1.0 help: "dfir-timeline  Create a DFIR timeline"; its
    output is -o <FILE> (yamato-security.github.io/hayabusa/commands/dfir-timeline)."""
    args = ["dfir-timeline", "-d", str(case / "evidence"), "-w"]
    resp, _, ran = _call(tmp_path, ["hayabusa.exe", *args])
    assert resp["success"] is True and ran[0][1:] == args  # no --json-output <folder>


def test_chainsaw_names_only_the_options_v2_has(case, tmp_path):  # noqa: F811
    """chainsaw hunt (github.com/WithSecureLabs/chainsaw): -r/--rule,
    -s/--sigma, --mapping, --full, and the --csv/--json switches; no --rules
    or --lateral-all."""
    args = ["hunt", str(case / "evidence"), "-s", "sigma", "--mapping", "map.yml"]
    resp, _, ran = _call(tmp_path, ["chainsaw.exe", *args])
    assert resp["success"] is True and ran[0][1:] == args


def test_winpmem_takes_its_image_path_as_an_argument(case, tmp_path):  # noqa: F811
    """WinPmem 2.0.1 help: "winpmem.exe [option] [output path]"; no -o."""
    dest = str(case / "evidence" / "mem.raw")
    resp, _, ran = _call(tmp_path, ["winpmem.exe", dest])
    assert resp["success"] is True and ran[0][1:] == [dest]


def test_moneta_names_its_required_m_and_p(case, tmp_path):  # noqa: F811
    """Moneta v1.0 help: "REQUIRED -m {*|region|referenced|ioc} -p {*|PID}";
    no -a; "--option {from-base|statistics}"."""
    resp, _, ran = _call(tmp_path, ["moneta64.exe", "-m", "ioc", "-p", "1234"])
    assert resp["success"] is True and ran[0][1:] == ["-m", "ioc", "-p", "1234"]


def test_autorunsc_and_hollows_hunter_find_their_knowledge():
    """The forensic-knowledge names their caveats are found by: autorunsc,
    HollowsHunter."""
    assert get_tool_def("autorunsc").knowledge_name == "autorunsc"
    assert get_tool_def("hollows_hunter").knowledge_name == "HollowsHunter"


def test_kape_reads_a_bare_drive_letter_as_that_drive(case, tmp_path, monkeypatch):  # noqa: F811
    """KAPE help: "tsource  Target source drive to copy files from (C, D:, or F:\\
    for example)". Here a folder named C:\\ in the working folder stands in for
    the drive."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "C:\\").mkdir()
    args = ["--tsource", "C", "--target", "KapeTriage", "--tdest", str(case / "out")]
    resp, _, ran = _call(tmp_path, ["kape.exe", *args])
    assert resp["success"] is True and ran[0][1:] == args, resp
    entry = _entries(case)[-1]
    assert [i["path"] for i in entry["inputs"]] == [str((tmp_path / "C:\\").resolve())]
