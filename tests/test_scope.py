"""What wintools won't run: a command that names another system or a device,
or one that puts a tool in its own live mode on the Windows host.

wintools runs tools on data already in the case. A refused command is
answered with why, before any path in it is looked at, and nothing runs.
The share is a local folder that is the active case; Popen is replaced, so
no process starts. Values are synthetic.
"""

from __future__ import annotations

import os
import pathlib
import re

import pytest
from test_batch_scan import case as scan_case  # noqa: F401  (fixture)
from test_batch_scan import ran  # noqa: F401  (fixture)
from test_csv_switch import _offline_system
from test_names_and_binaries import _call
from test_run_records import case  # noqa: F401  (fixture)

from wintools_mcp import server as srv
from wintools_mcp.catalog import load_catalog
from wintools_mcp.tools import generic


@pytest.fixture(autouse=True)
def _eula_accepted(monkeypatch):
    """Every Sysinternals EULA reads as accepted: these rows are about what
    runs, and an unread EULA would run whoami first."""
    monkeypatch.setattr(generic, "eula_accepted", lambda key: True)


def _refused(tmp_path, command, says):
    resp, asked, argvs = _call(tmp_path, command)
    assert resp["success"] is False, resp
    assert re.search(says, resp["error"]), resp["error"]
    assert argvs == []
    return resp, asked


def _runs(tmp_path, command):
    resp, asked, argvs = _call(tmp_path, command)
    assert resp["success"] is True, resp
    assert len(argvs) == 1
    return resp


# --- Tools with no use on data in the case are gone ---


@pytest.mark.parametrize(
    "command",
    [
        ["dumpit"],
        ["dumpit.exe", "/Q"],
        ["procdump", "-ma", "1234"],
        ["procdump64.exe", "-ma", "1234"],
        ["handle"],
        ["handle64.exe", "-a"],
        ["hollows_hunter.exe", "/pid", "1234"],
        ["moneta64.exe", "-m", "*"],
        ["Get-InjectedThreadEx"],
    ],
)
def test_a_removed_tool_is_not_in_the_catalog(case, tmp_path, command):  # noqa: F811
    resp, asked = _refused(tmp_path, command, "not in the approved tool catalog")
    assert asked == []


_REMOVED = ["dumpit", "procdump", "handle", "hollows_hunter", "moneta"]


def test_a_removed_tool_is_not_listed_and_has_no_help():
    tools = srv.create_server()._tool_manager._tools
    listed = {
        t["name"].lower() for t in tools["list_windows_tools"].fn.__wrapped__()["tools"]
    }
    assert listed and listed.isdisjoint([*_REMOVED, "get-injectedthreadex"])
    for name in [*_REMOVED, "Get-InjectedThreadEx"]:
        resp = tools["get_windows_tool_help"].fn.__wrapped__(tool_name=name)
        assert "not found in catalog" in resp.get("error", ""), (name, resp)


# --- Another system, a device or a volume ---


@pytest.mark.parametrize(
    "arg",
    [
        r"\\evilhost\share\x.bin",
        "//evilhost/share/x.bin",
        r"--x=\\evilhost\share",
        r"\\?\UNC\evilhost\share\x.bin",
        r"\??\UNC\evilhost\share\x.bin",
        r"\\.\PhysicalDrive0",
        r"\\.\C:",
        r"\\?\Volume{00000000-0000-0000-0000-000000000000}\x.bin",
        r"\??\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\x.bin",
        r"x.bin,\\evilhost\share",
        r"C:\case\a;\\evilhost\share",
        r"-d:\\evilhost\share",
        r"@\\evilhost\share\list.txt",
        "https://evilhost/x.bin",
    ],
)
def test_another_system_or_a_device_is_refused(case, tmp_path, arg):  # noqa: F811
    _refused(tmp_path, ["strings", arg], "another system|device|volume")


def test_a_declared_input_on_another_system_is_refused(
    case,  # noqa: F811
    stats,
):
    run = srv.create_server()._tool_manager._tools["run_windows_command"].fn.__wrapped__
    resp = run(
        purpose="row",
        command=["strings", "x.bin"],
        input_files=[r"\\evilhost\share\list.txt"],
    )
    assert resp["success"] is False
    assert "another system (evilhost)" in resp["error"], resp["error"]
    assert stats == []


def test_a_local_long_path_runs(case, tmp_path):  # noqa: F811
    _runs(tmp_path, ["strings", r"\\?\C:\Windows\x.bin"])


@pytest.mark.parametrize(
    "arg",
    [
        r"-f\\evilhost\share\x.evtx",
        r"-d\\evilhost\share",
        r"-f\\?\UNC\evilhost\share\x.evtx",
        "-f//evilhost/share/x.evtx",
    ],
)
def test_another_system_as_an_attached_value_is_refused(
    case,  # noqa: F811
    tmp_path,
    arg,
):
    """Hayabusa's short options take a value attached to the letter."""
    _refused(tmp_path, ["hayabusa", "dfir-timeline", arg, "-w"], "another system")


@pytest.fixture
def stats(monkeypatch):
    """Every path looked at (stat or lstat) that names evilhost."""
    seen: list[str] = []

    def watch(real):
        def call(path, *a, **k):
            if "evilhost" in os.fspath(path):
                seen.append(os.fspath(path))
            return real(path, *a, **k)

        return call

    monkeypatch.setattr(os, "stat", watch(os.stat))
    monkeypatch.setattr(os, "lstat", watch(os.lstat))
    # 3.10's pathlib looks through an accessor, which has stat only (its
    # Path.lstat is stat with follow_symlinks=False)
    accessor = getattr(pathlib, "_NormalAccessor", None)
    for name in ("stat", "lstat"):
        if accessor is not None and name in vars(accessor):
            real = getattr(os, name)
            monkeypatch.setattr(accessor, name, staticmethod(watch(real)))
    return seen


def test_another_system_is_refused_before_any_path_is_looked_at(
    case,  # noqa: F811
    tmp_path,
    stats,
):
    run = srv.create_server()._tool_manager._tools["run_windows_command"].fn.__wrapped__
    resp = run(
        purpose="row",
        command=["strings", r"\\evilhost\share\x.bin"],
        input_files=[r"\\evilhost\share\y.bin"],
    )
    assert resp["success"] is False
    assert "another system (evilhost)" in resp["error"], resp["error"]
    assert stats == []


def test_run_command_refuses_before_finding_the_tool(case, monkeypatch):  # noqa: F811
    from wintools_mcp.exceptions import WintoolsError

    asked: list = []
    monkeypatch.setattr(generic, "find_tool", lambda name: asked.append(name))
    with pytest.raises(WintoolsError, match="another system"):
        generic.run_command(["strings64.exe", r"\\evilhost\share\x.bin"])
    assert asked == []


@pytest.mark.parametrize(
    "arg, refused",
    [
        (r"\\sift\cases\c1\x.bin", False),
        (r"\\SIFT\cases\c1\x.bin", False),
        ("//sift/cases/c1/x.bin", False),
        (r"\\?\UNC\sift\cases\c1\x.bin", False),
        (r"\??\C:\x.bin", False),
        (r"\\evilhost\cases\x.bin", True),
        (r"\\sift.evil\cases\x.bin", True),
        (r"C:\case\a,\\evilhost\s", True),
        (r"-d:\\evilhost\s", True),
        (r"/d:\\evilhost\s", True),
    ],
)
def test_only_the_case_shares_host_is_reached(arg, refused):
    from wintools_mcp.scope import refusal

    why = refusal(["strings", arg], "", r"\\sift\cases")
    assert bool(why) is refused, why


def test_with_no_share_every_host_is_refused():
    from wintools_mcp.scope import refusal

    assert "no case share" in refusal(["strings", r"\\sift\cases\x"], "", "")


# --- A tool's own live mode ---


@pytest.mark.parametrize(
    "command, says",
    [
        (["sigcheck", "-v", "x.exe"], "VirusTotal"),
        (["sigcheck", "-vt", "x.exe"], "VirusTotal"),
        (["sigcheck", "-vrs", "x.exe"], "VirusTotal"),
        (["sigcheck", "/v", "x.exe"], "VirusTotal"),
        (["sigcheck", "-o", "x.exe"], "VirusTotal"),
        (["sigcheck", "-t"], "certificate stores"),
        (["sigcheck", "-tuv"], "certificate stores"),
        (["hayabusa", "csv-timeline", "-l", "-o", "t.csv"], "live-analysis"),
        (["hayabusa", "csv-timeline", "-wl", "-o", "t.csv"], "live-analysis"),
        (["hayabusa", "csv-timeline", "--live-analysis"], "live-analysis"),
        (["hayabusa", "csv-timeline", "--live"], "live-analysis"),
        (["hayabusa", "update-rules"], "GitHub"),
        (["EvtxECmd", "--sync"], "GitHub"),
        (["SQLECmd", "--sync"], "GitHub"),
        (["RECmd", "--sync"], "GitHub"),
        (["SBECmd", "-l", "--csv", "out"], "live registry"),
        (["SBECmd", "/l", "--csv", "out"], "live registry"),
        (["SBECmd", "--l", "--csv", "out"], "live registry"),
        (["AppCompatCacheParser", "--csv", "out"], "without -f"),
        (["AppCompatCacheParser", "-F", "SYSTEM", "--csv", "out"], "without -f"),
        (["AppCompatCacheParser", "-f:", "--csv", "out"], "without -f"),
        (["AppCompatCacheParser", "--csv", "out", "-f"], "without -f"),
        (["yara", "rules.yar", "1234"], "target 1234 is a process id"),
        (["yara", "rules.yar", "+1234"], r"target \+1234 is a process id"),
        (["yara", "rules.yar", "1234", "-s"], "target 1234 is a process id"),
        (["yara", "rules.yar", " 1234", "-s"], "target  1234 is a process id"),
        (["yara", "rules.yar", " -1234", "-s"], "target  -1234 is a process id"),
        (["yara", "rules.yar", "1234", "--timeout=60"], "target 1234 is"),
        (["yara", "rules.yar", "1234", "-a", "60"], "target 1234 is"),
        (["yara", "rules.yar", "1234", "-sa", "60"], "target 1234 is"),
        (["yara", "rules.yar", "１２３４"], "is a process id"),
        (["yara", "-s", "-d", "x=1", "rules.yar", "1234"], "target 1234 is"),
        (["kape", "--tsource", "C:", "--target", "!SANS_Triage"], "target mode"),
        (["kape", "--target", "!SANS_Triage", "--tdest", "out"], "target mode"),
        (["kape", "--msource", "in", "--module", "m", "--sync"], "another system"),
        (["kape", "--msource", "in", "--module", "m", "--rlc"], "another system"),
        (["kape", "--msource", "in", "--module", "m", "--s3b", "b"], "another system"),
        (["kape", "--msource", "in", "--module", "m", "--asu", "u"], "another system"),
        (
            ["kape", "--msource", "in", "--module", "m", "--sftpc", "c"],
            "another system",
        ),
        (["kape", "--msource", "in", "--module", "m", "--scs", "h"], "another system"),
    ],
)
def test_a_live_mode_is_refused(case, tmp_path, command, says):  # noqa: F811
    _refused(tmp_path, command, says)


@pytest.mark.parametrize(
    "command",
    [
        ["sigcheck", "-a", "-h", "<E>/x.exe"],
        ["sigcheck", "-e", "<E>/x.exe"],
        ["hayabusa", "csv-timeline", "-dl", "-o", "t.csv"],
        ["EvtxECmd", "-f", "<E>/x.evtx", "--csv", "out"],
        ["SBECmd", "-d", "<E>/Users", "--csv", "out"],
        ["AppCompatCacheParser", "-f", "<E>/SYSTEM", "--csv", "out"],
        ["AppCompatCacheParser", "-f:<E>/SYSTEM", "--csv", "out"],
        ["yara", "<E>/rules.yar", "<E>/x.bin"],
        ["yara", "<E>/rules.yar", "<E>/x.bin", "-a", "60"],
        ["yara", "<E>/rules.yar", "<E>/x.bin", "-p", "4"],
        ["yara", "<E>/rules.yar", "<E>/Users", "-p", "4"],
        ["yara", "-d", "1234", "<E>/rules.yar", "<E>/x.bin"],
        ["yara", "<E>/1234", "<E>/x.bin"],
        ["kape", "--msource", "<E>/Users", "--module", "m", "--mdest", "out"],
    ],
)
def test_the_same_tools_run_on_the_case(case, tmp_path, command):  # noqa: F811
    """<E> is the case's evidence folder, which holds each file named."""
    ev = case / "evidence"
    (ev / "Users").mkdir()
    for name in ("x.exe", "x.evtx", "SYSTEM", "rules.yar", "x.bin", "1234"):
        (ev / name).write_bytes(b"synthetic")
    _runs(tmp_path, [a.replace("<E>", str(ev)) for a in command])


@pytest.mark.parametrize(
    "command",
    [
        ["yara", "1234", "x.bin"],
        ["yara", "1234", "5678", "x.bin"],
        ["yara", "-a", "60", "rules.yar", "x.bin"],
        ["yara", "rules.yar", "0x4D2"],
        ["yara", "rules.yar", "1234 "],
        ["yara", "rules.yar", "1234", "--"],
    ],
)
def test_a_yara_target_that_is_no_process_id_runs(command):
    """yara's target is its last positional argument, and strtol must read
    all of it: a rules file, an option's value, hex or a trailing space is
    not a process id."""
    from wintools_mcp.scope import refusal

    assert refusal(command, "", "") == ""


def test_autorunsc_runs_on_a_system_in_the_case(case, tmp_path):  # noqa: F811
    p = _offline_system(case)
    _runs(tmp_path, ["autorunsc", "-a", "*", "-z", p["WIN"], p["USER"]])


def test_autorunsc_on_the_host_or_outside_the_case_is_refused(
    case,  # noqa: F811
    tmp_path,
):
    p = _offline_system(case)
    outside = tmp_path / "elsewhere"
    (outside / "Windows").mkdir(parents=True)
    _refused(tmp_path, ["autorunsc", "-a", "*"], "without -z")
    _refused(tmp_path, ["autorunsc", "-z", p["WIN"]], "two folders")
    _refused(
        tmp_path,
        ["autorunsc", "-z", str(outside / "Windows"), p["USER"]],
        "isn't in the case",
    )
    _refused(tmp_path, ["autorunsc", "-v", "-z", p["WIN"], p["USER"]], "VirusTotal")


@pytest.mark.parametrize("option", ["-o", "-a", "/o", "-O"])
def test_autorunsc_z_given_as_an_options_value_is_refused(
    case,  # noqa: F811
    tmp_path,
    option,
):
    """autorunsc's -a and -o take a value: a -z right after one is that value,
    and autorunsc lists the Windows host's own entries."""
    p = _offline_system(case)
    _refused(tmp_path, ["autorunsc", option, "-z", p["WIN"], p["USER"]], "without -z")


def test_autorunsc_runs_with_an_output_file(case, tmp_path):  # noqa: F811
    p = _offline_system(case)
    _runs(tmp_path, ["autorunsc", "-o", "out.csv", "-z", p["WIN"], p["USER"]])


def test_autorunsc_with_no_case_is_refused():
    from wintools_mcp.scope import refusal

    assert "active case" in refusal(["autorunsc", "-z", "W", "U"], "", "")


# --- batch_scan ---


def _batch(tool, directory):
    fn = srv.create_server()._tool_manager._tools["batch_scan"].fn.__wrapped__
    return fn(tool=tool, directory=directory)


def test_batch_scan_refuses_a_folder_on_another_system(scan_case, ran):  # noqa: F811
    resp = _batch("sigcheck", r"\\evilhost\share\files")
    assert "another system" in resp.get("error", ""), resp
    assert ran == []


def test_batch_scan_refuses_a_tool_in_its_live_mode(scan_case, ran):  # noqa: F811
    folder = scan_case / "evidence" / "files"
    folder.mkdir(parents=True)
    (folder / "a.exe").write_bytes(b"MZ")
    resp = _batch("autorunsc", str(folder))
    assert "without -z" in resp.get("error", ""), resp
    assert ran == []


# --- What the server tells the AI ---

_STEERS = re.compile(
    r"acquir|dump memory|memory dump|evidence collection|live (collection|response)"
    r"|collect (evidence|artifacts|from)",
    re.I,
)


def test_no_served_text_steers_toward_collection(monkeypatch):
    import shutil
    import subprocess
    from types import SimpleNamespace

    server = srv.create_server()
    texts = {"instructions": srv._INSTRUCTIONS}
    for name, t in server._tool_manager._tools.items():
        texts[f"tool {name}"] = t.description or ""
    for name, td in load_catalog().items():
        texts[f"catalog {name}"] = td.description or ""
        for i, r in enumerate(td.recipes):
            texts[f"recipe {name} {i}"] = f"{r.get('task', '')} {r.get('notes', '')}"
    monkeypatch.setattr(shutil, "which", lambda name: "kape.exe")
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: SimpleNamespace(stdout="M:\n  m\n")
    )
    kape = server._tool_manager._tools["list_kape_targets"].fn.__wrapped__()
    texts["list_kape_targets"] = str(kape)
    steering = {k: m.group(0) for k, v in texts.items() if (m := _STEERS.search(v))}
    assert steering == {}
