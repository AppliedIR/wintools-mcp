"""Which copy of a tool runs when a box has several.

The configured folders come first, then PATH, then the default folders with
C:\\Tools last. A copy KAPE bundles in its Modules\\bin runs only when there is
no other; every copy is still listed. In one folder, a copy under netN ranks
by N, highest first, and a .NET Framework one (net48, net472) below them.
A relative folder, a drive root or "." is read by its folder names the same
way.
"""

import os
from pathlib import Path

import pytest

from wintools_mcp import environment


def _exe(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"MZ")
    return path


@pytest.fixture
def no_path(monkeypatch):
    monkeypatch.setattr(environment.shutil, "which", lambda name: None)
    environment.clear_binary_cache()
    yield
    environment.clear_binary_cache()


@pytest.fixture
def name_order(monkeypatch):
    """Folders listed in name order, as NTFS lists them."""
    walk = os.walk

    def listed(top, *args, **kwargs):
        for root, dirs, files in walk(top, *args, **kwargs):
            dirs.sort(key=str.lower)
            yield root, dirs, sorted(files, key=str.lower)

    monkeypatch.setattr(environment.os, "walk", listed)


def test_the_standalone_copy_runs_over_kapes_bundled_one(
    tmp_path, monkeypatch, no_path
):
    kape = _exe(tmp_path / "KAPE" / "Modules" / "bin" / "EvtxECmd" / "EvtxECmd.exe")
    net9 = _exe(tmp_path / "ZimmermanTools" / "net9" / "EvtxeCmd" / "EvtxECmd.exe")
    folders = [tmp_path / "KAPE", tmp_path / "ZimmermanTools"]
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", folders)
    assert environment.find_binary("EvtxECmd.exe") == str(net9)
    assert environment.find_all("EvtxECmd.exe") == [str(net9), str(kape)]


def test_in_one_folder_the_bundled_copy_is_named_last(tmp_path, monkeypatch, no_path):
    root = tmp_path / "Forensic_Program_Files"
    kape = _exe(root / "kape" / "Modules" / "bin" / "PECmd.exe")
    net9 = _exe(root / "ZimmermanTools" / "net9" / "PECmd.exe")
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", [root])
    assert environment.find_binary("PECmd.exe") == str(net9)
    assert environment.find_all("PECmd.exe") == [str(net9), str(kape)]


def test_a_tool_only_kape_bundles_still_runs(tmp_path, monkeypatch, no_path):
    kape = _exe(tmp_path / "KAPE" / "Modules" / "bin" / "RBCmd.exe")
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", [tmp_path / "KAPE"])
    assert environment.find_binary("RBCmd.exe") == str(kape)


def test_a_configured_folder_runs_before_path(tmp_path, monkeypatch):
    on_path = _exe(tmp_path / "path" / "PECmd.exe")
    configured = _exe(tmp_path / "configured" / "PECmd.exe")
    monkeypatch.setattr(environment.shutil, "which", lambda name: str(on_path))
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", [])
    environment.clear_binary_cache()
    extra = [tmp_path / "configured"]
    assert environment.find_binary("PECmd.exe", extra) == str(configured)
    assert environment.find_all("PECmd.exe", extra) == [str(configured), str(on_path)]


def test_a_configured_folder_runs_before_the_default_folders(
    tmp_path, monkeypatch, no_path
):
    default = _exe(tmp_path / "default" / "PECmd.exe")
    configured = _exe(tmp_path / "configured" / "net9" / "PECmd.exe")
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", [tmp_path / "default"])
    extra = [tmp_path / "configured"]
    assert environment.find_binary("PECmd.exe", extra) == str(configured)
    assert environment.find_all("PECmd.exe", extra) == [str(configured), str(default)]


def test_a_bundled_copy_on_path_runs_after_a_folder_copy(tmp_path, monkeypatch):
    bundled = _exe(tmp_path / "KAPE" / "Modules" / "bin" / "PECmd.exe")
    standalone = _exe(tmp_path / "ZimmermanTools" / "PECmd.exe")
    monkeypatch.setattr(environment.shutil, "which", lambda name: str(bundled))
    monkeypatch.setattr(
        environment, "DEFAULT_TOOL_PATHS", [tmp_path / "ZimmermanTools"]
    )
    environment.clear_binary_cache()
    assert environment.find_binary("PECmd.exe") == str(standalone)
    assert environment.find_all("PECmd.exe") == [str(standalone), str(bundled)]
    environment.clear_binary_cache()


def test_c_tools_is_searched_last():
    paths = [str(p) for p in environment.DEFAULT_TOOL_PATHS]
    assert paths[-1] == str(Path("C:\\Tools"))
    under = [i for i, p in enumerate(paths) if p.startswith("C:\\Tools")]
    others = [i for i, p in enumerate(paths) if not p.startswith("C:\\Tools")]
    assert min(under) > max(others)


@pytest.mark.parametrize(
    ("path", "bundled"),
    [
        ("C:\\Forensic_Program_Files\\kape\\Modules\\bin\\PECmd.exe", True),
        ("C:\\Tools\\KAPE\\modules\\BIN\\EvtxECmd\\EvtxECmd.exe", True),
        ("C:\\Tools\\KAPE\\Modules\\binaries\\PECmd.exe", False),
        ("C:\\Tools\\ZimmermanTools\\bin\\PECmd.exe", False),
    ],
)
def test_a_kape_bundled_copy_is_known_by_its_folder(path, bundled):
    assert environment._kape_bundled(path) is bundled


def test_a_relative_modules_bin_folder_is_still_kapes(tmp_path, monkeypatch):
    bundled = _exe(tmp_path / "KAPE" / "Modules" / "bin" / "PECmd.exe")
    standalone = _exe(tmp_path / "ZimmermanTools" / "PECmd.exe")
    monkeypatch.chdir(tmp_path / "KAPE")
    monkeypatch.setattr(environment.shutil, "which", lambda name: str(standalone))
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", [])
    environment.clear_binary_cache()
    try:
        found = environment.find_all("PECmd.exe", [Path("Modules/bin")])
        assert environment.find_binary("PECmd.exe", [Path("Modules/bin")]) == str(
            standalone
        )
    finally:
        environment.clear_binary_cache()
    assert found == [str(standalone), str(Path("Modules/bin/PECmd.exe"))]
    assert Path(found[1]).resolve() == bundled.resolve()


def test_net_framework_folders_rank_below_every_modern_net(
    tmp_path, monkeypatch, no_path, name_order
):
    root = tmp_path / "ZimmermanTools"
    copies = {
        n: _exe(root / n / "PECmd.exe") for n in ("net472", "net48", "net6", "net9")
    }
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", [root])
    assert environment.find_all("PECmd.exe") == [
        str(copies[n]) for n in ("net9", "net6", "net48", "net472")
    ]


def test_dot_as_the_search_folder_still_runs_net9_over_net6(
    tmp_path, monkeypatch, no_path, name_order
):
    net6 = _exe(tmp_path / "net6" / "PECmd.exe")
    net9 = _exe(tmp_path / "net9" / "PECmd.exe")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", [Path(".")])
    found = environment.find_all("PECmd.exe")
    assert [Path(p).resolve() for p in found] == [net9.resolve(), net6.resolve()]


@pytest.mark.parametrize(
    ("folder", "paths"),
    [
        ("C:\\", ["C:\\net6\\PECmd.exe", "C:\\net9\\PECmd.exe"]),
        ("/", ["/net6/PECmd.exe", "/net9/PECmd.exe"]),
        (
            "\\\\box\\tools",
            ["\\\\box\\tools\\net6\\PECmd.exe", "\\\\box\\tools\\net9\\PECmd.exe"],
        ),
    ],
)
def test_a_root_or_share_as_the_search_folder_still_ranks_net9_first(folder, paths):
    assert environment._highest_net_first(paths, Path(folder)) == paths[::-1]


def test_an_unranked_copy_between_ranked_ones_keeps_its_place():
    paths = ["/t/net6/a.exe", "/t/x/a.exe", "/t/net9/a.exe", "/t/net48/a.exe"]
    assert environment._highest_net_first(paths, Path("/t")) == [
        "/t/net9/a.exe",
        "/t/x/a.exe",
        "/t/net6/a.exe",
        "/t/net48/a.exe",
    ]


def test_the_stock_layout_runs_net9_over_net6(
    tmp_path, monkeypatch, no_path, name_order
):
    root = tmp_path / "Forensic_Program_Files"
    kape = _exe(root / "kape" / "Modules" / "bin" / "PECmd.exe")
    net6 = _exe(root / "ZimmermanTools" / "net6" / "PECmd.exe")
    net9 = _exe(root / "ZimmermanTools" / "net9" / "PECmd.exe")
    evtx6 = _exe(root / "ZimmermanTools" / "net6" / "EvtxeCmd" / "EvtxECmd.exe")
    evtx9 = _exe(root / "ZimmermanTools" / "net9" / "EvtxeCmd" / "EvtxECmd.exe")
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", [root])
    assert environment.find_binary("PECmd.exe") == str(net9)
    assert environment.find_all("PECmd.exe") == [str(net9), str(net6), str(kape)]
    assert environment.find_binary("EvtxECmd.exe") == str(evtx9)
    assert environment.find_all("EvtxECmd.exe") == [str(evtx9), str(evtx6)]


def test_net_folders_rank_by_number_not_name(
    tmp_path, monkeypatch, no_path, name_order
):
    root = tmp_path / "ZimmermanTools"
    net9 = _exe(root / "net9" / "PECmd.exe")
    net10 = _exe(root / "net10" / "PECmd.exe")
    net11 = _exe(root / "net11" / "PECmd.exe")
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", [root])
    assert environment.find_all("PECmd.exe") == [str(net11), str(net10), str(net9)]


def test_a_copy_outside_a_net_folder_keeps_its_place(
    tmp_path, monkeypatch, no_path, name_order
):
    root = tmp_path / "ZimmermanTools"
    top = _exe(root / "PECmd.exe")
    net6 = _exe(root / "net6" / "PECmd.exe")
    net9 = _exe(root / "net9" / "PECmd.exe")
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", [root])
    assert environment.find_binary("PECmd.exe") == str(top)
    assert environment.find_all("PECmd.exe") == [str(top), str(net9), str(net6)]


def test_a_net_folder_above_the_search_folder_does_not_rank(
    tmp_path, monkeypatch, no_path, name_order
):
    first = _exe(tmp_path / "net9" / "tools" / "a" / "PECmd.exe")
    later = _exe(tmp_path / "net9" / "tools" / "net10" / "PECmd.exe")
    monkeypatch.setattr(
        environment, "DEFAULT_TOOL_PATHS", [tmp_path / "net9" / "tools"]
    )
    assert environment.find_all("PECmd.exe") == [str(first), str(later)]


def test_a_configured_net6_still_runs_before_a_default_net9(
    tmp_path, monkeypatch, no_path
):
    configured = _exe(tmp_path / "configured" / "net6" / "PECmd.exe")
    default = _exe(tmp_path / "default" / "net9" / "PECmd.exe")
    monkeypatch.setattr(environment, "DEFAULT_TOOL_PATHS", [tmp_path / "default"])
    extra = [tmp_path / "configured"]
    assert environment.find_binary("PECmd.exe", extra) == str(configured)
    assert environment.find_all("PECmd.exe", extra) == [str(configured), str(default)]
