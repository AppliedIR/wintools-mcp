"""Which copy of a tool runs when a box has several.

The configured folders come first, then PATH, then the default folders with
C:\\Tools last. A copy KAPE bundles in its Modules\\bin runs only when there is
no other; every copy is still listed.
"""

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
    assert bool(environment._KAPE_BIN.search(path)) is bundled
