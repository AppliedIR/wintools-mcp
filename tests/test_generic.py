"""Tests for generic run_command — catalog gating and denylist."""

import io
from unittest.mock import MagicMock, patch

import pytest

from wintools_mcp.exceptions import DenylistError, ToolNotInCatalogError
from wintools_mcp.tools.generic import _expand_script_command, run_command


@pytest.fixture
def test_catalog(tmp_path, monkeypatch):
    cat_dir = tmp_path / "catalog"
    cat_dir.mkdir()
    yaml_content = """
category: test
tools:
  - name: TestTool
    binary: testtool.exe
    description: A test tool
"""
    (cat_dir / "test.yaml").write_text(yaml_content)
    monkeypatch.setenv("WINTOOLS_CATALOG_DIR", str(cat_dir))
    return cat_dir


class TestRunCommand:
    def test_cataloged_tool_executes(self, test_catalog):
        proc = MagicMock()
        proc.stdout = io.BytesIO(b"output")
        proc.stderr = io.BytesIO(b"")
        proc.returncode = 0
        proc.wait.return_value = 0
        proc.kill = MagicMock()

        with (
            patch(
                "wintools_mcp.tools.generic.find_tool",
                return_value="/resolved/testtool.exe",
            ),
            patch("wintools_mcp.executor.subprocess.Popen", return_value=proc),
        ):
            result = run_command(["testtool.exe", "-f", "input.hve"])
        assert result["exit_code"] == 0

    def test_unresolved_binary_raises(self, test_catalog):
        """CRIT-03: When find_tool returns None, ToolNotInCatalogError is raised."""
        with patch("wintools_mcp.tools.generic.find_tool", return_value=None):
            with pytest.raises(ToolNotInCatalogError, match="not installed"):
                run_command(["testtool.exe", "-f", "input.hve"])

    def test_denylisted_binary_blocked(self, test_catalog):
        with pytest.raises(DenylistError):
            run_command(["cmd.exe", "/c", "dir"])

    def test_powershell_blocked(self, test_catalog):
        with pytest.raises(DenylistError):
            run_command(["powershell.exe", "-Command", "Get-Process"])

    def test_unknown_binary_blocked(self, test_catalog):
        with pytest.raises(ToolNotInCatalogError):
            run_command(["unknown_tool.exe", "--help"])

    def test_empty_command_raises(self, test_catalog):
        with pytest.raises(ValueError):
            run_command([])

    def test_dangerous_args_blocked(self, test_catalog):
        with patch(
            "wintools_mcp.tools.generic.find_tool",
            return_value="/resolved/testtool.exe",
        ):
            with pytest.raises(ValueError, match="Blocked"):
                run_command(["testtool.exe", "--exec", "malicious"])


class TestScriptExpansion:
    """Tests for _expand_script_command (BUG-W1)."""

    def test_non_script_tool_unchanged(self, test_catalog):
        """Non-script tools pass through unchanged."""
        result = _expand_script_command(["testtool.exe", "-f", "input"])
        assert result == ["testtool.exe", "-f", "input"]

    def test_unknown_tool_unchanged(self, test_catalog):
        """Unknown tools pass through unchanged."""
        result = _expand_script_command(["nonexistent", "--help"])
        assert result == ["nonexistent", "--help"]

    def test_script_not_in_exceptions_unchanged(self, test_catalog):
        """Script tools not in PS_SCRIPT_EXCEPTIONS pass through."""
        from wintools_mcp.catalog import ToolDefinition

        td = ToolDefinition(
            name="SomeScript",
            binary="powershell.exe",
            category="scripts",
            exec_type="script",
            install_paths=["/tmp"],
        )
        with patch("wintools_mcp.tools.generic.get_tool_def", return_value=td):
            result = _expand_script_command(["SomeScript", "--arg"])
        assert result == ["SomeScript", "--arg"]

    def test_script_found_expands(self, test_catalog, tmp_path):
        """Known script in install_paths expands to PowerShell invocation."""
        from wintools_mcp.catalog import ToolDefinition

        script = tmp_path / "Get-InjectedThreadEx.ps1"
        script.write_text("# script")
        td = ToolDefinition(
            name="Get-InjectedThreadEx",
            binary="powershell.exe",
            category="scripts",
            exec_type="script",
            install_paths=[str(tmp_path)],
        )
        with patch("wintools_mcp.tools.generic.get_tool_def", return_value=td):
            result = _expand_script_command(["Get-InjectedThreadEx", "--verbose"])
        assert result[0] == "powershell.exe"
        assert "-NoProfile" in result
        assert "-File" in result
        assert str(script) in result
        assert "--verbose" in result

    def test_script_not_found_raises(self, test_catalog, tmp_path):
        """Missing script raises ToolNotInCatalogError with searched paths."""
        from wintools_mcp.catalog import InstallMethod, ToolDefinition

        td = ToolDefinition(
            name="Get-InjectedThreadEx",
            binary="powershell.exe",
            category="scripts",
            exec_type="script",
            install_paths=[str(tmp_path / "nonexistent")],
            install_methods=[InstallMethod(method="github", url="https://example.com")],
        )
        with patch("wintools_mcp.tools.generic.get_tool_def", return_value=td):
            with pytest.raises(ToolNotInCatalogError, match="Script not found"):
                _expand_script_command(["Get-InjectedThreadEx"])

    def test_path_traversal_blocked(self, test_catalog, tmp_path):
        """Path traversal in command name is stripped to filename only."""
        from wintools_mcp.catalog import ToolDefinition

        td = ToolDefinition(
            name="../../etc/Get-InjectedThreadEx",
            binary="powershell.exe",
            category="scripts",
            exec_type="script",
            install_paths=[str(tmp_path)],
        )
        with patch("wintools_mcp.tools.generic.get_tool_def", return_value=td):
            # Should not find the script (traversal stripped, file doesn't exist)
            with pytest.raises(ToolNotInCatalogError, match="Script not found"):
                _expand_script_command(["../../etc/Get-InjectedThreadEx"])
