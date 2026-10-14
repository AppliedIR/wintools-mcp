"""Tests for generic run_command — catalog gating and denylist."""

import io
from unittest.mock import MagicMock, patch

import pytest

from wintools_mcp.exceptions import DenylistError, ToolNotInCatalogError
from wintools_mcp.tools.generic import run_command


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
