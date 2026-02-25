"""Tests for Zimmerman and timeline tool wrappers."""

from unittest.mock import MagicMock, patch

import pytest

from wintools_mcp.audit import AuditWriter


@pytest.fixture
def zimmerman_catalog(tmp_path, monkeypatch):
    cat_dir = tmp_path / "catalog"
    cat_dir.mkdir()
    yaml_content = """
category: zimmerman
tools:
  - name: AmcacheParser
    binary: AmcacheParser.exe
    description: "Parse Amcache.hve"
    input_flag: "-f"
    output_format: csv
    fk_tool_name: AmcacheParser
    install_methods:
      - method: dotnet
        command: "dotnet tool install --global AmcacheParser"
  - name: PECmd
    binary: PECmd.exe
    description: "Parse Prefetch files"
    input_flag: "-f"
    output_format: csv
    fk_tool_name: PECmd
"""
    (cat_dir / "zimmerman.yaml").write_text(yaml_content)

    timeline_yaml = """
category: timeline
tools:
  - name: hayabusa
    binary: hayabusa.exe
    description: "Sigma-based event log analysis"
    input_flag: "-d"
    output_format: json
    timeout_seconds: 1800
    fk_tool_name: Hayabusa
  - name: mactime
    binary: mactime.pl
    description: "Generate timeline from bodyfile"
    input_flag: "-b"
    output_format: text
"""
    (cat_dir / "timeline.yaml").write_text(timeline_yaml)

    monkeypatch.setenv("WINTOOLS_CATALOG_DIR", str(cat_dir))
    monkeypatch.setenv("AIIR_EXAMINER", "testuser")
    return cat_dir


class TestZimmermanTools:
    def test_register_tools(self, zimmerman_catalog):
        from wintools_mcp.tools.zimmerman import register_zimmerman_tools

        tools = {}
        server = MagicMock()
        server.tool.return_value = lambda f: tools.update({f.__name__: f}) or f

        audit = AuditWriter()
        register_zimmerman_tools(server, audit)

        assert "run_amcacheparser" in tools
        assert "run_pecmd" in tools

    def test_amcacheparser_execution(self, zimmerman_catalog, tmp_path, monkeypatch):
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path / "case"))

        from wintools_mcp.tools.zimmerman import _run_zimmerman_tool

        # Create mock CSV output
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_result = {
            "exit_code": 0,
            "stdout": "AmcacheParser v1.5\nProcessing...\n",
            "stderr": "",
            "elapsed_seconds": 1.0,
            "command": [
                "AmcacheParser.exe",
                "-f",
                "Amcache.hve",
                "--csv",
                str(output_dir),
            ],
        }

        csv_content = "SHA1,FullPath,FileSize\nabc123,C:\\Windows\\notepad.exe,123456\n"
        (output_dir / "Amcache_UnassociatedFileEntries.csv").write_text(csv_content)

        audit = AuditWriter()

        with (
            patch(
                "wintools_mcp.tools.zimmerman.find_binary",
                return_value="C:\\Tools\\AmcacheParser.exe",
            ),
            patch("wintools_mcp.tools.zimmerman.execute", return_value=mock_result),
        ):
            result = _run_zimmerman_tool(
                "AmcacheParser",
                "Amcache.hve",
                audit,
                output_dir=str(output_dir),
            )

        assert result["success"] is True
        assert result["examiner"] == "testuser"
        assert result["evidence_id"].startswith("wintools-testuser-")
        assert "Amcache_UnassociatedFileEntries" in result["data"]

    def test_tool_not_found_includes_guidance(self, zimmerman_catalog):
        from wintools_mcp.exceptions import ToolNotFoundError
        from wintools_mcp.tools.zimmerman import _run_zimmerman_tool

        audit = AuditWriter()

        with patch("wintools_mcp.tools.zimmerman.find_binary", return_value=None):
            with pytest.raises(ToolNotFoundError, match="Install guidance"):
                _run_zimmerman_tool("AmcacheParser", "test.hve", audit)


class TestTimelineTools:
    def test_register_tools(self, zimmerman_catalog):
        from wintools_mcp.tools.timeline import register_timeline_tools

        tools = {}
        server = MagicMock()
        server.tool.return_value = lambda f: tools.update({f.__name__: f}) or f

        audit = AuditWriter()
        register_timeline_tools(server, audit)

        assert "run_hayabusa" in tools
        assert "run_mactime" in tools

    def test_hayabusa_not_found(self, zimmerman_catalog):
        from wintools_mcp.exceptions import ToolNotFoundError
        from wintools_mcp.tools.timeline import register_timeline_tools

        tools = {}
        server = MagicMock()
        server.tool.return_value = lambda f: tools.update({f.__name__: f}) or f

        audit = AuditWriter()
        register_timeline_tools(server, audit)

        with patch("wintools_mcp.tools.timeline.find_binary", return_value=None):
            with pytest.raises(ToolNotFoundError):
                tools["run_hayabusa"]("C:\\evtx")

    def test_mactime_execution(self, zimmerman_catalog, monkeypatch, tmp_path):
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path / "case"))

        from wintools_mcp.tools.timeline import register_timeline_tools

        tools = {}
        server = MagicMock()
        server.tool.return_value = lambda f: tools.update({f.__name__: f}) or f

        audit = AuditWriter()
        register_timeline_tools(server, audit)

        mock_result = {
            "exit_code": 0,
            "stdout": "Mon Jan 01 2026 00:00:00,1024,...,C:/Windows/System32/test.dll\n",
            "stderr": "",
            "elapsed_seconds": 0.5,
            "command": ["mactime.pl", "-b", "body.txt"],
        }

        with (
            patch(
                "wintools_mcp.tools.timeline.find_binary",
                return_value="/usr/bin/mactime.pl",
            ),
            patch("wintools_mcp.tools.timeline.execute", return_value=mock_result),
        ):
            result = tools["run_mactime"]("body.txt")

        assert result["success"] is True
        assert result["evidence_id"].startswith("wintools-testuser-")
