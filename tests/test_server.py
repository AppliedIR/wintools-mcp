"""Tests for MCP server — tool registration and basic operation."""

import pytest
from unittest.mock import patch, MagicMock

from wintools_mcp.config import WintoolsConfig
from wintools_mcp.server import create_server


@pytest.fixture
def test_catalog(tmp_path, monkeypatch):
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
  - name: mactime
    binary: mactime.pl
    description: "Generate timeline"
    input_flag: "-b"
"""
    (cat_dir / "timeline.yaml").write_text(timeline_yaml)

    monkeypatch.setenv("WINTOOLS_CATALOG_DIR", str(cat_dir))
    monkeypatch.setenv("AIIR_EXAMINER", "testuser")
    return cat_dir


class TestCreateServer:

    def test_server_creates(self, test_catalog):
        config = WintoolsConfig()
        server = create_server(config)
        assert server is not None
        assert server.name == "wintools-mcp"

    def test_server_has_discovery_tools(self, test_catalog):
        config = WintoolsConfig()
        server = create_server(config)
        tool_names = [t.name for t in server._tool_manager._tools.values()]
        assert "scan_tools" in tool_names
        assert "list_available_tools" in tool_names
        assert "list_missing_tools" in tool_names
        assert "check_tools" in tool_names
        assert "get_tool_help" in tool_names
        assert "suggest_tools" in tool_names

    def test_server_has_generic_run(self, test_catalog):
        config = WintoolsConfig()
        server = create_server(config)
        tool_names = [t.name for t in server._tool_manager._tools.values()]
        assert "run_command" in tool_names

    def test_server_has_zimmerman_tools(self, test_catalog):
        config = WintoolsConfig()
        server = create_server(config)
        tool_names = [t.name for t in server._tool_manager._tools.values()]
        assert "run_amcacheparser" in tool_names

    def test_server_has_timeline_tools(self, test_catalog):
        config = WintoolsConfig()
        server = create_server(config)
        tool_names = [t.name for t in server._tool_manager._tools.values()]
        assert "run_hayabusa" in tool_names
        assert "run_mactime" in tool_names

    def test_total_tool_count(self, test_catalog):
        """Phase 1: 7 discovery/generic + 1 zimmerman + 2 timeline = 10 (with test catalog)."""
        config = WintoolsConfig()
        server = create_server(config)
        tool_names = [t.name for t in server._tool_manager._tools.values()]
        # Discovery: scan_tools, list_available_tools, list_missing_tools,
        #            check_tools, get_tool_help, suggest_tools
        # Generic: run_command
        # Zimmerman: run_amcacheparser (1 in test catalog)
        # Timeline: run_hayabusa, run_mactime
        assert len(tool_names) >= 10
