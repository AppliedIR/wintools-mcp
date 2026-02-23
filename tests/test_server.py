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

    def test_no_per_tool_wrappers(self, test_catalog):
        """Per-tool wrappers removed in FU-3 consolidation."""
        config = WintoolsConfig()
        server = create_server(config)
        tool_names = [t.name for t in server._tool_manager._tools.values()]
        assert "run_amcacheparser" not in tool_names
        assert "run_hayabusa" not in tool_names
        assert "run_mactime" not in tool_names

    def test_total_tool_count(self, test_catalog):
        """7 core tools: 6 discovery + 1 generic."""
        config = WintoolsConfig()
        server = create_server(config)
        tool_names = [t.name for t in server._tool_manager._tools.values()]
        assert len(tool_names) == 7

    def test_server_has_instructions(self, test_catalog):
        """Verify forensic discipline instructions are set."""
        config = WintoolsConfig()
        server = create_server(config)
        instructions = getattr(server, "instructions", None) or getattr(
            getattr(server, "_mcp_server", None), "instructions", None
        )
        assert instructions is not None
        assert "EVIDENCE IS SOVEREIGN" in instructions
