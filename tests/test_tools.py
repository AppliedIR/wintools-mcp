"""Tests for tool catalog and execution pipeline.

The per-tool wrappers (zimmerman.py, timeline.py) were consolidated into
generic.run_command() in FU-3.  These tests validate the catalog-driven
execution path.
"""

import pytest


@pytest.fixture
def tool_catalog(tmp_path, monkeypatch):
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

    monkeypatch.setenv("WINTOOLS_CATALOG_DIR", str(cat_dir))
    monkeypatch.setenv("AIIR_EXAMINER", "testuser")
    return cat_dir


class TestToolCatalog:
    def test_catalog_loads(self, tool_catalog):
        from wintools_mcp.catalog import load_catalog

        catalog = load_catalog()
        assert "amcacheparser" in catalog
        assert "pecmd" in catalog

    def test_uncataloged_tool_rejected(self, tool_catalog):
        from wintools_mcp.security import verify_catalog

        with pytest.raises(ValueError, match="not in the approved catalog"):
            verify_catalog("evil.exe")
