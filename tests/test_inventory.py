"""Tests for inventory and discovery modules."""

from unittest.mock import patch

import pytest

from wintools_mcp.inventory import get_install_guidance, print_scan_report, scan_tools


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
    install_methods:
      - method: dotnet
        command: "dotnet tool install --global AmcacheParser"
      - method: direct
        url: "https://ericzimmerman.github.io"
    alternatives:
      - "amcache.py (Volatility plugin)"

  - name: PECmd
    binary: PECmd.exe
    description: "Parse Prefetch files"
    input_flag: "-f"
    output_format: csv
"""
    (cat_dir / "test.yaml").write_text(yaml_content)
    monkeypatch.setenv("WINTOOLS_CATALOG_DIR", str(cat_dir))
    return cat_dir


class TestScanTools:
    def test_all_missing(self, test_catalog):
        with patch("wintools_mcp.inventory.find_binary", return_value=None):
            result = scan_tools()
        assert result["summary"]["total"] == 2
        assert result["summary"]["available"] == 0
        assert result["summary"]["missing"] == 2
        assert len(result["missing_tools"]) == 2

    def test_one_available(self, test_catalog):
        def mock_find(name, extra_paths=None):
            if name == "AmcacheParser.exe":
                return "C:\\Tools\\AmcacheParser.exe"
            return None

        with patch("wintools_mcp.inventory.find_binary", side_effect=mock_find):
            result = scan_tools()
        assert result["summary"]["available"] == 1
        assert result["summary"]["missing"] == 1
        assert result["available_tools"][0]["name"] == "AmcacheParser"

    def test_missing_includes_install_methods(self, test_catalog):
        with patch("wintools_mcp.inventory.find_binary", return_value=None):
            result = scan_tools()
        amcache = next(
            t for t in result["missing_tools"] if t["name"] == "AmcacheParser"
        )
        assert len(amcache["install_methods"]) == 2
        assert amcache["install_methods"][0]["method"] == "dotnet"

    def test_missing_includes_alternatives(self, test_catalog):
        with patch("wintools_mcp.inventory.find_binary", return_value=None):
            result = scan_tools()
        amcache = next(
            t for t in result["missing_tools"] if t["name"] == "AmcacheParser"
        )
        assert "alternatives" in amcache

    def test_by_category(self, test_catalog):
        with patch("wintools_mcp.inventory.find_binary", return_value=None):
            result = scan_tools()
        assert "zimmerman" in result["by_category"]
        assert result["by_category"]["zimmerman"]["total"] == 2


class TestInstallGuidance:
    def test_known_tool(self, test_catalog):
        with patch("wintools_mcp.inventory.find_binary", return_value=None):
            result = get_install_guidance("AmcacheParser")
        assert result["name"] == "AmcacheParser"
        assert result["installed"] is False
        assert len(result["install_methods"]) == 2

    def test_installed_tool(self, test_catalog):
        with patch(
            "wintools_mcp.inventory.find_binary",
            return_value="C:\\Tools\\AmcacheParser.exe",
        ):
            result = get_install_guidance("AmcacheParser")
        assert result["installed"] is True
        assert result["path"] == "C:\\Tools\\AmcacheParser.exe"

    def test_unknown_tool(self, test_catalog):
        result = get_install_guidance("NonexistentTool")
        assert "error" in result


class TestScanReport:
    def test_report_format(self, test_catalog):
        with patch("wintools_mcp.inventory.find_binary", return_value=None):
            report = print_scan_report()
        assert "wintools-mcp Tool Inventory" in report
        assert "MISSING" in report
        assert "0/2 tools available" in report

    def test_report_shows_available(self, test_catalog):
        def mock_find(name, extra_paths=None):
            if name == "AmcacheParser.exe":
                return "C:\\Tools\\AmcacheParser.exe"
            return None

        with patch("wintools_mcp.inventory.find_binary", side_effect=mock_find):
            report = print_scan_report()
        assert "[OK]" in report
        assert "[MISSING]" in report
        assert "1/2 tools available" in report
