"""Shared fixtures for wintools-mcp tests."""

import pytest

from wintools_mcp import versions
from wintools_mcp.catalog import clear_catalog_cache
from wintools_mcp.config import reset_config
from wintools_mcp.response import reset_call_counter


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    """Reset caches before and after each test. No test runs a tool to read
    its version: a probe here fails as an unrunnable one does (its own rows
    replace versions.run_probe)."""

    def not_run(argv):
        raise OSError("version probes are not run in tests")

    monkeypatch.setattr(versions, "run_probe", not_run)
    clear_catalog_cache()
    reset_config()
    reset_call_counter()
    versions.clear()
    yield
    clear_catalog_cache()
    reset_config()
    reset_call_counter()
    versions.clear()


@pytest.fixture
def catalog_dir(tmp_path):
    """Create a temporary catalog directory with test YAML files."""
    cat_dir = tmp_path / "catalog"
    cat_dir.mkdir()
    return cat_dir


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Set up a temporary case directory with CASE.yaml."""
    cd = tmp_path / "case"
    cd.mkdir()
    (cd / "CASE.yaml").write_text("case_id: test\n")
    monkeypatch.setenv("VHIR_CASE_DIR", str(cd))
    return cd


@pytest.fixture
def examiner(monkeypatch):
    """Set examiner identity."""
    monkeypatch.setenv("VHIR_EXAMINER", "testuser")
    return "testuser"
