"""Shared fixtures for wintools-mcp tests."""

import pytest

from wintools_mcp.catalog import clear_catalog_cache
from wintools_mcp.config import reset_config
from wintools_mcp.response import reset_call_counter


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset caches before and after each test."""
    clear_catalog_cache()
    reset_config()
    reset_call_counter()
    yield
    clear_catalog_cache()
    reset_config()
    reset_call_counter()


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
    monkeypatch.setenv("AIIR_CASE_DIR", str(cd))
    return cd


@pytest.fixture
def examiner(monkeypatch):
    """Set examiner identity."""
    monkeypatch.setenv("AIIR_EXAMINER", "testuser")
    return "testuser"
