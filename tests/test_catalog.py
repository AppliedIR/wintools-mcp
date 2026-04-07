"""Tests for catalog module — denylist, allowlist, PS exceptions."""

import pytest

from wintools_mcp.catalog import (
    BLOCKED_BINARIES,
    _is_valid_ps_exception,
    clear_catalog_cache,
    get_tool_def,
    is_in_catalog,
    load_catalog,
    validate_command,
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
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            "C:\\Scripts\\Get-InjectedThreadEx.ps1",
        ]
        assert _is_valid_ps_exception(cmd) is True

    def test_ps_exception_rejects_command_flag(self, test_catalog):
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Get-Process",
        ]
        assert _is_valid_ps_exception(cmd) is False

    def test_ps_exception_rejects_encoded_command(self, test_catalog):
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            "R2V0LVByb2Nlc3M=",
        ]
        assert _is_valid_ps_exception(cmd) is False

    def test_ps_exception_requires_noprofile(self, test_catalog):
        cmd = [
            "powershell.exe",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            "C:\\Scripts\\Get-InjectedThreadEx.ps1",
        ]
        assert _is_valid_ps_exception(cmd) is False

    def test_ps_exception_requires_execution_policy(self, test_catalog):
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-File",
            "C:\\Scripts\\Get-InjectedThreadEx.ps1",
        ]
        assert _is_valid_ps_exception(cmd) is False

    def test_ps_exception_rejects_uncataloged_script(self, test_catalog):
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            "C:\\Scripts\\Evil.ps1",
        ]
        assert _is_valid_ps_exception(cmd) is False

    def test_ps_exception_requires_file_flag(self, test_catalog):
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
        ]
        assert _is_valid_ps_exception(cmd) is False

    def test_validate_command_allows_valid_ps(self, test_catalog):
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            "C:\\Scripts\\Get-InjectedThreadEx.ps1",
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


class TestSysinternalsCatalog:
    """Tests for sysinternals.yaml catalog entries."""

    @pytest.fixture(autouse=True)
    def _use_real_catalog(self, monkeypatch):
        """Use the real catalog directory for these tests."""
        clear_catalog_cache()
        monkeypatch.delenv("WINTOOLS_CATALOG_DIR", raising=False)
        yield
        clear_catalog_cache()

    def test_sysinternals_catalog_loads(self):
        catalog = load_catalog()
        sysinternals = [td for td in catalog.values() if td.category == "sysinternals"]
        assert len(sysinternals) == 5

    def test_autorunsc_in_catalog(self):
        td = get_tool_def("autorunsc")
        assert td is not None
        assert td.binary == "autorunsc.exe"
        assert td.fk_tool_name == "autoruns"
        assert td.output_format == "csv"

    def test_sigcheck_in_catalog(self):
        td = get_tool_def("sigcheck")
        assert td is not None
        assert td.binary == "sigcheck.exe"
        assert td.fk_tool_name == "sigcheck"

    def test_autorunsc_allowed(self):
        result = validate_command(["autorunsc.exe", "-a", "*", "-c", "-accepteula"])
        assert result is None

    def test_sigcheck_allowed(self):
        result = validate_command(["sigcheck.exe", "-c", "-e", "C:\\Windows\\System32"])
        assert result is None


class TestMemoryCatalog:
    """Tests for memory.yaml catalog entries."""

    @pytest.fixture(autouse=True)
    def _use_real_catalog(self, monkeypatch):
        """Use the real catalog directory for these tests."""
        clear_catalog_cache()
        monkeypatch.delenv("WINTOOLS_CATALOG_DIR", raising=False)
        yield
        clear_catalog_cache()

    def test_memory_catalog_loads(self):
        catalog = load_catalog()
        memory_tools = [td for td in catalog.values() if td.category == "memory"]
        assert len(memory_tools) == 4

    def test_winpmem_in_catalog(self):
        td = get_tool_def("winpmem")
        assert td is not None
        assert td.binary == "winpmem.exe"
        assert td.fk_tool_name == "winpmem"

    def test_moneta_in_catalog(self):
        td = get_tool_def("moneta")
        assert td is not None
        assert td.binary == "moneta64.exe"
        assert td.input_flag == "--pid"

    def test_hollows_hunter_in_catalog(self):
        td = get_tool_def("hollows_hunter")
        assert td is not None
        assert td.binary == "hollows_hunter.exe"
        assert td.input_flag == "/pid"

    def test_dumpit_in_catalog(self):
        td = get_tool_def("dumpit")
        assert td is not None
        assert td.binary == "dumpit.exe"

    def test_memory_tools_allowed(self):
        for binary in (
            "winpmem.exe",
            "dumpit.exe",
            "moneta64.exe",
            "hollows_hunter.exe",
        ):
            result = validate_command([binary, "--help"])
            assert result is None, f"{binary} should be allowed"


class TestMalformedCatalogYAML:
    """TEST-06: Malformed catalog YAML files must fail closed."""

    def _make_catalog(self, tmp_path, monkeypatch, yaml_content):
        """Create a catalog directory with a single YAML file."""
        clear_catalog_cache()
        cat_dir = tmp_path / "catalog"
        cat_dir.mkdir()
        (cat_dir / "test.yaml").write_text(yaml_content)
        monkeypatch.setenv("WINTOOLS_CATALOG_DIR", str(cat_dir))
        return cat_dir

    def test_yaml_syntax_error(self, tmp_path, monkeypatch):
        """Truncated/malformed YAML must not allow any binaries."""
        self._make_catalog(
            tmp_path,
            monkeypatch,
            "tools:\n  - name: Foo\n    binary: foo.exe\n  invalid: [",
        )
        catalog = load_catalog()
        # Malformed YAML should be skipped; catalog should be empty
        assert len(catalog) == 0
        assert not is_in_catalog("foo.exe")

    def test_empty_yaml_file(self, tmp_path, monkeypatch):
        """Empty YAML file must not allow any binaries."""
        self._make_catalog(tmp_path, monkeypatch, "")
        catalog = load_catalog()
        assert len(catalog) == 0

    def test_wrong_type_for_tools_key(self, tmp_path, monkeypatch):
        """When tools key is a string instead of a list, no tools should load."""
        self._make_catalog(tmp_path, monkeypatch, "category: test\ntools: not_a_list\n")
        catalog = load_catalog()
        assert len(catalog) == 0

    def test_missing_binary_field(self, tmp_path, monkeypatch):
        """Tool entry without a name field should be skipped."""
        yaml_content = """
category: test
tools:
  - binary: orphan.exe
    description: Missing name field
"""
        self._make_catalog(tmp_path, monkeypatch, yaml_content)
        catalog = load_catalog()
        # Entry without 'name' should be skipped
        assert len(catalog) == 0
        assert not is_in_catalog("orphan.exe")

    def test_valid_entry_still_loads_alongside_invalid(self, tmp_path, monkeypatch):
        """Valid entries should load even when invalid entries are present."""
        yaml_content = """
category: test
tools:
  - binary: no_name.exe
    description: Missing name field
  - name: GoodTool
    binary: goodtool.exe
    description: Has all required fields
"""
        self._make_catalog(tmp_path, monkeypatch, yaml_content)
        catalog = load_catalog()
        assert len(catalog) == 1
        assert is_in_catalog("goodtool.exe")
        assert not is_in_catalog("no_name.exe")
