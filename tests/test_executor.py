"""Tests for executor module."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from wintools_mcp.exceptions import ExecutionError
from wintools_mcp.executor import _truncate, _validate_output_dir, execute


class TestExecutor:
    def test_successful_execution(self, monkeypatch):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "output line 1\noutput line 2\n"
        mock_result.stderr = ""

        with patch("wintools_mcp.executor.subprocess.run", return_value=mock_result):
            result = execute(["echo", "hello"])

        assert result["exit_code"] == 0
        assert "output line 1" in result["stdout"]
        assert result["elapsed_seconds"] >= 0

    def test_failed_execution(self, monkeypatch):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "error message"

        with patch("wintools_mcp.executor.subprocess.run", return_value=mock_result):
            result = execute(["false"])

        assert result["exit_code"] == 1
        assert "error message" in result["stderr"]

    def test_binary_not_found(self):
        with pytest.raises(ExecutionError, match="Binary not found"):
            execute(["nonexistent_binary_xyz123"])

    def test_crlf_normalization(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "line1\r\nline2\r\n"
        mock_result.stderr = "err\r\n"

        with patch("wintools_mcp.executor.subprocess.run", return_value=mock_result):
            result = execute(["test"])

        assert "\r\n" not in result["stdout"]
        assert "\r\n" not in result["stderr"]
        assert result["stdout"] == "line1\nline2\n"

    def test_truncation(self):
        long_text = "x" * 100_000
        truncated = _truncate(long_text, 50_000)
        assert len(truncated) < 100_000
        assert "truncated" in truncated

    def test_no_truncation_for_short_text(self):
        short_text = "hello"
        assert _truncate(short_text, 50_000) == "hello"

    def test_save_output(self, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "saved output"
        mock_result.stderr = ""

        save_dir = str(tmp_path / "output")
        with patch("wintools_mcp.executor.subprocess.run", return_value=mock_result):
            result = execute(["test"], save_output=True, save_dir=save_dir)

        assert "output_file" in result
        assert "output_sha256" in result

    def test_save_output_blocked_dir(self, tmp_path):
        """S-H4: saving output to a blocked Windows system directory raises ValueError."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "output"
        mock_result.stderr = ""

        # On Linux, C:\Windows resolves to a POSIX path. Patch Path.resolve
        # to return a Windows-style path so we can test the blocking logic.
        fake_resolved = Path(r"C:\Windows\Temp\evil")
        with (
            patch("wintools_mcp.executor.subprocess.run", return_value=mock_result),
            patch("wintools_mcp.executor.Path.resolve", return_value=fake_resolved),
        ):
            with pytest.raises(ValueError, match="Output directory blocked"):
                execute(
                    ["test"],
                    save_output=True,
                    save_dir=r"C:\Windows\Temp\evil",
                )

    def test_save_output_safe_dir(self, tmp_path):
        """S-H4: saving to a non-blocked directory succeeds."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "safe output"
        mock_result.stderr = ""

        save_dir = str(tmp_path / "safe_output")
        with patch("wintools_mcp.executor.subprocess.run", return_value=mock_result):
            result = execute(["test"], save_output=True, save_dir=save_dir)

        assert "output_file" in result

    def test_save_output_returns_extractions(self, tmp_path):
        """Saved output files should appear in extractions list."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "extraction data"
        mock_result.stderr = "some warnings"

        save_dir = str(tmp_path / "extractions")
        with patch("wintools_mcp.executor.subprocess.run", return_value=mock_result):
            result = execute(["EvtxECmd.exe"], save_output=True, save_dir=save_dir)

        assert "extractions" in result
        assert len(result["extractions"]) == 2  # stdout + stderr
        # Paths should be normalized (forward slashes)
        for path in result["extractions"]:
            assert "\\" not in path or "/" in path

    def test_save_output_extractions_share_relative(self, tmp_path, monkeypatch):
        """When AIIR_SHARE_ROOT is set, extractions use share-relative paths."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "data"
        mock_result.stderr = ""

        save_dir = str(tmp_path / "extractions")
        monkeypatch.setenv("AIIR_SHARE_ROOT", str(tmp_path))

        with patch("wintools_mcp.executor.subprocess.run", return_value=mock_result):
            result = execute(["EvtxECmd.exe"], save_output=True, save_dir=save_dir)

        assert "extractions" in result
        assert len(result["extractions"]) == 1
        # Should be relative to share root (starts with "extractions/")
        assert result["extractions"][0].startswith("extractions/")
        assert str(tmp_path) not in result["extractions"][0]

    def test_save_output_extractions_no_share_root(self, tmp_path, monkeypatch):
        """Without AIIR_SHARE_ROOT, extractions contain full paths."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "data"
        mock_result.stderr = ""

        save_dir = str(tmp_path / "extractions")
        monkeypatch.delenv("AIIR_SHARE_ROOT", raising=False)

        with patch("wintools_mcp.executor.subprocess.run", return_value=mock_result):
            result = execute(["EvtxECmd.exe"], save_output=True, save_dir=save_dir)

        assert "extractions" in result
        # Should contain the full path (normalized to forward slashes)
        assert "extractions" in result["extractions"][0]

    def test_no_extractions_without_save_output(self):
        """No extractions key when save_output is False."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "output"
        mock_result.stderr = ""

        with patch("wintools_mcp.executor.subprocess.run", return_value=mock_result):
            result = execute(["test"])

        assert "extractions" not in result


class TestValidateOutputDir:
    """S-H4: unit tests for _validate_output_dir.

    _validate_output_dir receives an already-resolved Path. On Linux, we pass
    PurePosixPath-style strings that mimic Windows resolved paths so the
    case-insensitive string comparison logic is exercised correctly.
    """

    def _win_path(self, p: str) -> Path:
        """Create a Path from a Windows-style string without resolving it.

        On Linux, Path(r"C:\\Windows") becomes a valid PosixPath with literal
        backslashes in the name. The validation function converts to str and
        replaces forward slashes with os.sep, then lowercases. To test
        correctly on Linux we pass a Path whose str() matches the blocked
        prefix pattern after the normalize step.
        """
        return Path(p)

    def test_blocked_windows_dir(self):
        with pytest.raises(ValueError, match="Output directory blocked"):
            _validate_output_dir(self._win_path(r"C:\Windows\System32"))

    def test_blocked_program_files(self):
        with pytest.raises(ValueError, match="Output directory blocked"):
            _validate_output_dir(self._win_path(r"C:\Program Files\MyApp"))

    def test_blocked_program_files_x86(self):
        with pytest.raises(ValueError, match="Output directory blocked"):
            _validate_output_dir(self._win_path(r"C:\Program Files (x86)\MyApp"))

    def test_blocked_programdata(self):
        with pytest.raises(ValueError, match="Output directory blocked"):
            _validate_output_dir(self._win_path(r"C:\ProgramData\secrets"))

    def test_blocked_exact_match(self):
        with pytest.raises(ValueError, match="Output directory blocked"):
            _validate_output_dir(self._win_path(r"C:\Windows"))

    def test_case_insensitive(self):
        """Windows paths are case-insensitive; c:\\windows should also be blocked."""
        with pytest.raises(ValueError, match="Output directory blocked"):
            _validate_output_dir(self._win_path(r"c:\windows\temp"))

    def test_allowed_path(self, tmp_path):
        """Normal temp paths should pass validation."""
        _validate_output_dir(tmp_path / "output")

    def test_allowed_c_drive_root(self):
        """C:\\ itself is allowed — only specific subdirectories are blocked."""
        _validate_output_dir(self._win_path(r"C:\Cases\output"))

    def test_partial_name_not_blocked(self):
        """C:\\WindowsUpdate should NOT match C:\\Windows."""
        _validate_output_dir(self._win_path(r"C:\WindowsUpdate\output"))
