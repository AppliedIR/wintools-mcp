"""Tests for executor module."""

import pytest
from unittest.mock import patch, MagicMock
from wintools_mcp.executor import execute, _truncate
from wintools_mcp.exceptions import ExecutionError, TimeoutError


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
        assert "line1\nline2\n" == result["stdout"]

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
