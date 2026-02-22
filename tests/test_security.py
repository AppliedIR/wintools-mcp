"""Tests for security module — input sanitization and path validation."""

import pytest
from wintools_mcp.security import (
    sanitize_extra_args,
    validate_input_path,
    _DANGEROUS_FLAGS,
    _TOOL_BLOCKED_FLAGS,
)


class TestSanitizeExtraArgs:

    def test_clean_args_pass(self):
        result = sanitize_extra_args(["--csv", "input/", "-q"])
        assert result == ["--csv", "input/", "-q"]

    def test_empty_args(self):
        assert sanitize_extra_args([]) == []
        assert sanitize_extra_args(None) == []

    def test_dangerous_flag_blocked(self):
        with pytest.raises(ValueError, match="Blocked dangerous flag"):
            sanitize_extra_args(["-e", "malicious"])

    def test_encoded_command_blocked(self):
        with pytest.raises(ValueError, match="Blocked dangerous flag"):
            sanitize_extra_args(["-enc", "base64payload"])

    def test_shell_metachar_blocked(self):
        with pytest.raises(ValueError, match="metacharacter"):
            sanitize_extra_args(["--flag", "file; rm -rf /"])

    def test_pipe_blocked(self):
        with pytest.raises(ValueError, match="metacharacter"):
            sanitize_extra_args(["--flag", "value && evil"])

    def test_command_substitution_blocked(self):
        with pytest.raises(ValueError, match="metacharacter"):
            sanitize_extra_args(["$(whoami)"])

    def test_backtick_blocked(self):
        with pytest.raises(ValueError, match="metacharacter"):
            sanitize_extra_args(["`whoami`"])

    def test_output_flags_blocked(self):
        """MED-06: output redirect flags are blocked."""
        for flag in ("-o", "--output", "-O", "--output-file"):
            with pytest.raises(ValueError, match="Blocked dangerous flag"):
                sanitize_extra_args([flag, "outfile.txt"])

    def test_tool_specific_blocked_flags(self):
        """Per-tool blocked flags are enforced."""
        with pytest.raises(ValueError, match="Blocked dangerous flag"):
            sanitize_extra_args(["-command", "evil"], tool_name="powershell")

    def test_non_string_arg_rejected(self):
        with pytest.raises(ValueError, match="Non-string"):
            sanitize_extra_args([123])


class TestValidateInputPath:
    """HIGH-11: Windows-appropriate input path validation."""

    def test_blocked_system32(self, tmp_path):
        """Paths inside System32 should be blocked."""
        from unittest.mock import patch
        from pathlib import Path
        fake_resolved = Path(r"C:\Windows\System32\config\SAM")
        with patch("wintools_mcp.security.Path.resolve", return_value=fake_resolved):
            with pytest.raises(ValueError, match="blocked system directory"):
                validate_input_path(r"C:\Windows\System32\config\SAM")

    def test_blocked_syswow64(self, tmp_path):
        """Paths inside SysWOW64 should be blocked."""
        from unittest.mock import patch
        from pathlib import Path
        fake_resolved = Path(r"C:\Windows\SysWOW64\evil.dll")
        with patch("wintools_mcp.security.Path.resolve", return_value=fake_resolved):
            with pytest.raises(ValueError, match="blocked system directory"):
                validate_input_path(r"C:\Windows\SysWOW64\evil.dll")

    def test_allowed_path(self, tmp_path):
        """Normal evidence paths should pass validation."""
        evidence = tmp_path / "evidence.evtx"
        evidence.touch()
        result = validate_input_path(str(evidence))
        assert result == str(evidence.resolve())
