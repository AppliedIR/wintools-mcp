"""Tests for security module — input sanitization and path validation."""

import pytest

from wintools_mcp.security import (
    sanitize_extra_args,
    validate_input_path,
)


class TestSanitizeExtraArgs:
    def test_clean_args_pass(self):
        result = sanitize_extra_args(["--verbose", "input/", "-q"])
        assert result == ["--verbose", "input/", "-q"]

    def test_empty_args(self):
        assert sanitize_extra_args([]) == []
        assert sanitize_extra_args(None) == []

    def test_dangerous_flag_blocked(self):
        with pytest.raises(ValueError, match="Blocked dangerous flag"):
            sanitize_extra_args(["--exec", "malicious"])

    def test_encoded_command_blocked(self):
        with pytest.raises(ValueError, match="Blocked dangerous flag"):
            sanitize_extra_args(["-enc", "base64payload"])

    def test_e_flag_blocked_for_powershell(self):
        """The -e flag is dangerous for PowerShell but not for other tools."""
        with pytest.raises(ValueError, match="Blocked dangerous flag"):
            sanitize_extra_args(["-e", "payload"], tool_name="powershell.exe")

    def test_e_flag_allowed_for_sigcheck(self):
        """Sigcheck uses -e to mean 'scan executables only' — must not be blocked."""
        result = sanitize_extra_args(["-e", "C:\\Windows"], tool_name="sigcheck.exe")
        assert result == ["-e", "C:\\Windows"]

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

    def test_output_flags_allowed(self):
        """Output flags are NOT blocked — they are legitimate forensic tool flags.

        Blocking --csv/--json/--output/-o broke Zimmerman tools, Hayabusa, and
        winpmem. sift-mcp validates output paths instead of blocking these flags.
        """
        for flag in (
            "-o",
            "--output",
            "-O",
            "--output-file",
            "/out",
            "--csv",
            "--json",
        ):
            result = sanitize_extra_args([flag, "outfile.txt"])
            assert result == [flag, "outfile.txt"]

    def test_response_file_blocked(self):
        """Backlog #11: @file response-file syntax blocked."""
        with pytest.raises(ValueError, match="metacharacter"):
            sanitize_extra_args(["@args.txt"])

    def test_tool_specific_blocked_flags(self):
        """Per-tool blocked flags are enforced."""
        with pytest.raises(ValueError, match="Blocked dangerous flag"):
            sanitize_extra_args(["-command", "evil"], tool_name="powershell.exe")

    def test_non_string_arg_rejected(self):
        with pytest.raises(ValueError, match="Non-string"):
            sanitize_extra_args([123])


class TestValidateInputPath:
    """Input path validation — blocks ~/.aiir, allows system dirs for forensics."""

    def test_system32_allowed(self, tmp_path):
        """System32 paths must be allowed — primary forensic use case."""
        from pathlib import Path
        from unittest.mock import patch

        fake_resolved = Path(r"C:\Windows\System32\svchost.exe")
        with patch("wintools_mcp.security.Path.resolve", return_value=fake_resolved):
            result = validate_input_path(r"C:\Windows\System32\svchost.exe")
            assert "svchost.exe" in result

    def test_syswow64_allowed(self, tmp_path):
        """SysWOW64 paths must be allowed for forensic tool analysis."""
        from pathlib import Path
        from unittest.mock import patch

        fake_resolved = Path(r"C:\Windows\SysWOW64\cmd.exe")
        with patch("wintools_mcp.security.Path.resolve", return_value=fake_resolved):
            result = validate_input_path(r"C:\Windows\SysWOW64\cmd.exe")
            assert "cmd.exe" in result

    def test_blocked_aiir_config(self, tmp_path):
        """Paths inside ~/.aiir should be blocked (tokens, credentials)."""
        from pathlib import Path
        from unittest.mock import patch

        aiir_dir = Path.home() / ".aiir"
        fake_resolved = aiir_dir / "config.yaml"
        with patch("wintools_mcp.security.Path.resolve", return_value=fake_resolved):
            with pytest.raises(ValueError, match="blocked"):
                validate_input_path(str(fake_resolved))

    def test_blocked_aiir_subdir(self, tmp_path):
        """Subdirectories of ~/.aiir should also be blocked."""
        from pathlib import Path
        from unittest.mock import patch

        aiir_dir = Path.home() / ".aiir"
        fake_resolved = aiir_dir / "tls" / "wintools-key.pem"
        with patch("wintools_mcp.security.Path.resolve", return_value=fake_resolved):
            with pytest.raises(ValueError, match="blocked"):
                validate_input_path(str(fake_resolved))

    def test_allowed_path(self, tmp_path):
        """Normal evidence paths should pass validation."""
        evidence = tmp_path / "evidence.evtx"
        evidence.touch()
        result = validate_input_path(str(evidence))
        assert result == str(evidence.resolve())
