"""Tests for security module — input sanitization."""

import pytest
from wintools_mcp.security import sanitize_extra_args


class TestSanitizeExtraArgs:

    def test_clean_args_pass(self):
        result = sanitize_extra_args(["--csv", "output/", "-q"])
        assert result == ["--csv", "output/", "-q"]

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
            sanitize_extra_args(["--output", "file; rm -rf /"])

    def test_pipe_blocked(self):
        with pytest.raises(ValueError, match="metacharacter"):
            sanitize_extra_args(["--flag", "value && evil"])

    def test_command_substitution_blocked(self):
        with pytest.raises(ValueError, match="metacharacter"):
            sanitize_extra_args(["$(whoami)"])

    def test_backtick_blocked(self):
        with pytest.raises(ValueError, match="metacharacter"):
            sanitize_extra_args(["`whoami`"])
