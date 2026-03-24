"""Adversarial security tests — wintools-mcp edge cases.

Tests designed to probe attack surfaces in wintools-mcp.
Split from the original combined adversarial test file.
Sift-mcp/sift-gateway tests are in sift-mcp/tests/test_adversarial_security.py.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

# ============================================================
# Section 1: String length validation
# ============================================================


class TestWintoolsStringValidation:
    """Validate _validate_str_length catches all adversarial inputs."""

    @pytest.fixture
    def validate(self):
        from wintools_mcp.server import _validate_str_length

        return _validate_str_length

    def test_accepts_normal_string(self, validate):
        validate("hello", "test", 100)

    def test_accepts_none(self, validate):
        """None values should pass (optional parameters)."""
        validate(None, "test", 100)

    def test_rejects_over_limit(self, validate):
        with pytest.raises(ValueError, match="exceeds maximum"):
            validate("A" * 101, "test", 100)

    def test_rejects_exact_boundary(self, validate):
        """At boundary should pass, one over should fail."""
        validate("A" * 100, "test", 100)  # exact limit OK
        with pytest.raises(ValueError, match="exceeds maximum"):
            validate("A" * 101, "test", 100)

    def test_rejects_null_bytes(self, validate):
        with pytest.raises(ValueError, match="null byte"):
            validate("hello\x00world", "test", 100)

    def test_rejects_leading_null(self, validate):
        with pytest.raises(ValueError, match="null byte"):
            validate("\x00", "test", 100)

    def test_unicode_length_counted_by_chars(self, validate):
        """Length is Python str length (chars), not bytes. Ensure consistent."""
        # 100 emoji chars = 100 len() but 400 bytes in UTF-8
        emoji_str = "\U0001f600" * 100
        validate(emoji_str, "test", 100)  # 100 chars, should pass
        with pytest.raises(ValueError, match="exceeds"):
            validate(emoji_str + "x", "test", 100)  # 101 chars

    def test_non_string_types_pass_through(self, validate):
        """Non-string types should not raise (MCP handles type checking)."""
        validate(42, "test", 100)  # int
        validate(True, "test", 100)  # bool
        validate([], "test", 100)  # list


# ============================================================
# Section 2: Examiner slug sanitization
# ============================================================


class TestExaminerSlugSanitization:
    """Adversarial examiner identity inputs."""

    @pytest.fixture
    def sanitize(self):
        from wintools_mcp.audit import _sanitize_slug

        return _sanitize_slug

    @pytest.fixture
    def pattern(self):
        from wintools_mcp.audit import _EXAMINER_RE

        return _EXAMINER_RE

    def test_normal_slug(self, sanitize, pattern):
        assert pattern.match(sanitize("alice"))
        assert sanitize("alice") == "alice"

    def test_uppercase_lowered(self, sanitize):
        assert sanitize("ALICE") == "alice"

    def test_special_chars_replaced(self, sanitize, pattern):
        result = sanitize("alice@evil.com")
        assert "@" not in result
        assert "." not in result
        assert pattern.match(result)

    def test_path_traversal_in_examiner(self, sanitize, pattern):
        result = sanitize("../../../etc/passwd")
        assert "/" not in result
        assert ".." not in result
        assert pattern.match(result) or result == "unknown"

    def test_null_bytes_stripped(self, sanitize, pattern):
        result = sanitize("alice\x00bob")
        assert "\x00" not in result
        assert pattern.match(result)

    def test_unicode_stripped(self, sanitize, pattern):
        result = sanitize("al\u0456ce")  # Cyrillic 'i'
        assert pattern.match(result)

    def test_empty_becomes_unknown(self, sanitize):
        assert sanitize("") == "unknown"

    def test_all_special_becomes_unknown(self, sanitize):
        assert sanitize("@#$%^&*()") == "unknown"

    def test_very_long_truncated(self, sanitize):
        result = sanitize("a" * 100)
        assert len(result) <= 40

    def test_leading_hyphens_stripped(self, sanitize, pattern):
        result = sanitize("---alice")
        assert pattern.match(result)
        assert not result.startswith("-")

    def test_all_hyphens_becomes_unknown(self, sanitize):
        assert sanitize("---") == "unknown"

    def test_sql_injection_attempt(self, sanitize, pattern):
        result = sanitize("alice'; DROP TABLE users; --")
        assert "'" not in result
        assert ";" not in result
        assert pattern.match(result) or result == "unknown"


# ============================================================
# Section 3: Output directory validation
# ============================================================


class TestOutputDirValidation:
    """Test _validate_output_dir blocks system directories."""

    @pytest.fixture
    def validate(self):
        from wintools_mcp.executor import _validate_output_dir

        return _validate_output_dir

    def test_allows_normal_path(self, validate, tmp_path):
        validate(tmp_path)

    def test_blocks_etc(self, validate):
        with pytest.raises(ValueError, match="blocked"):
            validate(Path("/etc"))

    def test_blocks_etc_subdir(self, validate):
        with pytest.raises(ValueError, match="blocked"):
            validate(Path("/etc/ssh"))

    def test_blocks_usr(self, validate):
        with pytest.raises(ValueError, match="blocked"):
            validate(Path("/usr"))

    def test_blocks_bin(self, validate):
        with pytest.raises(ValueError, match="blocked"):
            validate(Path("/bin"))

    def test_blocks_proc(self, validate):
        with pytest.raises(ValueError, match="blocked"):
            validate(Path("/proc"))

    def test_allows_similar_name(self, validate, tmp_path):
        """Path /etcetera should NOT be blocked (not under /etc)."""
        validate(Path("/tmp/etcetera"))

    def test_windows_case_insensitive(self, validate):
        """Windows paths should be case-insensitive blocked."""
        with pytest.raises(ValueError, match="blocked"):
            validate(Path(r"C:\WINDOWS"))
        with pytest.raises(ValueError, match="blocked"):
            validate(Path(r"C:\windows\system32"))


# ============================================================
# Section 4: Audit writer concurrency
# ============================================================


class TestAuditWriterConcurrency:
    """Stress test audit writer under concurrent load."""

    def test_no_duplicate_audit_ids_under_contention(self, tmp_path, monkeypatch):
        """50 threads generating evidence IDs simultaneously — all must be unique."""
        monkeypatch.setenv("VHIR_EXAMINER", "tester")
        (tmp_path / "CASE.yaml").write_text("case_id: test\n")
        monkeypatch.setenv("VHIR_CASE_DIR", str(tmp_path))

        from wintools_mcp.audit import AuditWriter

        writer = AuditWriter("wintools-mcp")
        ids = []
        lock = threading.Lock()
        errors = []

        def generate_id():
            try:
                for _ in range(10):
                    eid = writer.log(tool="stress_test", params={}, result_summary={})
                    with lock:
                        ids.append(eid)
            except Exception as e:
                with lock:
                    errors.append(e)

        threads = [threading.Thread(target=generate_id) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent audit: {errors}"
        assert len(ids) == 500
        assert len(set(ids)) == 500, (
            f"Duplicate IDs found! {len(ids) - len(set(ids))} dupes"
        )

    def test_audit_file_not_corrupted_after_concurrent_writes(
        self, tmp_path, monkeypatch
    ):
        """Verify JSONL file is parseable after concurrent writes."""
        monkeypatch.setenv("VHIR_EXAMINER", "tester")
        (tmp_path / "CASE.yaml").write_text("case_id: test\n")
        monkeypatch.setenv("VHIR_CASE_DIR", str(tmp_path))

        from wintools_mcp.audit import AuditWriter

        writer = AuditWriter("wintools-mcp")

        def writer_fn():
            for i in range(20):
                writer.log(
                    tool=f"tool_{threading.current_thread().name}",
                    params={"iteration": i},
                    result_summary={"ok": True},
                )

        threads = [threading.Thread(target=writer_fn, name=f"t{n}") for n in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Verify every line is valid JSON
        audit_file = tmp_path / "audit" / "wintools-mcp.jsonl"
        assert audit_file.exists()
        lines = [
            line for line in audit_file.read_text().strip().split("\n") if line.strip()
        ]
        assert len(lines) == 200
        for i, line in enumerate(lines):
            try:
                entry = json.loads(line)
                assert "audit_id" in entry
                assert "tool" in entry
            except json.JSONDecodeError:
                pytest.fail(f"Corrupt JSONL at line {i}: {line[:100]}")
