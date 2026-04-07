"""Tests for audit module — evidence IDs, JSONL writing, examiner identity."""

import json
import threading
from pathlib import Path

from wintools_mcp.audit import AuditWriter, resolve_examiner


class TestExaminerResolution:
    def test_examiner_from_env(self, monkeypatch):
        monkeypatch.setenv("VHIR_EXAMINER", "Jane")
        assert resolve_examiner() == "jane"

    def test_examiner_fallback_analyst(self, monkeypatch):
        monkeypatch.delenv("VHIR_EXAMINER", raising=False)
        monkeypatch.setenv("VHIR_ANALYST", "Steve")
        assert resolve_examiner() == "steve"

    def test_examiner_fallback_os_user(self, monkeypatch):
        monkeypatch.delenv("VHIR_EXAMINER", raising=False)
        monkeypatch.delenv("VHIR_ANALYST", raising=False)
        result = resolve_examiner()
        assert result  # Non-empty
        assert result == result.lower()


class TestAuditIds:
    def test_audit_id_format(self, monkeypatch):
        monkeypatch.setenv("VHIR_EXAMINER", "jane")
        audit = AuditWriter()
        eid = audit._next_audit_id()
        assert eid.startswith("wintools-jane-")
        parts = eid.split("-")
        assert len(parts) == 4
        assert parts[0] == "wintools"
        assert parts[1] == "jane"
        assert len(parts[2]) == 8  # YYYYMMDD
        assert len(parts[3]) == 6  # NNNNNN

    def test_audit_id_sequential(self, monkeypatch):
        monkeypatch.setenv("VHIR_EXAMINER", "jane")
        audit = AuditWriter()
        id1 = audit._next_audit_id()
        id2 = audit._next_audit_id()
        id3 = audit._next_audit_id()
        # Sequence numbers increase
        assert id1.endswith("-000001")
        assert id2.endswith("-000002")
        assert id3.endswith("-000003")

    def test_audit_id_per_process(self, monkeypatch):
        monkeypatch.setenv("VHIR_EXAMINER", "steve")
        a1 = AuditWriter()
        a2 = AuditWriter()
        # Different instances get independent counters
        assert a1._next_audit_id().endswith("-000001")
        assert a2._next_audit_id().endswith("-000001")


class TestAuditWriting:
    def test_writes_jsonl(self, case_dir, examiner):
        audit = AuditWriter()
        eid = audit.log(
            tool="run_amcacheparser",
            params={"input_file": "Amcache.hve"},
            result_summary={"exit_code": 0},
        )
        assert eid.startswith("wintools-testuser-")

        log_file = case_dir / "audit" / "wintools-mcp.jsonl"
        assert log_file.exists()
        entries = [json.loads(line) for line in log_file.read_text().splitlines()]
        assert len(entries) == 1
        entry = entries[0]
        assert entry["mcp"] == "wintools-mcp"
        assert entry["tool"] == "run_amcacheparser"
        assert entry["audit_id"] == eid
        assert entry["examiner"] == "testuser"
        assert entry["source"] == "mcp_server"
        assert "ts" in entry

    def test_case_id_from_env(self, case_dir, examiner, monkeypatch):
        monkeypatch.setenv("VHIR_ACTIVE_CASE", "INC-2026-001")
        audit = AuditWriter()
        audit.log(tool="test", params={}, result_summary={})

        log_file = case_dir / "audit" / "wintools-mcp.jsonl"
        entry = json.loads(log_file.read_text().strip())
        assert entry["case_id"] == "INC-2026-001"

    def test_elapsed_ms_recorded(self, case_dir, examiner):
        audit = AuditWriter()
        audit.log(
            tool="test",
            params={},
            result_summary={},
            elapsed_ms=1234.5,
        )
        log_file = case_dir / "audit" / "wintools-mcp.jsonl"
        entry = json.loads(log_file.read_text().strip())
        assert entry["elapsed_ms"] == 1234.5

    def test_no_write_without_case_dir(self, monkeypatch, tmp_path, examiner):
        monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
        monkeypatch.delenv("VHIR_AUDIT_DIR", raising=False)
        # Ensure active_case fallback also fails
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "nohome")
        audit = AuditWriter()
        eid = audit.log(tool="test", params={}, result_summary={})
        assert eid is None  # Returns None when no case dir available
        # No file written
        audit_dir = tmp_path / "audit"
        assert not audit_dir.exists()

    def test_multiple_entries_append(self, case_dir, examiner):
        audit = AuditWriter()
        audit.log(tool="tool1", params={}, result_summary={})
        audit.log(tool="tool2", params={}, result_summary={})
        audit.log(tool="tool3", params={}, result_summary={})

        log_file = case_dir / "audit" / "wintools-mcp.jsonl"
        entries = [json.loads(line) for line in log_file.read_text().splitlines()]
        assert len(entries) == 3
        assert [e["tool"] for e in entries] == ["tool1", "tool2", "tool3"]


class TestAuditRetrieval:
    def test_get_entries(self, case_dir, examiner):
        audit = AuditWriter()
        audit.log(tool="t1", params={}, result_summary={})
        audit.log(tool="t2", params={}, result_summary={})

        entries = audit.get_entries()
        assert len(entries) == 2

    def test_get_entries_case_filter(self, case_dir, examiner, monkeypatch):
        monkeypatch.setenv("VHIR_ACTIVE_CASE", "INC-001")
        audit = AuditWriter()
        audit.log(tool="t1", params={}, result_summary={})

        monkeypatch.setenv("VHIR_ACTIVE_CASE", "INC-002")
        audit.log(tool="t2", params={}, result_summary={})

        entries = audit.get_entries(case_id="INC-001")
        assert len(entries) == 1
        assert entries[0]["tool"] == "t1"

    def test_get_entries_empty(self, monkeypatch, tmp_path, examiner):
        monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        audit = AuditWriter()
        entries = audit.get_entries()
        assert entries == []


class TestAuditDirParameter:
    def test_explicit_audit_dir(self, tmp_path, examiner):
        audit_dir = tmp_path / "local_audit"
        audit = AuditWriter(audit_dir=str(audit_dir))
        audit.log(tool="test", params={}, result_summary={})

        log_file = audit_dir / "wintools-mcp.jsonl"
        assert log_file.exists()
        entry = json.loads(log_file.read_text().strip())
        assert entry["tool"] == "test"

    def test_audit_dir_env_var(self, tmp_path, monkeypatch, examiner):
        audit_dir = tmp_path / "env_audit"
        monkeypatch.setenv("VHIR_AUDIT_DIR", str(audit_dir))
        monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
        audit = AuditWriter()
        audit.log(tool="test", params={}, result_summary={})

        log_file = audit_dir / "wintools-mcp.jsonl"
        assert log_file.exists()

    def test_explicit_overrides_env(self, tmp_path, monkeypatch, examiner):
        env_dir = tmp_path / "env_audit"
        explicit_dir = tmp_path / "explicit_audit"
        monkeypatch.setenv("VHIR_AUDIT_DIR", str(env_dir))
        audit = AuditWriter(audit_dir=str(explicit_dir))
        audit.log(tool="test", params={}, result_summary={})

        assert (explicit_dir / "wintools-mcp.jsonl").exists()
        assert not env_dir.exists()

    def test_env_overrides_case_dir(self, tmp_path, monkeypatch, examiner):
        case_dir = tmp_path / "case"
        case_dir.mkdir()
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        env_audit = tmp_path / "local_audit"
        monkeypatch.setenv("VHIR_AUDIT_DIR", str(env_audit))
        audit = AuditWriter()
        audit.log(tool="test", params={}, result_summary={})

        assert (env_audit / "wintools-mcp.jsonl").exists()
        assert not (case_dir / "audit").exists()


class TestThreadSafety:
    def test_concurrent_log_calls(self, case_dir, examiner):
        audit = AuditWriter()
        ids = []
        lock = threading.Lock()

        def log_one():
            eid = audit.log(tool="test", params={}, result_summary={})
            with lock:
                ids.append(eid)

        threads = [threading.Thread(target=log_one) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(ids) == 10
        assert len(set(ids)) == 10  # all unique
