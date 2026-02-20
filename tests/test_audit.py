"""Tests for audit module — evidence IDs, JSONL writing, examiner identity."""

import json
import os
import pytest

from wintools_mcp.audit import AuditWriter, resolve_examiner


class TestExaminerResolution:

    def test_examiner_from_env(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "Jane")
        assert resolve_examiner() == "jane"

    def test_examiner_fallback_analyst(self, monkeypatch):
        monkeypatch.delenv("AIIR_EXAMINER", raising=False)
        monkeypatch.setenv("AIIR_ANALYST", "Steve")
        assert resolve_examiner() == "steve"

    def test_examiner_fallback_os_user(self, monkeypatch):
        monkeypatch.delenv("AIIR_EXAMINER", raising=False)
        monkeypatch.delenv("AIIR_ANALYST", raising=False)
        result = resolve_examiner()
        assert result  # Non-empty
        assert result == result.lower()


class TestEvidenceIds:

    def test_evidence_id_format(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "jane")
        audit = AuditWriter()
        eid = audit._next_evidence_id()
        assert eid.startswith("win-jane-")
        parts = eid.split("-")
        assert len(parts) == 4
        assert parts[0] == "win"
        assert parts[1] == "jane"
        assert len(parts[2]) == 8  # YYYYMMDD
        assert len(parts[3]) == 3  # NNN

    def test_evidence_id_sequential(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "jane")
        audit = AuditWriter()
        id1 = audit._next_evidence_id()
        id2 = audit._next_evidence_id()
        id3 = audit._next_evidence_id()
        # Sequence numbers increase
        assert id1.endswith("-001")
        assert id2.endswith("-002")
        assert id3.endswith("-003")

    def test_evidence_id_per_process(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "steve")
        a1 = AuditWriter()
        a2 = AuditWriter()
        # Different instances get independent counters
        assert a1._next_evidence_id().endswith("-001")
        assert a2._next_evidence_id().endswith("-001")


class TestAuditWriting:

    def test_writes_jsonl(self, case_dir, examiner):
        audit = AuditWriter()
        eid = audit.log(
            tool="run_amcacheparser",
            params={"input_file": "Amcache.hve"},
            result_summary={"exit_code": 0},
        )
        assert eid.startswith("win-testuser-")

        log_file = case_dir / ".audit" / "wintools-mcp.jsonl"
        assert log_file.exists()
        entries = [json.loads(line) for line in log_file.read_text().splitlines()]
        assert len(entries) == 1
        entry = entries[0]
        assert entry["mcp"] == "wintools-mcp"
        assert entry["tool"] == "run_amcacheparser"
        assert entry["evidence_id"] == eid
        assert entry["examiner"] == "testuser"
        assert entry["source"] == "mcp_server"
        assert "ts" in entry

    def test_case_id_from_env(self, case_dir, examiner, monkeypatch):
        monkeypatch.setenv("AIIR_ACTIVE_CASE", "INC-2026-001")
        audit = AuditWriter()
        audit.log(tool="test", params={}, result_summary={})

        log_file = case_dir / ".audit" / "wintools-mcp.jsonl"
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
        log_file = case_dir / ".audit" / "wintools-mcp.jsonl"
        entry = json.loads(log_file.read_text().strip())
        assert entry["elapsed_ms"] == 1234.5

    def test_no_write_without_case_dir(self, monkeypatch, tmp_path, examiner):
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        audit = AuditWriter()
        eid = audit.log(tool="test", params={}, result_summary={})
        assert eid  # Still returns an evidence ID
        # No file written
        audit_dir = tmp_path / ".audit"
        assert not audit_dir.exists()

    def test_multiple_entries_append(self, case_dir, examiner):
        audit = AuditWriter()
        audit.log(tool="tool1", params={}, result_summary={})
        audit.log(tool="tool2", params={}, result_summary={})
        audit.log(tool="tool3", params={}, result_summary={})

        log_file = case_dir / ".audit" / "wintools-mcp.jsonl"
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
        monkeypatch.setenv("AIIR_ACTIVE_CASE", "INC-001")
        audit = AuditWriter()
        audit.log(tool="t1", params={}, result_summary={})

        monkeypatch.setenv("AIIR_ACTIVE_CASE", "INC-002")
        audit.log(tool="t2", params={}, result_summary={})

        entries = audit.get_entries(case_id="INC-001")
        assert len(entries) == 1
        assert entries[0]["tool"] == "t1"

    def test_get_entries_empty(self, monkeypatch, examiner):
        monkeypatch.delenv("AIIR_CASE_DIR", raising=False)
        audit = AuditWriter()
        entries = audit.get_entries()
        assert entries == []
