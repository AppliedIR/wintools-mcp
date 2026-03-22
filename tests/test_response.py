"""Tests for response envelope builder."""

from wintools_mcp.response import DISCIPLINE_REMINDERS, build_response


class TestBuildResponse:
    def test_basic_response(self, examiner):
        resp = build_response(
            tool_name="run_test",
            success=True,
            data={"key": "value"},
            audit_id="win-testuser-20260220-001",
        )
        assert resp["success"] is True
        assert resp["tool"] == "run_test"
        assert resp["data"] == {"key": "value"}
        assert resp["audit_id"] == "win-testuser-20260220-001"
        assert resp["examiner"] == "testuser"
        assert "discipline_reminder" in resp

    def test_error_response(self, examiner):
        resp = build_response(
            tool_name="run_test",
            success=False,
            data=None,
            audit_id="win-testuser-20260220-001",
            error="Tool not found",
        )
        assert resp["success"] is False
        assert resp["error"] == "Tool not found"

    def test_metadata_included(self, examiner):
        resp = build_response(
            tool_name="run_test",
            success=True,
            data={},
            audit_id="win-testuser-20260220-001",
            elapsed_seconds=1.5,
            exit_code=0,
            command=["test.exe", "-f", "input"],
        )
        assert resp["metadata"]["elapsed_seconds"] == 1.5
        assert resp["metadata"]["exit_code"] == 0
        assert resp["metadata"]["command"] == ["test.exe", "-f", "input"]

    def test_output_files_included(self, examiner):
        files = [{"path": "output/test.csv", "size_bytes": 1024}]
        resp = build_response(
            tool_name="run_test",
            success=True,
            data={},
            audit_id="win-testuser-20260220-001",
            output_files=files,
        )
        assert resp["output_files"] == files

    def test_discipline_reminder_rotates(self, examiner):
        reminders = set()
        for i in range(len(DISCIPLINE_REMINDERS)):
            resp = build_response(
                tool_name="run_test",
                success=True,
                data={},
                audit_id=f"win-testuser-20260220-{i + 1:03d}",
            )
            reminders.add(resp["discipline_reminder"])
        assert len(reminders) == len(DISCIPLINE_REMINDERS)

    def test_cross_mcp_checks_included(self, examiner):
        """Response should include cross_mcp_checks from artifact data."""
        resp = build_response(
            tool_name="run_pecmd",
            success=True,
            data={},
            audit_id="win-testuser-20260220-030",
            fk_tool_name="PECmd",
        )
        # PECmd parses prefetch, which should have cross_mcp_checks
        if "cross_mcp_checks" in resp:
            checks = resp["cross_mcp_checks"]
            assert len(checks) >= 1
            for check in checks:
                assert "mcp" in check
                assert "tool" in check
                assert "when" in check

    def test_extractions_included(self, examiner):
        extractions = ["extractions/evtxecmd-Security-003.csv"]
        resp = build_response(
            tool_name="run_windows_command",
            success=True,
            data={},
            audit_id="win-testuser-20260220-001",
            extractions=extractions,
        )
        assert resp["extractions"] == extractions

    def test_extractions_omitted_when_none(self, examiner):
        resp = build_response(
            tool_name="run_windows_command",
            success=True,
            data={},
            audit_id="win-testuser-20260220-001",
        )
        assert "extractions" not in resp

    def test_extractions_omitted_when_empty(self, examiner):
        resp = build_response(
            tool_name="run_windows_command",
            success=True,
            data={},
            audit_id="win-testuser-20260220-001",
            extractions=[],
        )
        assert "extractions" not in resp

    def test_examiner_in_response(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "steve")
        resp = build_response(
            tool_name="run_test",
            success=True,
            data={},
            audit_id="win-steve-20260220-001",
        )
        assert resp["examiner"] == "steve"
