"""Audit trail writer for wintools-mcp. Writes per-MCP JSONL files."""

from __future__ import annotations

import getpass
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def resolve_examiner() -> str:
    """Resolve examiner identity: AIIR_EXAMINER > AIIR_ANALYST > OS username."""
    examiner = os.environ.get("AIIR_EXAMINER") or os.environ.get("AIIR_ANALYST")
    if not examiner:
        try:
            examiner = getpass.getuser()
        except Exception:
            examiner = "unknown"
    return examiner.lower()


class AuditWriter:
    def __init__(self, mcp_name: str = "wintools-mcp") -> None:
        self.mcp_name = mcp_name
        self._sequence = 0
        self._date_str = ""

    @property
    def examiner(self) -> str:
        return resolve_examiner()

    def _get_audit_dir(self) -> Path | None:
        case_dir = os.environ.get("AIIR_CASE_DIR")
        if not case_dir:
            return None
        # Windows-local audit: .audit/ (local convention)
        # If AIIR_CASE_DIR is an SMB mount of SIFT, write to .local/audit/
        audit_dir = Path(case_dir) / ".audit"
        audit_dir.mkdir(parents=True, exist_ok=True)
        return audit_dir

    def _next_evidence_id(self) -> str:
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        if today != self._date_str:
            self._date_str = today
            self._sequence = 0
        self._sequence += 1
        return f"win-{self.examiner}-{today}-{self._sequence:03d}"

    def log(
        self,
        tool: str,
        params: dict,
        result_summary: Any,
        source: str = "mcp_server",
        evidence_id: str | None = None,
        case_id: str | None = None,
        elapsed_ms: float | None = None,
    ) -> str:
        if evidence_id is None:
            evidence_id = self._next_evidence_id()

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "mcp": self.mcp_name,
            "tool": tool,
            "evidence_id": evidence_id,
            "examiner": self.examiner,
            "case_id": case_id or os.environ.get("AIIR_ACTIVE_CASE", ""),
            "source": source,
            "params": params,
            "result_summary": _summarize(result_summary),
        }
        if elapsed_ms is not None:
            entry["elapsed_ms"] = round(elapsed_ms, 1)

        audit_dir = self._get_audit_dir()
        if audit_dir:
            log_file = audit_dir / f"{self.mcp_name}.jsonl"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        else:
            logger.debug(
                "No AIIR_CASE_DIR set, audit entry not written: %s/%s",
                self.mcp_name,
                tool,
            )
        return evidence_id

    def get_entries(
        self, since: str | None = None, case_id: str | None = None
    ) -> list[dict]:
        """Read back audit entries, optionally filtered."""
        audit_dir = self._get_audit_dir()
        if not audit_dir:
            return []
        log_file = audit_dir / f"{self.mcp_name}.jsonl"
        if not log_file.exists():
            return []
        entries = []
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if since and entry.get("ts", "") < since:
                    continue
                if case_id and entry.get("case_id", "") != case_id:
                    continue
                entries.append(entry)
        return entries


def _summarize(result: Any) -> Any:
    if isinstance(result, dict):
        return result
    if isinstance(result, list):
        return {"count": len(result), "type": "list"}
    return {"value": str(result)[:500]}
