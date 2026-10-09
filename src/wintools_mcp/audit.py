"""Audit trail writer for wintools-mcp.

Each MCP writes to its own JSONL file in the case audit directory.
Canonical implementation — copied (not imported) into each MCP repo.
"""

from __future__ import annotations

import getpass
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_share_error = ""  # why the case folder's share can't be read, or ""
_share_lock = threading.Lock()


def _set_share_error(reason: str) -> None:
    global _share_error
    with _share_lock:
        _share_error = reason


# Windows and POSIX error numbers, as fixed categories
_REASONS = {
    1: "not permitted",
    2: "not found",
    5: "access denied",
    13: "access denied",
    53: "share not reachable",
    59: "network error",
    64: "share not reachable",
    67: "share not reachable",
    86: "wrong password",
    1219: "mapped already with other credentials",
    1326: "wrong user name or password",
}


def share_reason(e: BaseException | int | None) -> str:
    """A fixed category for why the share failed, from an exception or an
    error number: never the exception's text, which can carry a command
    line (net use's holds the SMB password), for the share state, /health
    and the log."""
    import subprocess

    if isinstance(e, subprocess.TimeoutExpired):
        return "timed out"
    code = e
    if isinstance(e, OSError):
        code = getattr(e, "winerror", None) or e.errno
    elif isinstance(e, BaseException):
        return f"failed ({type(e).__name__})"
    if not code:
        return "failed"
    return _REASONS.get(code, f"error {code}")


def share_error() -> str:
    """Why the evidence share can't be read now ("" when it can): for the
    call's warnings and /health."""
    with _share_lock:
        return _share_error


_ULID_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"  # Crockford base32, lowercase
_EXAMINER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")


def _sanitize_slug(raw: str) -> str:
    """Sanitize a raw string into a valid examiner slug.

    Lowercases, replaces invalid characters with hyphens, strips leading/trailing
    hyphens, and truncates to 20 characters.
    """
    slug = re.sub(r"[^a-z0-9-]", "-", raw.lower()).strip("-")
    if len(slug) > 20:
        logger.warning(
            "Examiner slug truncated from %d to 20 chars: %s", len(slug), slug[:20]
        )
        slug = slug[:20]
    if not slug:
        return "unknown"
    # Ensure starts with alphanumeric
    slug = slug.lstrip("-")
    return slug if slug else "unknown"


def resolve_examiner() -> str:
    """Resolve examiner identity: VHIR_EXAMINER > VHIR_ANALYST > OS username.

    The result is validated against the slug pattern ^[a-z0-9][a-z0-9-]{0,19}$.
    """
    examiner = os.environ.get("VHIR_EXAMINER") or os.environ.get("VHIR_ANALYST")
    if not examiner:
        try:
            examiner = getpass.getuser()
        except Exception:
            examiner = "unknown"
    slug = _sanitize_slug(examiner)
    return slug


class AuditWriter:
    """Writes audit entries to a per-MCP JSONL file.

    Ids need no counter or lock: each ends in a ULID. File writes are wrapped
    in try/except with fsync for durability.
    """

    def __init__(
        self, mcp_name: str = "wintools-mcp", audit_dir: str | None = None
    ) -> None:
        self.mcp_name = mcp_name
        self._explicit_audit_dir = audit_dir

    @property
    def examiner(self) -> str:
        return resolve_examiner()

    def _get_audit_dir(self) -> Path | None:
        """Get the audit directory.

        Priority: explicit audit_dir > VHIR_AUDIT_DIR env > VHIR_CASE_DIR/audit/.
        A case folder on a share this process can't read (access denied,
        a dropped session) is reported through share_error(), never raised:
        one denied share must not fail every call.
        """
        try:
            audit_dir = self._find_audit_dir()
            if audit_dir is None:
                return None
            audit_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            _set_share_error(f"evidence share not accessible: {share_reason(e)}")
            logger.warning("Audit directory not accessible: %s", share_reason(e))
            return None
        _set_share_error("")
        return audit_dir

    def _find_audit_dir(self) -> Path | None:
        if self._explicit_audit_dir:
            return Path(self._explicit_audit_dir)
        env_audit = os.environ.get("VHIR_AUDIT_DIR")
        if env_audit:
            return Path(env_audit)
        from wintools_mcp import share_guard

        try:  # the case's own log, whichever way it's found
            share_guard.before_write()
        except share_guard.ShareRefused:
            return None  # noted for /health
        case_dir = os.environ.get("VHIR_CASE_DIR", "").strip()
        # Validate: must be a directory with CASE.yaml
        if case_dir:
            path = Path(case_dir)
            if path.is_dir() and (path / "CASE.yaml").exists():
                return path / "audit"
        # Set-but-wrong or unset: read the active case pointer file
        try:  # (a local file: unreadable means no active case)
            case_dir = (Path.home() / ".vhir" / "active_case").read_text().strip()
        except OSError:
            return None
        if not case_dir:
            return None
        path = Path(case_dir)
        if not path.is_dir() or not (path / "CASE.yaml").exists():
            logger.warning(
                "VHIR_CASE_DIR=%s is not a case directory, skipping audit", case_dir
            )
            return None
        return path / "audit"

    def _next_audit_id(self) -> str:
        """Generate the next audit ID: {prefix}-{examiner}-{date}-{ulid}.

        The ULID (48-bit milliseconds, 80 random bits) makes the id unique
        without a counter, across writers and processes.
        """
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        n = (time.time_ns() // 1_000_000) << 80 | int.from_bytes(os.urandom(10), "big")
        ulid = "".join(_ULID_ALPHABET[(n >> s) & 31] for s in range(125, -1, -5))
        prefix = self.mcp_name.replace("-mcp", "").replace("-", "")
        return f"{prefix}-{self.examiner}-{today}-{ulid}"

    def log(
        self,
        tool: str,
        params: dict[str, Any],
        result_summary: Any,
        source: str = "mcp_server",
        audit_id: str | None = None,
        case_id: str | None = None,
        elapsed_ms: float | None = None,
        input_files: list[str] | None = None,
        input_sha256s: list[str] | None = None,
        input_detection_method: str = "",
        source_evidence: str = "",
        extra: dict[str, Any] | None = None,
    ) -> str | None:
        """Write an audit entry. Returns the audit_id, or None on failure.
        ``extra`` adds fields to the entry (never over the ones above)."""
        if not self._get_audit_dir():
            return None
        if audit_id is None:
            audit_id = self._next_audit_id()

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "mcp": self.mcp_name,
            "tool": tool,
            "audit_id": audit_id,
            "examiner": self.examiner,
            "case_id": case_id or os.environ.get("VHIR_ACTIVE_CASE", ""),
            "source": source,
            "params": params,
            "result_summary": _summarize(result_summary),
        }
        if elapsed_ms is not None:
            entry["elapsed_ms"] = round(elapsed_ms, 1)
        if input_files:
            entry["input_files"] = input_files
            entry["input_sha256s"] = input_sha256s or []
        if input_detection_method:
            entry["input_detection_method"] = input_detection_method
        if source_evidence:
            entry["source_evidence"] = source_evidence
        for key, value in (extra or {}).items():
            entry.setdefault(key, value)

        if not self._write_entry(entry):
            logger.warning(
                "Audit write failed for audit_id=%s — returning None",
                audit_id,
            )
            return None
        return audit_id

    def _write_entry(self, entry: dict) -> bool:
        """Write a single audit entry to the JSONL file with fsync.

        Returns True if the entry was written successfully, False otherwise.
        """
        audit_dir = self._get_audit_dir()
        if not audit_dir:
            logger.debug(
                "No audit directory configured (audit_dir / VHIR_AUDIT_DIR / VHIR_CASE_DIR), "
                "audit entry not written: %s/%s",
                self.mcp_name,
                entry.get("tool"),
            )
            return False
        try:
            log_file = audit_dir / f"{self.mcp_name}.jsonl"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
            return True  # (the share's error was cleared when its folder was found)
        except OSError as e:
            _set_share_error(f"evidence share not accessible: {share_reason(e)}")
            logger.warning(
                "Failed to write audit entry for audit_id=%s tool=%s: %s "
                "(this audit_id was NOT recorded to the audit trail)",
                entry.get("audit_id"),
                entry.get("tool"),
                e,
            )
            return False

    def get_entries(
        self, since: str | None = None, case_id: str | None = None
    ) -> list[dict]:
        """Read back audit entries, optionally filtered."""
        audit_dir = self._get_audit_dir()
        if not audit_dir:
            return []
        log_file = audit_dir / f"{self.mcp_name}.jsonl"
        try:
            if not log_file.exists():
                return []
        except OSError as e:
            _set_share_error(f"evidence share not accessible: {share_reason(e)}")
            return []
        entries = []
        try:
            with open(log_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning("Corrupt JSONL line in %s", log_file)
                        continue
                    if since and entry.get("ts", "") < since:
                        continue
                    if case_id and entry.get("case_id", "") != case_id:
                        continue
                    entries.append(entry)
        except OSError as e:
            _set_share_error(f"evidence share not accessible: {share_reason(e)}")
            logger.warning(
                "Failed to read audit entries from %s: %s", log_file, share_reason(e)
            )
        return entries

    def reset_counter(self) -> None:
        """Kept for callers' tests: ids no longer use a counter."""


def _summarize(result: Any) -> Any:
    """Truncate large results for audit log."""
    if isinstance(result, dict):
        return result
    if isinstance(result, list):
        return {"count": len(result), "type": "list"}
    return {"value": str(result)[:500]}
