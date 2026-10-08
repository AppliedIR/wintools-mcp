"""SMB session management -- shared between http_server and executor."""

from __future__ import annotations

import logging
import os
import secrets
import subprocess
import threading

logger = logging.getLogger(__name__)

_smb_lock = threading.Lock()
_smb_session_ok = False


def _probe(share_root: str, active_case: str) -> str:
    """Write, read back and remove a small file through the mapping; "" when
    that works, else why not. "Already connected" says nothing about a
    session that still works (a stale mapping after a re-join). Nothing is
    written unless the share is the active case."""
    from wintools_mcp import share_guard

    refused = share_guard.check(share_root, active_case)
    if refused:
        return refused
    name = os.path.join(
        share_root, f".wintools-probe-{os.getpid()}-{secrets.token_hex(4)}"
    )
    data = secrets.token_hex(8)
    try:
        with open(name, "w", encoding="ascii") as f:
            f.write(data)
        with open(name, encoding="ascii") as f:
            if f.read() != data:
                return "the probe read back different bytes"
        return ""
    except OSError as e:
        return str(e)
    finally:
        try:
            os.remove(name)
        except OSError:
            pass


def _net_use(config):
    return subprocess.run(
        [
            "net",
            "use",
            config.share_root,
            f"/user:{config.smb_user}",
            config.smb_password,
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )


def establish_smb_session(config) -> bool:
    """Establish SMB session via net use. Returns True on success: a mapping
    a write/read probe went through. An existing mapping that fails the
    probe (stale after a re-join) is deleted and mapped again."""
    global _smb_session_ok
    from wintools_mcp import share_guard

    if not config.share_root.startswith("\\\\"):
        return True  # Not a UNC path, no SMB needed
    if not config.smb_user or not config.smb_password:
        logger.info("SMB credentials not configured, skipping session")
        return False
    with _smb_lock:
        _smb_session_ok = False
        try:
            result = _net_use(config)
            combined = (result.stderr + result.stdout).lower()
            existing = result.returncode != 0 and (
                "already" in combined or "multiple connections" in combined
            )
            if result.returncode == 0 or existing:
                why = _probe(config.share_root, config.active_case)
                if why and existing and not share_guard.is_refusal(why):
                    # a stale mapping: drop it and map again
                    subprocess.run(
                        ["net", "use", config.share_root, "/delete", "/y"],
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    again = _net_use(config)
                    why = (
                        _probe(config.share_root, config.active_case)
                        if again.returncode == 0
                        else (again.stderr or again.stdout).strip()
                        or f"exit {again.returncode}"
                    )
                if not why:
                    _smb_session_ok = True
                    logger.info("SMB session established to %s", config.share_root)
                    return True
                err_msg = f"mapped, but the share can't be used: {why}"
            elif os.path.isdir(config.share_root):
                # net use failed: a persistent mapping counts if it works end to end
                why = _probe(config.share_root, config.active_case)
                if not why:
                    _smb_session_ok = True
                    logger.info(
                        "SMB share accessible via existing mapping: %s",
                        config.share_root,
                    )
                    return True
                err_msg = f"mapped, but the share can't be used: {why}"
            else:
                err_msg = f"exit {result.returncode}: {result.stderr.strip()}"
            logger.error("SMB session failed: %s", err_msg)
            _audit_smb_failure(config.share_root, err_msg)
            return False
        except Exception as e:
            _smb_session_ok = False
            logger.error("SMB session error: %s", e)
            _audit_smb_failure(config.share_root, str(e))
            return False


def is_smb_session_ok() -> bool:
    """Check if the last SMB session establishment succeeded."""
    with _smb_lock:
        return _smb_session_ok


def _audit_smb_failure(share_root: str, error: str) -> None:
    """Best-effort audit log for SMB failures."""
    try:
        from wintools_mcp.audit import AuditWriter

        writer = AuditWriter()
        writer.log(
            tool="smb_session",
            params={"share": share_root},
            result_summary=f"SMB failed: {error}",
        )
    except Exception:
        pass  # Audit itself may be unavailable
