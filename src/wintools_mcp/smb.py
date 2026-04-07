"""SMB session management -- shared between http_server and executor."""

from __future__ import annotations

import logging
import os
import subprocess
import threading

logger = logging.getLogger(__name__)

_smb_lock = threading.Lock()
_smb_session_ok = False


def establish_smb_session(config) -> bool:
    """Establish SMB session via net use. Returns True on success."""
    global _smb_session_ok
    if not config.share_root.startswith("\\\\"):
        return True  # Not a UNC path, no SMB needed
    if not config.smb_user or not config.smb_password:
        logger.info("SMB credentials not configured, skipping session")
        return False
    with _smb_lock:
        try:
            result = subprocess.run(
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
            if result.returncode == 0:
                _smb_session_ok = True
                logger.info("SMB session established to %s", config.share_root)
                return True
            # Error 1219 (multiple connections) or "already connected" -- both fine
            combined = (result.stderr + result.stdout).lower()
            if "already" in combined or "multiple connections" in combined:
                _smb_session_ok = True
                return True
            # net use failed but share may be accessible via persistent mapping
            if os.path.isdir(config.share_root):
                _smb_session_ok = True
                logger.info(
                    "SMB share accessible via existing mapping: %s",
                    config.share_root,
                )
                return True
            _smb_session_ok = False
            err_msg = result.stderr.strip()
            logger.error(
                "SMB session failed (exit %d): %s",
                result.returncode,
                err_msg,
            )
            _audit_smb_failure(
                config.share_root, f"exit {result.returncode}: {err_msg}"
            )
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
