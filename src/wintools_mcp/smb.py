"""SMB session management -- shared between http_server and executor."""

from __future__ import annotations

import logging
import os
import secrets
import subprocess
import threading
import time

logger = logging.getLogger(__name__)

_smb_lock = threading.Lock()
_smb_session_ok = False
# The last finished attempt's (result, time.time()), read without the lock:
# an attempt holds the lock across net use and the share's own I/O
_smb_last: tuple[bool, float] | None = None


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
        from wintools_mcp.audit import share_reason

        return share_reason(e)
    finally:
        try:
            os.remove(name)
        except OSError:
            pass


def _net_use_reason(result) -> str:
    """Why net use failed, as a fixed category: its error number, never its
    output (nor its command line, which holds the password)."""
    import re

    from wintools_mcp.audit import share_reason

    found = re.search(r"System error (\d+)", f"{result.stderr} {result.stdout}")
    if found:
        return share_reason(int(found.group(1)))
    return f"net use exit {result.returncode}"


def _legacy_share(share_root: str) -> str:
    """`\\\\<server>\\cases`, the share 0.6.3 used on the same server; "" when
    share_root is that share or ends in \\cases, or isn't \\\\server\\share."""
    parts = share_root[2:].split("\\")
    if not share_root.startswith("\\\\") or len(parts) < 2 or not parts[0]:
        return ""
    if parts[1].lower() == "cases" or share_root.rstrip("\\").lower().endswith(
        "\\cases"
    ):
        return ""  # that share, or a folder named cases: its own mapping went first
    return f"\\\\{parts[0]}\\cases"


def _is_1219(result) -> bool:
    """net use refused: the server is already mapped with other credentials.
    By the error number, since its words follow Windows' display language."""
    import re

    text = f"{result.stderr} {result.stdout}"
    return result.returncode != 0 and re.search(r"(?<!\d)1219(?!\d)", text) is not None


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
            return _finished(_attempt(config, share_guard))
        except Exception as e:
            from wintools_mcp.audit import share_reason

            # never the error's text: net use's argv holds the password
            reason = share_reason(e)
            logger.error("SMB session error: %s", reason)
            _note_smb_failure(config.share_root, reason)
            return _finished(False)


def _finished(ok: bool) -> bool:
    """Record an attempt's result, and when it finished."""
    global _smb_session_ok, _smb_last
    _smb_session_ok = ok
    _smb_last = (ok, time.time())
    return ok


def _attempt(config, share_guard) -> bool:
    """One session attempt, under the lock (see establish_smb_session)."""
    result = _net_use(config)
    combined = (result.stderr + result.stdout).lower()
    existing = (
        result.returncode != 0
        and ("already" in combined or "multiple connections" in combined)
        or _is_1219(result)
    )  # 1219 by its number, in any display language
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
            legacy = _legacy_share(config.share_root)
            if legacy and _is_1219(again):
                # a mapping to the share 0.6.3 used, remembered by this logon
                # session, holds the server under an earlier join's password
                subprocess.run(
                    ["net", "use", legacy, "/delete", "/y"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                again = _net_use(config)
            why = (
                _probe(config.share_root, config.active_case)
                if again.returncode == 0
                else _net_use_reason(again)
            )
        if not why:
            logger.info("SMB session established to %s", config.share_root)
            return True
        err_msg = f"mapped, but the share can't be used: {why}"
    elif os.path.isdir(config.share_root):
        # net use failed: a persistent mapping counts if it works end to end
        why = _probe(config.share_root, config.active_case)
        if not why:
            logger.info(
                "SMB share accessible via existing mapping: %s",
                config.share_root,
            )
            return True
        err_msg = f"mapped, but the share can't be used: {why}"
    else:
        err_msg = f"net use failed: {_net_use_reason(result)}"
    logger.error("SMB session failed: %s", err_msg)
    _note_smb_failure(config.share_root, err_msg)
    return False


def is_smb_session_ok() -> bool:
    """Whether the last SMB session attempt succeeded (False while one runs).
    Never waits for the lock: an attempt can hang on the share."""
    return _smb_session_ok


def smb_session_state() -> dict:
    """For /health, without the lock: the last finished attempt's result and
    its age in seconds (None before the first), and whether one is running."""
    last = _smb_last
    return {
        "ok": last[0] if last else False,
        "age_seconds": round(time.time() - last[1]) if last else None,
        "checking": _smb_lock.locked(),
    }


def _note_smb_failure(share_root: str, error: str) -> None:
    """Keep why the session failed for /health, in memory only: a session
    attempt never writes to the share, nor calls anything that can (an
    audit entry there would run the share's own checks, and their recovery,
    while this attempt holds the session lock)."""
    from wintools_mcp.audit import _set_share_error

    _set_share_error(f"SMB session to {share_root} failed: {error}")
