"""wintools writes into the case only through a share that is the active case.

Sharing a case on SIFT writes a marker at the case's root holding the case's
folder name, the id wintools is told at activation. Before any write through
the share (tool output, the audit log, the session probe) wintools reads the
marker under the share's root and compares it with its active case. A share
still pointed at another case, at no case, or at a folder that isn't a case
(an old mapping to SIFT's own shares) holds no such marker, and nothing is
written there.
"""

from __future__ import annotations

import os
import threading

from wintools_mcp.exceptions import WintoolsError

_recovering = threading.local()  # a session recovery's own audit entry checks only

MARKER = ".vhir-share-case"
REFUSED = "the evidence share isn't the active case (re-join or re-activate)"


def check(share_root: str, active_case: str) -> str:
    """Why nothing may be written through `share_root`, or an empty string
    when its marker names `active_case`. A share that can't be read at all
    says so, without the refusal."""
    try:
        with open(os.path.join(share_root, MARKER), encoding="utf-8") as f:
            named = f.read(512).strip()
    except FileNotFoundError:
        named = ""
    except (OSError, ValueError) as e:
        return f"evidence share not accessible: {e}"
    if active_case and named == active_case:
        return ""
    held = f"it holds case {named!r}" if named else "it holds no case marker"
    return f"{REFUSED}: the active case is {active_case or 'none'}, {held}"


def refusal(config=None) -> str:
    """Why nothing may be written through the configured share now, or "".
    A wintools with no share writes to its own local case, unchecked."""
    if config is None:
        from wintools_mcp.config import get_config

        config = get_config()
    if not config.share_root:
        return ""
    return check(config.share_root, config.active_case)


def is_refusal(reason: str) -> bool:
    return reason.startswith(REFUSED)


class ShareRefused(WintoolsError):
    """Nothing may be written through the share now."""


def before_write(config=None) -> None:
    """Called immediately before every create or write under the share.
    A share that can't be read first gets its SMB session re-established and
    is checked again; a refusal is raised (ShareRefused) and kept for
    /health, and a pass clears it."""
    if config is None:
        from wintools_mcp.config import get_config

        config = get_config()
    if not config.share_root:
        return
    from wintools_mcp.audit import _set_share_error

    why = check(config.share_root, config.active_case)
    if why and not is_refusal(why) and not getattr(_recovering, "on", False):
        from wintools_mcp.smb import establish_smb_session

        _recovering.on = True  # an expired session, say: recover it first
        try:
            if establish_smb_session(config):
                why = check(config.share_root, config.active_case)
        finally:
            _recovering.on = False
    _set_share_error(why)
    if why:
        raise ShareRefused(why)
