"""What a run in a case records about the files it read and wrote.

Each file is named three ways: its path here, its path relative to the share
(``share_path``), and its path in the case on SIFT (``sift_path``: the same,
case-relative, with ``/``). A file over the size limit isn't hashed here: it
is recorded ``pending``, and SIFT hashes it in place.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from wintools_mcp.output import _chunked_sha256, to_share_relative

# Bigger files are hashed on SIFT, not here
HASH_LIMIT = 1_000_000_000

_tool_hashes: dict[tuple[str, int, int], str] = {}
_tool_lock = threading.Lock()


def file_record(path: str | Path, share_root: str) -> dict:
    """``{path, share_path, sift_path, size, sha256}``, or ``hash_state:
    pending`` in place of the hash for a file over the limit."""
    p = Path(path)
    st = p.stat()
    share_path = to_share_relative(str(p), share_root)
    record = {
        "path": str(p),
        "share_path": share_path,
        "sift_path": share_path.replace("\\", "/").lstrip("/"),
        "size": st.st_size,
    }
    if st.st_size > HASH_LIMIT:
        record["hash_state"] = "pending"
    else:
        record["sha256"] = _chunked_sha256(p)
    return record


def listing(folder: str | Path) -> dict[str, tuple[int, int]]:
    """Every file under ``folder`` (or ``folder`` itself, a file), with its
    size and modification time; empty when it doesn't exist."""
    p = Path(folder)
    if p.is_file():
        st = p.stat()
        return {str(p): (st.st_size, st.st_mtime_ns)}
    out = {}
    if p.is_dir():
        for f in p.rglob("*"):
            if f.is_file():
                st = f.stat()
                out[str(f)] = (st.st_size, st.st_mtime_ns)
    return out


def written(before: dict[str, tuple[int, int]], folder: str | Path) -> list[str]:
    """The files under ``folder`` that are new or changed since ``before``."""
    return sorted(p for p, seen in listing(folder).items() if before.get(p) != seen)


def tool_sha256(path: str | None) -> str:
    """The tool file's SHA-256, kept while its size and time stay the same."""
    if not path:
        return ""
    try:
        st = os.stat(path)
    except OSError:
        return ""
    key = (str(path), st.st_size, st.st_mtime_ns)
    with _tool_lock:
        if key in _tool_hashes:
            return _tool_hashes[key]
    digest = _chunked_sha256(Path(path))
    with _tool_lock:
        _tool_hashes[key] = digest
    return digest


def settings_record(
    tool_path: str | None, folders: list[str], op_dir: str
) -> list[dict]:
    """For each settings folder beside the tool: its files and one digest of
    their sorted ``path sha256`` lines. The per-file hashes are saved to the
    op folder (``settings-<folder>.json``), whose own hash is recorded."""
    if not tool_path or not folders:
        return []
    base = Path(tool_path).parent
    records = []
    for name in folders:
        folder = base / name
        files = (
            sorted(f for f in folder.rglob("*") if f.is_file())
            if folder.is_dir()
            else []
        )
        hashes = {f.relative_to(folder).as_posix(): tool_sha256(str(f)) for f in files}
        lines = "".join(f"{rel} {sha}\n" for rel, sha in hashes.items())
        record = {
            "path": str(folder),
            "files": len(hashes),
            "sha256": _sha256_text(lines),
        }
        if op_dir and hashes:
            manifest = Path(op_dir) / f"settings-{name}.json"
            manifest.write_text(json.dumps(hashes, indent=1, sort_keys=True))
            record["manifest"] = str(manifest)
            record["manifest_sha256"] = _chunked_sha256(manifest)
        records.append(record)
    return records


def _sha256_text(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()
