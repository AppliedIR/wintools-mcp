"""Output file tracking and manifest generation."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_HASH_CHUNK_SIZE = 65536  # 64 KB


def _chunked_sha256(path: Path) -> str:
    """Compute SHA-256 without reading the entire file into memory."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_HASH_CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def to_share_relative(absolute_path: str, share_root: str) -> str:
    """Convert an absolute path to a share-relative path.

    If share_root is set and the path starts with it, strip the prefix.
    Otherwise return the path as-is (solo mode, no share).
    Normalizes backslashes to forward slashes.
    """
    if not share_root:
        return absolute_path.replace("\\", "/")
    # Normalize both paths for comparison
    norm_path = absolute_path.replace("\\", "/").rstrip("/")
    norm_root = share_root.replace("\\", "/").rstrip("/")
    if norm_path.startswith(norm_root + "/"):
        return norm_path[len(norm_root) + 1 :]
    if norm_path.lower().startswith(norm_root.lower() + "/"):
        return norm_path[len(norm_root) + 1 :]
    return absolute_path.replace("\\", "/")


def get_output_dir(working_dir: str, audit_id: str) -> Path:
    """Get the per-audit-ID output directory, creating it if needed."""
    out_dir = Path(working_dir) / "output" / audit_id
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.warning("Failed to create output directory %s: %s", out_dir, e)
    return out_dir


def build_manifest(output_dir: Path, base_url: str = "") -> list[dict[str, Any]]:
    """Build output file manifest for a directory.

    Returns list of file entries with path, size, sha256, and optional download_url.
    """
    if not output_dir.is_dir():
        return []

    manifest = []
    for f in sorted(output_dir.rglob("*")):
        if not f.is_file():
            continue
        try:
            file_size = f.stat().st_size
        except FileNotFoundError:
            logger.warning("File disappeared during manifest build: %s", f)
            continue
        except OSError as e:
            logger.warning("Failed to read file %s for manifest: %s", f, e)
            continue
        try:
            sha256 = _chunked_sha256(f)
        except OSError as e:
            logger.warning("Failed to hash file %s: %s", f, e)
            continue
        try:
            rel_path = f.relative_to(output_dir.parent.parent)
        except ValueError:
            rel_path = f.name
        entry: dict[str, Any] = {
            "path": str(rel_path).replace("\\", "/"),
            "size_bytes": file_size,
            "sha256": sha256,
            "description": f.stem.replace("_", " "),
        }
        if base_url:
            entry["download_url"] = (
                f"{base_url}/api/v1/files/download?path={entry['path']}"
            )
        manifest.append(entry)

    return manifest
