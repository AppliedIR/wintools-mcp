"""Output file tracking and manifest generation."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def get_output_dir(working_dir: str, evidence_id: str) -> Path:
    """Get the per-evidence-ID output directory, creating it if needed."""
    out_dir = Path(working_dir) / "output" / evidence_id
    out_dir.mkdir(parents=True, exist_ok=True)
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
        rel_path = f.relative_to(output_dir.parent.parent)  # relative to working_dir
        sha256 = hashlib.sha256(f.read_bytes()).hexdigest()
        entry: dict[str, Any] = {
            "path": str(rel_path).replace("\\", "/"),
            "size_bytes": f.stat().st_size,
            "sha256": sha256,
            "description": f.stem.replace("_", " "),
        }
        if base_url:
            entry["download_url"] = (
                f"{base_url}/api/v1/files/download?path={entry['path']}"
            )
        manifest.append(entry)

    return manifest
