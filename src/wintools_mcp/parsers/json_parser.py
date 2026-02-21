"""JSON/JSONL output parser."""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_json(text: str, *, max_entries: int = 1000) -> dict[str, Any]:
    """Parse JSON text into structured data.

    Returns: {"data": parsed, "total_entries": int, "truncated": bool}
    """
    if not text.strip():
        return {"data": None, "total_entries": 0, "truncated": False}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        logger.warning("JSON parse error: %s", e)
        return {"data": {"_raw": text[:2000]}, "total_entries": 1, "truncated": False, "parse_error": str(e)}
    if isinstance(parsed, list):
        total = len(parsed)
        return {
            "data": parsed[:max_entries],
            "total_entries": total,
            "truncated": total > max_entries,
        }
    return {"data": parsed, "total_entries": 1, "truncated": False}


def parse_jsonl(text: str, *, max_entries: int = 1000) -> dict[str, Any]:
    """Parse JSONL text into structured data.

    Returns: {"data": [...], "total_entries": int, "truncated": bool}
    """
    entries = []
    total = 0
    for line in text.strip().split("\n"):
        if not line.strip():
            continue
        total += 1
        if total <= max_entries:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                entries.append({"_raw": line})
    return {
        "data": entries,
        "total_entries": total,
        "truncated": total > max_entries,
    }
