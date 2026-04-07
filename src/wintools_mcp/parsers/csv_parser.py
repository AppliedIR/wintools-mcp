"""CSV output parser."""

import csv
import io
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

MAX_CSV_BYTES = 50_000_000  # 50 MB — refuse to read larger files into memory


def _clean_row(row: dict) -> dict[str, str]:
    """Normalize a csv.DictReader row: drop restkey lists, stringify values."""
    cleaned: dict[str, str] = {}
    for k, v in row.items():
        if k is None:
            continue
        if isinstance(v, list):
            cleaned[k] = ", ".join(str(i) for i in v)
        elif v is None:
            cleaned[k] = ""
        else:
            cleaned[k] = str(v)
    return cleaned


def parse_csv(
    text: str, *, max_rows: int = 10000, byte_budget: int = 0
) -> dict[str, Any]:
    """Parse CSV text into structured data.

    Args:
        text: Raw CSV text.
        max_rows: Maximum rows to return (secondary safety limit).
        byte_budget: If > 0, fill complete rows until budget exhausted.

    Returns: {"rows": [...], "total_rows": int, "truncated": bool, "columns": [...]}
    """
    if not text.strip():
        return {
            "rows": [],
            "total_rows": 0,
            "truncated": False,
            "columns": [],
            "preview_rows": 0,
            "preview_bytes": 0,
        }

    if max_rows < 1:
        max_rows = 1

    try:
        reader = csv.DictReader(io.StringIO(text))
        fieldnames = reader.fieldnames
    except csv.Error as e:
        logger.warning("CSV header parsing error: %s", e)
        return {
            "rows": [],
            "total_rows": 0,
            "truncated": False,
            "columns": [],
            "preview_rows": 0,
            "preview_bytes": 0,
            "parse_error": str(e),
        }

    if fieldnames is None:
        logger.warning("CSV has no header row; returning empty result")
        return {
            "rows": [],
            "total_rows": 0,
            "truncated": False,
            "columns": [],
            "preview_rows": 0,
            "preview_bytes": 0,
        }

    rows = []
    used_bytes = 0
    budget_hit = False
    total_offset = 0
    parse_error = None
    try:
        for row in reader:
            if max_rows and len(rows) >= max_rows:
                break
            row_dict = _clean_row(dict(row))
            if byte_budget:
                row_bytes = (
                    sum(
                        len(v.encode("utf-8", errors="replace"))
                        for v in row_dict.values()
                    )
                    + len(row_dict) * 4
                )
                if used_bytes + row_bytes > byte_budget and rows:
                    budget_hit = True
                    total_offset = 1  # count the row we're skipping
                    break
                used_bytes += row_bytes
            rows.append(row_dict)
    except csv.Error as e:
        logger.warning("CSV parsing error after %d rows: %s", len(rows), e)
        parse_error = str(e)

    total = len(rows) + total_offset
    if budget_hit or len(rows) == max_rows:
        try:
            for _ in reader:
                total += 1
        except csv.Error as e:
            logger.warning("CSV error while counting remaining rows: %s", e)

    columns = list(rows[0].keys()) if rows else list(fieldnames or [])
    result: dict[str, Any] = {
        "rows": rows,
        "total_rows": total,
        "preview_rows": len(rows),
        "preview_bytes": used_bytes,
        "truncated": total > len(rows),
        "columns": list(columns),
    }
    if parse_error:
        result["parse_error"] = parse_error
    return result


def parse_csv_file(
    file_path: str, *, max_rows: int = 10000, byte_budget: int = 0
) -> dict[str, Any]:
    """Parse a CSV file into structured data."""
    # Check file size before reading to prevent OOM on large files
    try:
        file_size = os.path.getsize(file_path)
    except OSError as e:
        return {"error": f"Failed to read CSV file: {e}", "rows": [], "total_rows": 0}

    if file_size > MAX_CSV_BYTES:
        return {
            "error": f"CSV file too large ({file_size:,} bytes, max {MAX_CSV_BYTES:,})",
            "rows": [],
            "total_rows": 0,
        }

    try:
        with open(file_path, encoding="utf-8-sig", errors="replace") as f:
            text = f.read()
    except OSError as e:
        return {"error": f"Failed to read CSV file: {e}", "rows": [], "total_rows": 0}

    return parse_csv(text, max_rows=max_rows, byte_budget=byte_budget)
