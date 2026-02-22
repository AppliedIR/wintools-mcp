"""CSV output parser."""

import csv
import io
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

MAX_CSV_BYTES = 50_000_000  # 50 MB — refuse to read larger files into memory


def parse_csv(text: str, *, max_rows: int = 1000) -> dict[str, Any]:
    """Parse CSV text into structured data.

    Returns: {"rows": [...], "total_rows": int, "truncated": bool, "columns": [...]}
    """
    if not text.strip():
        return {"rows": [], "total_rows": 0, "truncated": False, "columns": []}

    if max_rows < 1:
        max_rows = 1

    reader = csv.DictReader(io.StringIO(text))

    if reader.fieldnames is None:
        logger.warning("CSV has no header row; returning empty result")
        return {"rows": [], "total_rows": 0, "truncated": False, "columns": []}

    rows = []
    try:
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            rows.append(dict(row))
    except csv.Error as e:
        logger.warning("CSV parsing error after %d rows: %s", len(rows), e)
        if not rows:
            return {
                "rows": [],
                "total_rows": 0,
                "truncated": False,
                "columns": list(reader.fieldnames or []),
                "parse_error": str(e),
            }

    total = len(rows)
    if len(rows) == max_rows:
        try:
            for _ in reader:
                total += 1
        except csv.Error as e:
            logger.warning("CSV error while counting remaining rows: %s", e)

    columns = list(rows[0].keys()) if rows else list(reader.fieldnames or [])
    return {
        "rows": rows,
        "total_rows": total,
        "truncated": total > max_rows,
        "columns": list(columns),
    }


def parse_csv_file(file_path: str, *, max_rows: int = 1000) -> dict[str, Any]:
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

    return parse_csv(text, max_rows=max_rows)
