"""CSV output parser."""

import csv
import io
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_csv(text: str, *, max_rows: int = 1000) -> dict[str, Any]:
    """Parse CSV text into structured data.

    Returns: {"rows": [...], "total_rows": int, "truncated": bool, "columns": [...]}
    """
    if not text.strip():
        return {"rows": [], "total_rows": 0, "truncated": False, "columns": []}

    if max_rows < 1:
        max_rows = 1

    reader = csv.DictReader(io.StringIO(text))
    rows = []
    try:
        for i, row in enumerate(reader):
            if i >= max_rows:
                break
            rows.append(dict(row))
    except csv.Error as e:
        logger.warning("CSV parsing error after %d rows: %s", len(rows), e)

    total = len(rows)
    if len(rows) == max_rows:
        try:
            for _ in reader:
                total += 1
        except csv.Error:
            pass  # Already counted what we could

    columns = list(rows[0].keys()) if rows else list(reader.fieldnames or [])
    return {
        "rows": rows,
        "total_rows": total,
        "truncated": total > max_rows,
        "columns": list(columns),
    }


def parse_csv_file(file_path: str, *, max_rows: int = 1000) -> dict[str, Any]:
    """Parse a CSV file into structured data."""
    with open(file_path, "r", encoding="utf-8-sig") as f:
        text = f.read()
    return parse_csv(text, max_rows=max_rows)
