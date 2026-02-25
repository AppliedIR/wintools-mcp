"""Tests for output parsers."""

import json

from wintools_mcp.parsers.csv_parser import parse_csv, parse_csv_file
from wintools_mcp.parsers.json_parser import parse_json, parse_jsonl
from wintools_mcp.parsers.text_parser import extract_lines, parse_text


class TestCsvParser:
    def test_parse_csv(self):
        text = "name,value\nfoo,1\nbar,2\n"
        result = parse_csv(text)
        assert result["total_rows"] == 2
        assert result["columns"] == ["name", "value"]
        assert result["rows"][0]["name"] == "foo"
        assert result["truncated"] is False

    def test_parse_csv_empty(self):
        result = parse_csv("")
        assert result["rows"] == []
        assert result["total_rows"] == 0

    def test_parse_csv_truncation(self):
        rows = "name,value\n" + "\n".join(f"row{i},{i}" for i in range(2000))
        result = parse_csv(rows, max_rows=100)
        assert len(result["rows"]) == 100
        assert result["truncated"] is True

    def test_parse_csv_file(self, tmp_path):
        csv_file = tmp_path / "test.csv"
        csv_file.write_text("col1,col2\na,1\nb,2\n", encoding="utf-8")
        result = parse_csv_file(str(csv_file))
        assert result["total_rows"] == 2


class TestJsonParser:
    def test_parse_json_object(self):
        result = parse_json('{"key": "value"}')
        assert result["data"] == {"key": "value"}
        assert result["total_entries"] == 1

    def test_parse_json_array(self):
        result = parse_json('[{"a": 1}, {"a": 2}]')
        assert result["total_entries"] == 2
        assert len(result["data"]) == 2

    def test_parse_json_empty(self):
        result = parse_json("")
        assert result["data"] is None

    def test_parse_jsonl(self):
        text = '{"a": 1}\n{"a": 2}\n{"a": 3}\n'
        result = parse_jsonl(text)
        assert result["total_entries"] == 3
        assert len(result["data"]) == 3

    def test_parse_jsonl_truncation(self):
        lines = "\n".join(json.dumps({"i": i}) for i in range(2000))
        result = parse_jsonl(lines, max_entries=100)
        assert len(result["data"]) == 100
        assert result["truncated"] is True


class TestTextParser:
    def test_parse_text(self):
        result = parse_text("line1\nline2\nline3\n")
        assert result["total_lines"] == 4  # includes trailing empty
        assert len(result["lines"]) == 4
        assert result["truncated"] is False

    def test_parse_text_truncation(self):
        text = "\n".join(f"line{i}" for i in range(1000))
        result = parse_text(text, max_lines=50)
        assert len(result["lines"]) == 50
        assert result["truncated"] is True

    def test_extract_lines(self):
        text = "\n".join(f"line{i}" for i in range(100))
        lines = extract_lines(text, start=10, count=5)
        assert len(lines) == 5
        assert lines[0] == "line10"
