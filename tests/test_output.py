"""Tests for output file tracking and manifest generation."""

from wintools_mcp.output import build_manifest, get_output_dir, to_share_relative


class TestOutputDir:
    def test_creates_evidence_dir(self, tmp_path):
        out = get_output_dir(str(tmp_path), "win-jane-20260220-001")
        assert out.exists()
        assert out.name == "win-jane-20260220-001"
        assert out.parent.name == "output"

    def test_idempotent(self, tmp_path):
        out1 = get_output_dir(str(tmp_path), "win-jane-20260220-001")
        out2 = get_output_dir(str(tmp_path), "win-jane-20260220-001")
        assert out1 == out2


class TestManifest:
    def test_empty_dir(self, tmp_path):
        out_dir = tmp_path / "output" / "test"
        out_dir.mkdir(parents=True)
        manifest = build_manifest(out_dir)
        assert manifest == []

    def test_manifest_with_files(self, tmp_path):
        working = tmp_path
        out_dir = working / "output" / "win-jane-20260220-001"
        out_dir.mkdir(parents=True)
        (out_dir / "result.csv").write_text("col1,col2\na,b\n")
        (out_dir / "summary.txt").write_text("summary data")

        manifest = build_manifest(out_dir)
        assert len(manifest) == 2
        paths = [m["path"] for m in manifest]
        assert any("result.csv" in p for p in paths)
        assert all("sha256" in m for m in manifest)
        assert all("size_bytes" in m for m in manifest)

    def test_manifest_with_download_urls(self, tmp_path):
        out_dir = tmp_path / "output" / "win-jane-20260220-001"
        out_dir.mkdir(parents=True)
        (out_dir / "test.csv").write_text("data")

        manifest = build_manifest(out_dir, base_url="http://localhost:4624")
        assert manifest[0]["download_url"].startswith(
            "http://localhost:4624/api/v1/files/download"
        )

    def test_nonexistent_dir(self, tmp_path):
        manifest = build_manifest(tmp_path / "nonexistent")
        assert manifest == []


class TestShareRelative:
    def test_strips_share_root(self):
        result = to_share_relative(
            "E:\\cases\\SRL2\\extractions\\output.csv",
            "E:\\cases\\SRL2",
        )
        assert result == "extractions/output.csv"

    def test_strips_share_root_forward_slashes(self):
        result = to_share_relative(
            "E:/cases/SRL2/extractions/output.csv",
            "E:/cases/SRL2",
        )
        assert result == "extractions/output.csv"

    def test_no_share_root_returns_normalized(self):
        result = to_share_relative(
            "E:\\cases\\SRL2\\extractions\\output.csv",
            "",
        )
        assert result == "E:/cases/SRL2/extractions/output.csv"

    def test_case_insensitive_match(self):
        result = to_share_relative(
            "e:\\Cases\\SRL2\\extractions\\output.csv",
            "E:\\cases\\SRL2",
        )
        assert result == "extractions/output.csv"

    def test_no_match_returns_normalized(self):
        result = to_share_relative(
            "D:\\other\\path\\file.csv",
            "E:\\cases\\SRL2",
        )
        assert result == "D:/other/path/file.csv"

    def test_trailing_slash_handling(self):
        result = to_share_relative(
            "E:\\cases\\SRL2\\extractions\\output.csv",
            "E:\\cases\\SRL2\\",
        )
        assert result == "extractions/output.csv"
