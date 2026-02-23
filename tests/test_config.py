"""Tests for config module."""

import os
import pytest
from wintools_mcp.config import WintoolsConfig, get_config, reset_config


class TestWintoolsConfig:

    def test_defaults(self):
        cfg = WintoolsConfig()
        assert cfg.default_timeout == 600
        assert cfg.max_output_bytes == 52_428_800
        assert cfg.response_byte_budget == 10_240
        assert cfg.http_port == 4624
        assert cfg.file_transfer_enabled is True

    def test_from_env_examiner_primary(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "Jane")
        cfg = WintoolsConfig.from_env()
        assert cfg.examiner == "jane"  # lowercased

    def test_from_env_examiner_fallback_analyst(self, monkeypatch):
        monkeypatch.delenv("AIIR_EXAMINER", raising=False)
        monkeypatch.setenv("AIIR_ANALYST", "Steve")
        cfg = WintoolsConfig.from_env()
        assert cfg.examiner == "steve"

    def test_from_env_examiner_fallback_os_user(self, monkeypatch):
        monkeypatch.delenv("AIIR_EXAMINER", raising=False)
        monkeypatch.delenv("AIIR_ANALYST", raising=False)
        cfg = WintoolsConfig.from_env()
        assert cfg.examiner  # Should be something (OS username)
        assert cfg.examiner == cfg.examiner.lower()

    def test_examiner_sanitization(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "Jane@Company!")
        cfg = WintoolsConfig.from_env()
        # Only lowercase alphanumeric + hyphens
        assert all(c.isalnum() or c == "-" for c in cfg.examiner)

    def test_case_dir_from_env(self, monkeypatch):
        monkeypatch.setenv("AIIR_CASE_DIR", "C:\\Cases\\INC-001")
        cfg = WintoolsConfig.from_env()
        assert cfg.case_dir == "C:\\Cases\\INC-001"

    def test_active_case_from_env(self, monkeypatch):
        monkeypatch.setenv("AIIR_ACTIVE_CASE", "INC-2026-001")
        cfg = WintoolsConfig.from_env()
        assert cfg.active_case == "INC-2026-001"

    def test_timeout_from_env(self, monkeypatch):
        monkeypatch.setenv("WINTOOLS_TIMEOUT", "120")
        cfg = WintoolsConfig.from_env()
        assert cfg.default_timeout == 120

    def test_http_config_from_env(self, monkeypatch):
        monkeypatch.setenv("WINTOOLS_HOST", "0.0.0.0")
        monkeypatch.setenv("WINTOOLS_PORT", "9000")
        cfg = WintoolsConfig.from_env()
        assert cfg.http_host == "0.0.0.0"
        assert cfg.http_port == 9000

    def test_yaml_config(self, tmp_path):
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text(
            "default_timeout: 120\n"
            "http_port: 9000\n"
            "hayabusa_dir: D:\\Tools\\Hayabusa\n"
        )
        cfg = WintoolsConfig.from_env(config_file=str(yaml_file))
        assert cfg.default_timeout == 120
        assert cfg.http_port == 9000

    def test_share_root_from_env(self, monkeypatch):
        monkeypatch.setenv("AIIR_SHARE_ROOT", "E:\\cases\\SRL2")
        cfg = WintoolsConfig.from_env()
        assert cfg.share_root == "E:\\cases\\SRL2"

    def test_audit_dir_from_env(self, monkeypatch):
        monkeypatch.setenv("AIIR_AUDIT_DIR", "C:\\Users\\jane\\AppData\\Local\\aiir\\audit")
        cfg = WintoolsConfig.from_env()
        assert cfg.audit_dir == "C:\\Users\\jane\\AppData\\Local\\aiir\\audit"

    def test_share_root_from_yaml(self, tmp_path):
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text(
            "share_root: E:\\cases\\SRL2\n"
            "audit_dir: C:\\local\\audit\n"
        )
        cfg = WintoolsConfig.from_env(config_file=str(yaml_file))
        assert cfg.share_root == "E:\\cases\\SRL2"
        assert cfg.audit_dir == "C:\\local\\audit"

    def test_share_root_defaults_empty(self):
        cfg = WintoolsConfig()
        assert cfg.share_root == ""
        assert cfg.audit_dir == ""

    def test_singleton(self, monkeypatch):
        monkeypatch.setenv("AIIR_EXAMINER", "singleton-test")
        cfg1 = get_config()
        cfg2 = get_config()
        assert cfg1 is cfg2
        assert cfg1.examiner == "singleton-test"
