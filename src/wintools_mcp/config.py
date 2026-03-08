"""Configuration: env vars + optional YAML, examiner identity."""

from __future__ import annotations

import getpass
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


_EXAMINER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9\-]{0,19}$")


@dataclass
class WintoolsConfig:
    # Timeouts
    default_timeout: int = 600
    max_output_bytes: int = 52_428_800  # 50MB — subprocess capture limit
    response_byte_budget: int = 10_240  # 10KB — max bytes in MCP response

    # Paths
    tool_paths: list[Path] = field(default_factory=list)
    hayabusa_dir: Path = Path("C:\\Tools\\Hayabusa")
    catalog_dir: Path | None = None

    # AIR integration
    case_dir: str = ""
    active_case: str = ""  # Maps to case_id in audit entries
    examiner: str = ""  # Primary identity — set once at startup, immutable
    share_root: str = (
        ""  # SMB mount root (e.g., E:\cases\SRL2\) for share-relative paths
    )
    audit_dir: str = ""  # Local audit directory (default: AIIR_CASE_DIR/audit/)

    # HTTP mode
    http_host: str = "127.0.0.1"
    http_port: int = 4624
    api_keys: dict = field(default_factory=dict)

    # File transfer
    file_transfer_enabled: bool = True
    working_dir: str = ""  # Defaults to case_dir or C:\Cases
    max_upload_bytes: int = 2_147_483_648  # 2 GB

    @classmethod
    def from_env(cls, config_file: str | None = None) -> WintoolsConfig:
        cfg = cls()
        if config_file:
            cfg._load_yaml(config_file)

        # Env vars override YAML
        try:
            cfg.default_timeout = int(
                os.environ.get("WINTOOLS_TIMEOUT", str(cfg.default_timeout))
            )
        except ValueError:
            pass  # Keep YAML or default value
        cfg.case_dir = os.environ.get("AIIR_CASE_DIR", cfg.case_dir)
        cfg.active_case = os.environ.get("AIIR_ACTIVE_CASE", cfg.active_case)
        cfg.share_root = os.environ.get("AIIR_SHARE_ROOT", cfg.share_root)
        cfg.audit_dir = os.environ.get("AIIR_AUDIT_DIR", cfg.audit_dir)

        # Examiner identity: AIIR_EXAMINER > AIIR_ANALYST (deprecated) > OS username
        # Set once at startup, immutable for process lifetime.
        raw = os.environ.get("AIIR_EXAMINER") or os.environ.get("AIIR_ANALYST", "")
        if not raw:
            try:
                raw = getpass.getuser()
            except Exception:
                raw = "unknown"
        cfg.examiner = raw.lower().strip()

        # Validate examiner slug
        if not _EXAMINER_PATTERN.match(cfg.examiner):
            # Sanitize: keep only valid chars, truncate
            original = cfg.examiner
            sanitized = re.sub(r"[^a-z0-9\-]", "-", cfg.examiner).strip("-")[:20]
            cfg.examiner = sanitized or "unknown"
            logger.warning(
                "Examiner identity sanitized from %r to %r",
                original,
                cfg.examiner,
            )

        if os.environ.get("WINTOOLS_RESPONSE_BUDGET"):
            try:
                cfg.response_byte_budget = int(os.environ["WINTOOLS_RESPONSE_BUDGET"])
            except ValueError:
                pass

        if os.environ.get("WINTOOLS_MAX_OUTPUT"):
            try:
                cfg.max_output_bytes = int(os.environ["WINTOOLS_MAX_OUTPUT"])
            except ValueError:
                pass

        # HTTP config
        cfg.http_host = os.environ.get("WINTOOLS_HOST", cfg.http_host)
        try:
            port = int(os.environ.get("WINTOOLS_PORT", str(cfg.http_port)))
            if 1 <= port <= 65535:
                cfg.http_port = port
            else:
                logger.warning(
                    "WINTOOLS_PORT=%d out of range (1-65535), using default %d",
                    port,
                    cfg.http_port,
                )
        except ValueError:
            logger.warning(
                "Invalid WINTOOLS_PORT value, using default %d", cfg.http_port
            )

        # Tool paths
        extra = os.environ.get("WINTOOLS_TOOL_PATHS", "")
        if extra:
            for p in extra.split(os.pathsep):
                cfg.tool_paths.append(Path(p))

        return cfg

    def _load_yaml(self, path: str) -> None:
        p = Path(path)
        if not p.is_file():
            return
        try:
            with open(p, encoding="utf-8") as f:
                doc = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.warning("Failed to parse config file %s: %s", path, e)
            return
        except OSError as e:
            logger.warning("Failed to read config file %s: %s", path, e)
            return
        if not doc or not isinstance(doc, dict):
            logger.warning("Empty or invalid config file %s, skipping", path)
            return
        self.default_timeout = doc.get("default_timeout", self.default_timeout)
        self.max_output_bytes = doc.get("max_output_bytes", self.max_output_bytes)
        self.http_host = doc.get("http_host", self.http_host)
        port = doc.get("http_port", self.http_port)
        if isinstance(port, int) and 1 <= port <= 65535:
            self.http_port = port
        elif port != self.http_port:
            logger.warning(
                "Invalid port %r in config, using default %d", port, self.http_port
            )
        self.file_transfer_enabled = doc.get(
            "file_transfer_enabled", self.file_transfer_enabled
        )
        self.working_dir = doc.get("working_dir", self.working_dir)
        self.share_root = doc.get("share_root", self.share_root)
        self.audit_dir = doc.get("audit_dir", self.audit_dir)
        self.max_upload_bytes = doc.get("max_upload_bytes", self.max_upload_bytes)
        hayabusa = doc.get("hayabusa_dir")
        if hayabusa:
            self.hayabusa_dir = Path(hayabusa)
        catalog = doc.get("catalog_dir")
        if catalog:
            self.catalog_dir = Path(catalog)
        keys = doc.get("api_keys")
        if keys:
            self.api_keys = keys
        paths = doc.get("tool_paths", [])
        for p in paths:
            self.tool_paths.append(Path(p))


# Module-level singleton — initialized once, immutable after that
_config: WintoolsConfig | None = None


def get_config(config_file: str | None = None) -> WintoolsConfig:
    global _config
    if _config is None:
        _config = WintoolsConfig.from_env(config_file)
    return _config


def reset_config() -> None:
    """Reset singleton — for testing only."""
    global _config
    _config = None
