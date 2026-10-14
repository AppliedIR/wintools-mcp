"""Joined to SIFT, the case is the share: while a case is active, its folder
is the share root. After a re-join moves the share (`cases` to `vhir-cases`),
the case's paths follow it at the next start and at SIFT's next activation,
with no hand step. Standalone (no share root) keeps its own case folder."""

from __future__ import annotations

import os

import pytest
from starlette.testclient import TestClient

from wintools_mcp import server
from wintools_mcp.config import WintoolsConfig
from wintools_mcp.http_server import create_http_app

OLD = r"\\10.0.1.91\cases"
NEW = r"\\10.0.1.91\vhir-cases"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for var in ("VHIR_CASE_DIR", "VHIR_ACTIVE_CASE", "VHIR_SHARE_ROOT"):
        monkeypatch.delenv(var, raising=False)


def _rejoined(tmp_path):
    """config.yaml as a re-join leaves it: the new share, the old case folder."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        f"share_root: '{NEW}'\ncase_dir: '{OLD}'\nactive_case: CASE-1\n",
        encoding="utf-8",
    )
    return str(cfg)


def test_a_start_after_a_share_move_puts_the_case_on_the_new_share(tmp_path):
    cfg = WintoolsConfig.from_env(config_file=_rejoined(tmp_path))
    assert cfg.case_dir == NEW
    assert os.environ["VHIR_CASE_DIR"] == NEW  # the audit writer follows too


def test_the_share_info_names_every_case_path_on_the_new_share(tmp_path):
    cfg = WintoolsConfig.from_env(config_file=_rejoined(tmp_path))
    info = (
        server.create_server(cfg)
        ._tool_manager._tools["get_share_info"]
        .fn.__wrapped__()
    )
    for key in ("case_dir", "evidence_dir", "extractions_dir"):
        assert info[key].startswith(NEW), (key, info[key])


def test_sifts_next_activation_of_the_same_case_repairs_a_running_server(
    monkeypatch,
):
    from wintools_mcp import http_server

    cfg = WintoolsConfig()
    cfg.share_root, cfg.case_dir, cfg.active_case = NEW, OLD, "CASE-1"
    saved = {}
    monkeypatch.setattr(http_server, "get_config", lambda: cfg)
    monkeypatch.setattr(
        http_server, "_persist_config_fields", lambda c, fields: saved.update(fields)
    )
    with TestClient(
        create_http_app(WintoolsConfig()), raise_server_exceptions=False
    ) as c:
        r = c.post("/cases/activate", json={"case_id": "CASE-1"})
    assert r.json()["status"] == "activated" and r.json()["case_dir"] == NEW
    assert cfg.case_dir == NEW and saved["case_dir"] == NEW
    # once it's consistent, the 30 s re-sync is the no-op it was
    with TestClient(
        create_http_app(WintoolsConfig()), raise_server_exceptions=False
    ) as c:
        r = c.post("/cases/activate", json={"case_id": "CASE-1"})
    assert r.json()["status"] == "already_active"


def test_standalone_keeps_its_own_case_folder(tmp_path):
    case = tmp_path / "cases" / "INC-1"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: INC-1\n")
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(f"case_dir: '{case}'\nactive_case: INC-1\n", encoding="utf-8")
    cfg = WintoolsConfig.from_env(config_file=str(cfg_file))
    assert cfg.share_root == "" and cfg.case_dir == str(case)
