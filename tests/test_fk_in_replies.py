"""What forensic-knowledge content a reply carries, and the recipes a tool's
help gives.

- A run whose tool ran gets the tool's caveats and field meanings every time,
  and the discovery content (advisories, corroboration, field notes, cross-MCP
  checks) on its first three runs and every tenth.
- A run whose tool showed a screen in place of running gets no FK content and
  does not count toward that decay.
- The file that ran and its version ride in the reply's metadata; an exit
  code is the bare code.
- A tool's help gives the recipes checked on its installed version, the rest
  with the versions they were checked on, and says when none was checked on
  it.

FK is a stub here: CI installs no forensic-knowledge.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest
from test_batch_scan import _files, case  # noqa: F401 - fixtures
from test_eula_surrogate import NAMED, _sent, _tool, tools  # noqa: F401 - fixtures

from wintools_mcp import response, versions
from wintools_mcp.response import build_response
from wintools_mcp.tools import discovery

DUP_ADVISORY = "This artifact does NOT prove: execution"

TOOLS = {
    "PECmd": {
        "caveats": ["run counts cap at 8"],
        "advisories": ["read the volume info", DUP_ADVISORY],
        "field_meanings": {"LastRun": "the last of up to 8 run times"},
        "artifacts_parsed": ["prefetch", "amcache", "missing", "listed"],
        "exit_code_hints": {1: "no files found"},
    },
}
ARTIFACTS = {
    "prefetch": {
        "does_not_prove": ["execution", "who ran it"],
        "corroborate_with": {"execution": ["amcache", "amcache", "shimcache"]},
        "timestamps": [
            {"field": "LastRun", "meaning": "the last run"},
            {"field": "no meaning"},
            "a bare string",
        ],
        "common_misinterpretations": [
            {"claim": "a run count is every run", "correction": "it caps"},
            {"claim": "no correction"},
            "a bare string",
        ],
        "cross_mcp_checks": [{"mcp": "sift-mcp", "tool": "x", "when": "always"}],
    },
    "amcache": {
        "does_not_prove": ["who ran it", "run time"],
        "corroborate_with": {
            "execution": ["shimcache", "prefetch"],
            "presence": ["mft"],
        },
        "timestamps": [{"field": "KeyLastWrite", "meaning": "any write to the key"}],
        "common_misinterpretations": [
            {"claim": "a run count is every run", "correction": "it caps"},
        ],
        "cross_mcp_checks": [
            {"mcp": "sift-mcp", "tool": "x", "when": "always"},
            {"mcp": "windows-triage-mcp", "tool": "check_file", "when": "a path"},
        ],
    },
    "listed": ["not", "a", "dict"],
}

DISCOVERY = ("advisories", "corroboration", "field_notes", "cross_mcp_checks")
ACCURACY = ("caveats", "field_meanings")


@pytest.fixture
def fk(monkeypatch):
    calls = []

    def get_tool(name):
        calls.append(name)
        return TOOLS.get(name)

    loader = SimpleNamespace(get_tool=get_tool, get_artifact=ARTIFACTS.get)
    monkeypatch.setattr(response, "fk_loader", loader)
    return calls


def _reply(tool_ran=True, **kw):
    return build_response(
        tool_name="run_windows_command",
        success=True,
        data={},
        audit_id="win-testuser-20261016-001",
        fk_tool_name=kw.pop("fk_tool_name", "PECmd"),
        tool_ran=tool_ran,
        **kw,
    )


def test_a_run_whose_tool_ran_gets_its_tools_knowledge(fk, examiner):
    r = _reply()
    assert r["caveats"] == ["run counts cap at 8"]
    assert r["field_meanings"] == {"LastRun": "the last of up to 8 run times"}
    assert r["advisories"] == [
        "read the volume info",
        DUP_ADVISORY,
        "This artifact does NOT prove: who ran it",
        "a run count is every run → it caps",
        "This artifact does NOT prove: run time",
    ]
    assert r["corroboration"] == {
        "execution": ["amcache", "shimcache", "prefetch"],
        "presence": ["mft"],
    }
    assert r["field_notes"] == {
        "LastRun": "the last run",
        "KeyLastWrite": "any write to the key",
    }
    assert r["cross_mcp_checks"] == [
        {"mcp": "sift-mcp", "tool": "x", "when": "always"},
        {"mcp": "windows-triage-mcp", "tool": "check_file", "when": "a path"},
    ]


def test_the_tools_own_lists_are_not_changed_by_a_reply(fk, examiner):
    before = {k: list(v) for k, v in TOOLS["PECmd"].items() if isinstance(v, list)}
    _reply()
    _reply()
    after = {k: list(v) for k, v in TOOLS["PECmd"].items() if isinstance(v, list)}
    assert after == before


def test_a_run_whose_tool_did_not_run_gets_no_knowledge_and_no_count(fk, examiner):
    for _ in range(5):
        r = _reply(tool_ran=False)
        assert not set(r) & set(ACCURACY + DISCOVERY), r
    assert fk == [] and response._fk_delivery_counts.get("PECmd", 0) == 0
    # the runs that follow are still the tool's first three
    for _ in range(3):
        assert set(DISCOVERY) <= set(_reply())
    assert response._fk_delivery_counts["PECmd"] == 3


def test_discovery_content_decays_after_three_runs_and_returns_every_tenth(
    fk, examiner
):
    seen = []
    for n in range(1, 21):
        r = _reply()
        assert set(ACCURACY) <= set(r), n
        if set(DISCOVERY) <= set(r):
            seen.append(n)
        else:
            assert not set(DISCOVERY) & set(r), (n, r)
    assert seen == [1, 2, 3, 10, 20]


def test_a_screen_between_runs_does_not_move_the_tenth(fk, examiner):
    seen = []
    for n in range(1, 11):
        _reply(tool_ran=False)
        if "advisories" in _reply():
            seen.append(n)
    assert seen == [1, 2, 3, 10]


def test_each_tool_decays_on_its_own_count(fk, examiner):
    TOOLS["EvtxECmd"] = {"advisories": ["one"]}
    try:
        for _ in range(4):
            _reply()
        assert "advisories" not in _reply()
        assert _reply(fk_tool_name="EvtxECmd")["advisories"] == ["one"]
    finally:
        del TOOLS["EvtxECmd"]


def test_a_failing_knowledge_lookup_gives_none_and_says_so(
    fk, examiner, monkeypatch, caplog
):
    def boom(name):
        raise RuntimeError("bad yaml")

    monkeypatch.setattr(response.fk_loader, "get_tool", boom)
    with caplog.at_level(logging.WARNING, logger="wintools_mcp.response"):
        r = _reply()
    assert not set(r) & set(ACCURACY + DISCOVERY), r
    assert "FK enrichment failed for PECmd: bad yaml" in caplog.text
    assert response._fk_delivery_counts["PECmd"] == 1


@pytest.mark.parametrize("info", [None, "a string", ["a", "list"], {}])
def test_a_tool_without_usable_knowledge_gets_none(fk, examiner, monkeypatch, info):
    monkeypatch.setattr(response.fk_loader, "get_tool", lambda name: info)
    r = _reply()
    assert not set(r) & set(ACCURACY + DISCOVERY), r


def test_no_knowledge_package_gives_none(examiner, monkeypatch):
    monkeypatch.setattr(response, "fk_loader", None)
    r = _reply()
    assert not set(r) & set(ACCURACY + DISCOVERY), r


def test_an_exit_code_is_the_bare_code_with_no_meaning(fk, examiner):
    r = _reply(exit_code=1, elapsed_seconds=1.234, command=["PECmd.exe", "-d", "x"])
    assert r["metadata"] == {
        "exit_code": 1,
        "elapsed_seconds": 1.23,
        "command": ["PECmd.exe", "-d", "x"],
    }


@pytest.mark.parametrize("tool_ran", [True, False])
def test_the_file_that_ran_and_its_version_are_in_the_metadata(examiner, tool_ran):
    ran = {"tool_version": "1.5.0.0", "resolved_path": r"C:\Tools\PECmd.exe"}
    r = _reply(tool_ran=tool_ran, tool_version=ran, exit_code=0)
    assert r["metadata"] == {"exit_code": 0, **ran}


def test_a_reply_with_no_version_and_no_run_details_has_no_metadata(examiner):
    assert "metadata" not in _reply(tool_version=None)
    assert "metadata" not in _reply(tool_version={})


# --- the recipes a tool's help gives -----------------------------------------------

RECIPES = [
    {"argv": ["csv-timeline"], "versions": ">=3.9,<4"},
    {"argv": ["dfir-timeline"], "versions": ">=4.1,<5"},
]


def _td(recipes, name="tool"):
    return SimpleNamespace(name=name, recipes=recipes)


def test_a_version_every_recipe_was_checked_on_lists_no_others():
    one = [{"argv": ["csv-timeline"], "versions": ">=3.9,<4"}]
    assert discovery._recipes(_td(one), "3.9.2") == {"recipes": one}


def test_the_installed_versions_recipe_and_the_others_with_their_range():
    r = discovery._recipes(_td(RECIPES), "4.1.0")
    assert r == {
        "recipes": [RECIPES[1]],
        "recipes_other_versions": [{**RECIPES[0], "note": "tested on >=3.9,<4 only"}],
    }


@pytest.mark.parametrize(
    "version,named",
    [("9.0.0", "tool 9.0.0"),
     ("", "tool of an unknown version"),
     (versions.UNKNOWN, "tool of an unknown version")],
)  # fmt: skip
def test_a_version_no_recipe_was_checked_on_is_said(version, named):
    r = discovery._recipes(_td(RECIPES), version)
    assert r["recipes"] == [] and len(r["recipes_other_versions"]) == 2
    assert r["no_recipe"] == (
        f"No recipe for {named}; tested on >=3.9,<4, >=4.1,<5. Use the tool's own help."
    )


def test_a_recipe_without_a_range_is_named_as_such():
    bare = [{"argv": ["x"]}]
    r = discovery._recipes(_td(bare), "1.0")
    assert r["recipes_other_versions"] == [{"argv": ["x"], "note": "tested on ? only"}]
    assert "tested on ?." in r["no_recipe"]


def test_a_tool_with_no_recipes_gets_no_recipe_keys():
    assert discovery._recipes(_td([]), "1.0") == {}


def test_help_for_a_tool_not_installed_names_no_version_and_its_recipes(monkeypatch):
    monkeypatch.setattr(discovery, "tool_path", lambda td: None)
    r = discovery.get_tool_help("hayabusa")
    assert r["available"] is False
    assert not {"path", "installed_version", "resolved_path"} & set(r), r
    assert r["recipes"] == [] and len(r["recipes_other_versions"]) >= 2
    assert r["no_recipe"].startswith("No recipe for hayabusa of an unknown version")


def test_help_for_a_tool_not_in_the_catalog_says_so():
    assert discovery.get_tool_help("no-such-tool") == {
        "error": "Tool 'no-such-tool' not found in catalog"
    }


def test_a_script_tool_names_the_copy_that_runs_and_lists_no_other_copies(monkeypatch):
    """A script runs under its interpreter, so other copies of the script on
    the PATH are not listed (only an executable's are)."""
    looked = []
    monkeypatch.setattr(discovery, "tool_path", lambda td: r"C:\Perl\mactime.pl")
    monkeypatch.setattr(
        discovery, "tool_copies", lambda b: looked.append(b) or ["a", "b"]
    )
    monkeypatch.setattr(
        versions, "tool_version", lambda p, td=None: {"tool_version": "4.12"}
    )
    r = discovery.check_tools(["mactime"])["mactime"]
    assert r["installed_version"] == "4.12"
    assert r["resolved_path"] == r"C:\Perl\mactime.pl"
    assert "copies" not in r and looked == []


def test_a_tool_not_installed_is_checked_with_no_version(monkeypatch):
    monkeypatch.setattr(discovery, "tool_path", lambda td: None)
    r = discovery.check_tools(["hayabusa"])
    assert r == {
        "hayabusa": {"binary": "hayabusa.exe", "available": False, "path": None}
    }


# --- the caller: run_windows_command passes tool_ran=not eula -------------------------


def test_a_run_that_showed_the_eula_screen_gets_no_knowledge_and_no_count(
    case,  # noqa: F811
    tools,  # noqa: F811
    monkeypatch,
):
    asked = []

    def get_tool(name):
        asked.append(name)
        return {"caveats": ["c"], "advisories": ["a"]}

    loader = SimpleNamespace(get_tool=get_tool, get_artifact=lambda name: None)
    monkeypatch.setattr(response, "fk_loader", loader)
    target = _files(case / "evidence" / "fk", ["a.exe"]) / "a.exe"
    rwc = _tool("run_windows_command")
    tools["screen"] = True
    for _ in range(5):
        r = _sent(rwc(command=["sigcheck", str(target)], purpose="check"))
        assert r["success"] is False and NAMED in r["error"], r
        assert not {"caveats", "advisories"} & set(r), r
    assert asked == [] and not any(response._fk_delivery_counts.values())
    tools["screen"] = False
    r = _sent(rwc(command=["sigcheck", str(target)], purpose="check"))
    assert r["success"] is True and (r["caveats"], r["advisories"]) == (["c"], ["a"])
    assert len(asked) == 1 and response._fk_delivery_counts[asked[0]] == 1
