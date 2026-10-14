"""The catalog's recipes are tested calls, each tagged with the versions it
was checked on, and each flag in one is in that version's own help.

- Every recipe's subcommand and flags appear in the help text of a version
  in its range, kept under tests/fixtures/tool_help/<tool>/<version>/ (the
  tool's own output). A flag a help doesn't show fails here, by name.
- get_windows_tool_help gives the recipes for the installed version, lists
  the rest as "tested on <range> only", and says when no recipe was checked
  on the installed version (Hayabusa 4.x against 3.x recipes).
- A range is a comma list of >=, >, <=, <, ==; an unreadable version is in
  none.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from wintools_mcp import environment, versions
from wintools_mcp import server as srv
from wintools_mcp.catalog import load_catalog, version_in

FIXTURES = Path(__file__).parent / "fixtures" / "tool_help"


def _helps(tool: str) -> dict[str, str]:
    """{version: all of that version's help text} for a tool."""
    out = {}
    for d in sorted((FIXTURES / tool).glob("*")) if (FIXTURES / tool).is_dir() else []:
        out[d.name] = "\n".join(f.read_text() for f in sorted(d.glob("*.txt")))
    return out


def _named(recipe: dict) -> list[str]:
    """What the help must show: its subcommand (a first word that isn't a
    flag or a <placeholder>) and every flag."""
    argv = [str(a) for a in recipe["argv"]]
    words = [a for a in argv if a.startswith("-")]
    if argv and not argv[0].startswith(("-", "<")):
        words.insert(0, argv[0])
    return words


def _missing(recipe: dict, text: str) -> list[str]:
    return [
        w for w in _named(recipe)
        if not re.search(rf"(?<![\w-]){re.escape(w)}(?![\w-])", text)
    ]  # fmt: skip


RECIPES = [
    (td.name, i, r) for td in load_catalog().values() for i, r in enumerate(td.recipes)
]


@pytest.mark.parametrize(
    "tool, i, recipe", RECIPES, ids=[f"{t}-{i}" for t, i, _ in RECIPES]
)
def test_every_recipe_flag_is_in_its_versions_own_help(tool, i, recipe):
    helps = {v: t for v, t in _helps(tool).items() if version_in(v, recipe["versions"])}
    assert helps, f"{tool} recipe {i}: no help fixture for {recipe['versions']}"
    for version, text in helps.items():
        assert _missing(recipe, text) == [], f"{tool} {version}: {recipe['argv']}"


def test_a_flag_the_help_doesnt_show_is_named():
    (recipe,) = [
        r
        for r in load_catalog()["hayabusa"].recipes
        if "-U" in r["argv"] and r["versions"] == ">=3.9,<4"
    ]
    text = _helps("hayabusa")["3.9.0"]
    cut = "\n".join(line for line in text.splitlines() if "--UTC" not in line)
    assert _missing(recipe, cut) == ["-U"]


@pytest.mark.parametrize(
    "version, versions_, inside",
    [("3.9.0", ">=3.9,<4", True), ("4.1.0", ">=3.9,<4", False),
     ("v4.2.0", ">=4.0,<5", True), ("1.5.0.0", ">=1.5,<2", True),
     ("2026.5.0.0", ">=1.5,<2", False), ("unknown", ">=3.9,<4", False),
     ("14.3", "==14.3", True), ("4.2.0", "", False), ("4.2.0", " , ", False),
     ("4.0.0-rc1", ">=4.0", False), ("4.0.0-rc1", "<4.0", True),
     ("4.0.0", ">=4.0", True)],
)  # fmt: skip
def test_a_version_range(version, versions_, inside):
    assert version_in(version, versions_) is inside


@pytest.fixture
def hayabusa_at(tmp_path, monkeypatch):
    exe = tmp_path / "hayabusa.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(environment, "find_tool", lambda name: str(exe))
    monkeypatch.setattr("wintools_mcp.tools.discovery.tool_path", lambda td: str(exe))
    monkeypatch.setattr(
        "wintools_mcp.tools.discovery.tool_copies", lambda b: [str(exe)]
    )
    monkeypatch.setattr(versions, "run_probe", lambda argv: "Usage: hayabusa.exe\n")

    def at(version):
        monkeypatch.setattr(versions, "file_version", lambda p: version)
        versions.clear()
        fn = (
            srv.create_server()
            ._tool_manager._tools["get_windows_tool_help"]
            .fn.__wrapped__
        )
        return fn(tool_name="hayabusa")

    return at


def test_the_installed_versions_recipes_are_given(hayabusa_at):
    """3.x gets csv-timeline; 4.x gets dfir-timeline; each lists the other's
    as tested on its range only."""
    r = hayabusa_at("3.9.0")
    assert {x["argv"][0] for x in r["recipes"]} == {
        "csv-timeline"
    } and "no_recipe" not in r
    assert {x["note"] for x in r["recipes_other_versions"]} == {
        "tested on >=4.1,<5 only"
    }
    r = hayabusa_at("4.1.0")
    assert {x["argv"][0] for x in r["recipes"]} == {
        "dfir-timeline"
    } and "no_recipe" not in r
    assert {x["note"] for x in r["recipes_other_versions"]} == {
        "tested on >=3.9,<4 only"
    }


def test_a_version_no_recipe_was_checked_on_is_said(hayabusa_at):
    r = hayabusa_at("9.0.0")
    assert r["recipes"] == []
    assert r["no_recipe"].startswith(
        "No recipe for hayabusa 9.0.0; tested on >=3.9,<4, >=4.1,<5"
    )


def test_an_unknown_version_gets_no_recipe_as_its_own(hayabusa_at):
    r = hayabusa_at(None)  # no VERSIONINFO, and the probe names none
    assert r["recipes"] == [] and "of an unknown version" in r["no_recipe"]


def test_no_tool_keeps_a_switch_list():
    assert not any(hasattr(td, "common_flags") for td in load_catalog().values())


def test_yaras_probe_reads_its_version_from_its_own_help():
    """yara64.exe has no VERSIONINFO; its help's first line names it."""
    probe = load_catalog()["yara"].version_probe
    text = _helps("yara")["4.2.0"]
    assert probe["argv"] == ["--help"]
    assert re.search(probe["pattern"], text).group(1) == "4.2.0"
