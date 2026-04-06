"""Tool discovery: scan, list, check, suggest, help."""

from __future__ import annotations

import itertools
import logging
from typing import Any

from wintools_mcp.catalog import get_tool_def, load_catalog
from wintools_mcp.environment import find_tool

logger = logging.getLogger(__name__)

try:
    from forensic_knowledge import loader as fk_loader
except ImportError:
    fk_loader = None

try:
    from wintools_mcp.response import DISCIPLINE_REMINDERS
except ImportError:
    DISCIPLINE_REMINDERS = ["Evidence is sovereign"]

# Alias mapping — common artifact names to FK artifact YAML names
ARTIFACT_ALIASES: dict[str, list[str]] = {
    "evtx": [
        "event_logs_security",
        "event_logs_system",
        "event_logs_sysmon",
        "event_logs_powershell",
    ],
    "evt": ["event_logs_security", "event_logs_system"],
    "event_log": ["event_logs_security", "event_logs_system", "event_logs_sysmon"],
    "event_logs": ["event_logs_security", "event_logs_system", "event_logs_sysmon"],
    "registry": ["registry_run_keys", "registry_services", "shellbags", "shimcache"],
    "registry hive": ["registry_run_keys", "registry_services", "shimcache"],
    "hive": ["registry_run_keys", "registry_services", "shimcache"],
    "persistence": ["registry_run_keys", "registry_services"],
    "execution": ["prefetch", "amcache"],
    "binary": ["amcache"],
    "dll": ["amcache"],
    "mft": ["mft"],
    "prefetch": ["prefetch"],
    "usn": ["usn_journal"],
    "userassist": ["userassist"],
    "amcache": ["amcache"],
}

_suggest_counter = itertools.count(1)


def list_available_tools(category: str | None = None) -> list[dict]:
    """List tools with their availability status."""
    catalog = load_catalog()
    results = []
    for td in catalog.values():
        if category and td.category != category:
            continue
        path = find_tool(td.binary)
        results.append(
            {
                "name": td.name,
                "binary": td.binary,
                "category": td.category,
                "description": td.description,
                "available": path is not None,
                "path": path,
            }
        )
    return sorted(results, key=lambda x: (x["category"], x["name"]))


def list_missing_tools() -> list[dict]:
    """List tools that are not installed, with installation guidance."""
    catalog = load_catalog()
    missing = []
    for td in catalog.values():
        if find_tool(td.binary):
            continue
        entry: dict[str, Any] = {
            "name": td.name,
            "binary": td.binary,
            "category": td.category,
            "description": td.description,
        }
        if td.install_methods:
            entry["install_methods"] = [
                {"method": im.method, "command": im.command, "url": im.url}
                for im in td.install_methods
                if im.command or im.url
            ]
        if td.alternatives:
            entry["alternatives"] = td.alternatives
        missing.append(entry)
    return sorted(missing, key=lambda x: (x["category"], x["name"]))


def check_tools(tool_names: list[str] | None = None) -> dict:
    """Check which tools are installed."""
    catalog = load_catalog()
    if tool_names:
        names = [n.lower() for n in tool_names]
        tools = {n: td for n, td in catalog.items() if n in names}
    else:
        tools = catalog

    results = {}
    for name, td in tools.items():
        path = find_tool(td.binary)
        results[name] = {
            "binary": td.binary,
            "available": path is not None,
            "path": path,
        }
    return results


def get_tool_help(tool_name: str) -> dict:
    """Get usage info, flags, and FK caveats for a tool."""
    td = get_tool_def(tool_name)
    if not td:
        return {"error": f"Tool '{tool_name}' not found in catalog"}

    result: dict[str, Any] = {
        "name": td.name,
        "binary": td.binary,
        "category": td.category,
        "description": td.description,
        "input_style": td.input_style,
        "input_flag": td.input_flag,
        "output_format": td.output_format,
        "common_flags": td.common_flags,
    }

    path = find_tool(td.binary)
    result["available"] = path is not None
    if path:
        result["path"] = path

    # FK enrichment
    if fk_loader:
        try:
            tool_info = fk_loader.get_tool(td.knowledge_name)
            if tool_info and isinstance(tool_info, dict):
                result["caveats"] = tool_info.get("caveats") or []
                result["advisories"] = tool_info.get("advisories") or []
                result["artifacts_parsed"] = tool_info.get("artifacts_parsed") or []
                if tool_info.get("quick_start"):
                    result["quick_start"] = tool_info["quick_start"]
                if tool_info.get("investigation_sequence"):
                    result["investigation_sequence"] = tool_info[
                        "investigation_sequence"
                    ]
                if tool_info.get("field_meanings"):
                    result["field_meanings"] = tool_info["field_meanings"]
        except Exception as e:
            logger.warning("FK enrichment failed for %s: %s", td.knowledge_name, e)

    return result


def suggest_tools(artifact_type: str, question: str = "") -> dict:
    """Suggest tools for analyzing a specific artifact type.

    Returns an enriched envelope with suggestions, advisories, corroboration,
    cross-MCP checks, and discipline reminders.
    """
    if not fk_loader:
        return {"suggestions": [], "error": "forensic-knowledge not available"}

    if not artifact_type or not isinstance(artifact_type, str):
        return {"suggestions": [], "error": "artifact_type must be a non-empty string"}

    # Resolve aliases
    artifact_names = ARTIFACT_ALIASES.get(artifact_type.lower(), [artifact_type])

    suggestions: list[dict] = []
    all_advisories: list[str] = []
    all_corroboration: dict[str, list[str]] = {}
    all_cross_mcp: list[dict] = []
    catalog = load_catalog()

    for art_name in artifact_names:
        try:
            artifact = fk_loader.get_artifact(art_name)
        except Exception as e:
            logger.warning("FK get_artifact(%s) failed: %s", art_name, e)
            continue
        if not artifact or not isinstance(artifact, dict):
            continue
        # Skip non-Windows artifacts (wintools only runs Windows tools)
        if artifact.get("platform", "windows") != "windows":
            continue

        for tool_name in artifact.get("related_tools") or []:
            # Avoid duplicates across aliases
            if any(s.get("tool") == tool_name for s in suggestions):
                continue

            td = None
            for cat_td in catalog.values():
                if cat_td.knowledge_name.lower() == tool_name.lower():
                    td = cat_td
                    break

            entry: dict[str, Any] = {"tool": tool_name, "artifact": art_name}
            if td:
                path = find_tool(td.binary)
                entry["binary"] = td.binary
                entry["available"] = path is not None
                if not path and td.install_methods:
                    entry["install_guidance"] = [
                        {"method": im.method, "command": im.command}
                        for im in td.install_methods
                        if im.command
                    ][:2]

            suggestions.append(entry)

        # Advisories from does_not_prove
        for item in artifact.get("does_not_prove") or []:
            advisory = f"This artifact does NOT prove: {item}"
            if advisory not in all_advisories:
                all_advisories.append(advisory)

        # Corroboration map
        for key, val in (artifact.get("corroborate_with") or {}).items():
            if key not in all_corroboration:
                all_corroboration[key] = []
            for ref in val:
                if ref not in all_corroboration[key]:
                    all_corroboration[key].append(ref)

        # Cross-MCP checks
        for check in artifact.get("cross_mcp_checks") or []:
            if check not in all_cross_mcp:
                all_cross_mcp.append(check)

    if not suggestions:
        try:
            available = [
                a["name"] for a in fk_loader.list_artifacts(platform="windows")
            ]
        except Exception as e:
            logger.warning("FK list_artifacts() failed: %s", e)
            available = []
        return {
            "suggestions": [],
            "info": f"No tools found for artifact type '{artifact_type}'",
            "available_artifacts": available,
        }

    call_num = next(_suggest_counter)
    return {
        "suggestions": suggestions,
        "advisories": all_advisories,
        "corroboration": all_corroboration,
        "cross_mcp_checks": all_cross_mcp,
        "discipline_reminder": DISCIPLINE_REMINDERS[
            call_num % len(DISCIPLINE_REMINDERS)
        ],
    }
