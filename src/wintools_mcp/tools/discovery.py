"""Tool discovery: scan, list, check, suggest, help."""

from __future__ import annotations

from typing import Any

from wintools_mcp.catalog import load_catalog, get_tool_def
from wintools_mcp.environment import find_binary
from wintools_mcp.inventory import scan_tools, get_install_guidance

try:
    from forensic_knowledge import loader as fk_loader
except ImportError:
    fk_loader = None


def list_available_tools(category: str | None = None) -> list[dict]:
    """List tools with their availability status."""
    catalog = load_catalog()
    results = []
    for td in catalog.values():
        if category and td.category != category:
            continue
        path = find_binary(td.binary)
        results.append({
            "name": td.name,
            "binary": td.binary,
            "category": td.category,
            "description": td.description,
            "available": path is not None,
            "path": path,
        })
    return sorted(results, key=lambda x: (x["category"], x["name"]))


def list_missing_tools() -> list[dict]:
    """List tools that are not installed, with installation guidance."""
    catalog = load_catalog()
    missing = []
    for td in catalog.values():
        if find_binary(td.binary):
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
        path = find_binary(td.binary)
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

    path = find_binary(td.binary)
    result["available"] = path is not None
    if path:
        result["path"] = path

    # FK enrichment
    if fk_loader:
        tool_info = fk_loader.get_tool(td.knowledge_name)
        if tool_info:
            result["caveats"] = tool_info.get("caveats", [])
            result["advisories"] = tool_info.get("advisories", [])
            result["artifacts_parsed"] = tool_info.get("artifacts_parsed", [])
            if tool_info.get("quick_start"):
                result["quick_start"] = tool_info["quick_start"]
            if tool_info.get("investigation_sequence"):
                result["investigation_sequence"] = tool_info["investigation_sequence"]
            if tool_info.get("field_meanings"):
                result["field_meanings"] = tool_info["field_meanings"]

    return result


def suggest_tools(artifact_type: str, question: str = "") -> list[dict]:
    """Suggest tools for analyzing a specific artifact type."""
    if not fk_loader:
        return [{"error": "forensic-knowledge not available"}]

    artifact = fk_loader.get_artifact(artifact_type)
    if not artifact:
        return [{"error": f"Unknown artifact type: {artifact_type}"}]

    suggestions = []
    catalog = load_catalog()

    for tool_name in artifact.get("tools", []):
        td = None
        for cat_td in catalog.values():
            if cat_td.knowledge_name.lower() == tool_name.lower():
                td = cat_td
                break

        entry: dict[str, Any] = {"tool": tool_name}
        if td:
            path = find_binary(td.binary)
            entry["binary"] = td.binary
            entry["available"] = path is not None
            if not path and td.install_methods:
                entry["install_guidance"] = [
                    {"method": im.method, "command": im.command}
                    for im in td.install_methods
                    if im.command
                ][:2]

        corroborate = artifact.get("corroborate_with", {}).get(tool_name, [])
        if corroborate:
            entry["corroborate_with"] = corroborate

        suggestions.append(entry)

    return suggestions
