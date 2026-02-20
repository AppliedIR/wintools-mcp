"""Dynamic tool discovery: scan, availability, install guidance, alternatives."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from wintools_mcp.catalog import load_catalog, ToolDefinition
from wintools_mcp.environment import find_binary


def scan_tools(extra_paths: list[Path] | None = None) -> dict[str, Any]:
    """Scan for all cataloged tools. Returns availability summary."""
    catalog = load_catalog()
    available = []
    missing = []

    for td in catalog.values():
        path = find_binary(td.binary, extra_paths)
        if path:
            available.append({
                "name": td.name,
                "binary": td.binary,
                "category": td.category,
                "path": path,
                "description": td.description,
            })
        else:
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

    by_category: dict[str, dict[str, int]] = {}
    for td in catalog.values():
        cat = td.category
        if cat not in by_category:
            by_category[cat] = {"total": 0, "available": 0, "missing": 0}
        by_category[cat]["total"] += 1
        path = find_binary(td.binary, extra_paths)
        if path:
            by_category[cat]["available"] += 1
        else:
            by_category[cat]["missing"] += 1

    return {
        "summary": {
            "total": len(catalog),
            "available": len(available),
            "missing": len(missing),
        },
        "by_category": by_category,
        "available_tools": available,
        "missing_tools": missing,
    }


def get_install_guidance(tool_name: str) -> dict[str, Any]:
    """Get installation guidance for a specific tool."""
    catalog = load_catalog()
    td = catalog.get(tool_name.lower())
    if not td:
        return {"error": f"Tool '{tool_name}' not found in catalog"}

    path = find_binary(td.binary)
    result: dict[str, Any] = {
        "name": td.name,
        "binary": td.binary,
        "installed": path is not None,
    }
    if path:
        result["path"] = path
    if td.install_methods:
        result["install_methods"] = [
            {"method": im.method, "command": im.command, "url": im.url, "notes": im.notes}
            for im in td.install_methods
        ]
    if td.alternatives:
        result["alternatives"] = td.alternatives
    return result


def print_scan_report(extra_paths: list[Path] | None = None) -> str:
    """Generate a human-readable scan report for --scan flag."""
    result = scan_tools(extra_paths)
    lines = ["wintools-mcp Tool Inventory", "=" * 40, ""]

    # Group by category
    by_cat: dict[str, list[dict]] = {}
    for tool in result["available_tools"]:
        by_cat.setdefault(tool["category"], []).append(
            {"name": tool["name"], "binary": tool["binary"],
             "status": "OK", "path": tool["path"]}
        )
    for tool in result["missing_tools"]:
        by_cat.setdefault(tool["category"], []).append(
            {"name": tool["name"], "binary": tool["binary"],
             "status": "MISSING", "install": tool.get("install_methods", [])}
        )

    for cat, tools in sorted(by_cat.items()):
        total = len(tools)
        lines.append(f"Category: {cat} ({total} tools)")
        for t in sorted(tools, key=lambda x: x["name"]):
            if t["status"] == "OK":
                lines.append(f"  [OK] {t['binary']:25s} {t['path']}")
            else:
                hint = ""
                install = t.get("install", [])
                if install:
                    first = install[0]
                    hint = f" Install: {first.get('command') or first.get('url', '')}"
                lines.append(f"  [MISSING] {t['binary']:20s}{hint}")
        lines.append("")

    s = result["summary"]
    lines.append(f"Summary: {s['available']}/{s['total']} tools available, {s['missing']} missing")
    lines.append("         Run 'list_missing_tools' for install guidance")

    return "\n".join(lines)
