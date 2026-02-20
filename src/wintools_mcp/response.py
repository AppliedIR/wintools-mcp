"""Response envelope builder with forensic-knowledge enrichment."""

from __future__ import annotations

from typing import Any

from wintools_mcp.audit import resolve_examiner

try:
    from forensic_knowledge import loader as fk_loader
except ImportError:
    fk_loader = None

DISCIPLINE_REMINDERS = [
    "Evidence is sovereign — if results conflict with your hypothesis, revise the hypothesis, never reinterpret evidence to fit",
    "Absence of evidence ≠ evidence of absence — record the gap explicitly, check if logs were cleared or never enabled",
    "Correlation ≠ causation — look for a mechanism connecting events, consider coincidence and common causes",
    "Benign until proven malicious — check baseline expectations first, require positive evidence of malice",
    "Show evidence for every claim — every sentence in a finding must trace back to a specific evidence_id",
    "Stop at HITL checkpoints — stage as DRAFT and tell the examiner before: attribution, root cause, exclusion, scope",
    "Query tools before conclusions — run the relevant tool first, cite the evidence_id, never guess when you can check",
    "UNKNOWN from triage is neutral — investigate further with other tools, do not escalate based on UNKNOWN alone",
    "Verify field meanings — cross-check values against documentation, flag anomalies, do not assume field semantics",
    "Consider alternatives — after forming a hypothesis, search for contradicting evidence before corroborating evidence",
]

_call_counter = 0


def build_response(
    *,
    tool_name: str,
    success: bool,
    data: Any,
    evidence_id: str,
    output_format: str = "text",
    elapsed_seconds: float | None = None,
    exit_code: int | None = None,
    command: list[str] | None = None,
    error: str | None = None,
    fk_tool_name: str | None = None,
    output_files: list[dict] | None = None,
) -> dict:
    global _call_counter
    _call_counter += 1

    response: dict[str, Any] = {
        "success": success,
        "tool": tool_name,
        "data": data,
        "output_format": output_format,
        "evidence_id": evidence_id,
        "examiner": resolve_examiner(),
    }

    if error:
        response["error"] = error

    if output_files:
        response["output_files"] = output_files

    # FK enrichment
    fk_name = fk_tool_name or tool_name
    corroboration, caveats, advisories, field_notes = _build_knowledge_context(fk_name)
    if caveats:
        response["caveats"] = caveats
    if advisories:
        response["advisories"] = advisories
    if corroboration:
        response["corroboration"] = corroboration
    if field_notes:
        response["field_notes"] = field_notes

    response["discipline_reminder"] = DISCIPLINE_REMINDERS[
        _call_counter % len(DISCIPLINE_REMINDERS)
    ]

    metadata: dict[str, Any] = {}
    if elapsed_seconds is not None:
        metadata["elapsed_seconds"] = round(elapsed_seconds, 2)
    if exit_code is not None:
        metadata["exit_code"] = exit_code
        if fk_loader:
            tool_info = fk_loader.get_tool(fk_name)
            if tool_info and exit_code in (tool_info.get("exit_code_hints") or {}):
                metadata["exit_code_meaning"] = tool_info["exit_code_hints"][exit_code]
    if command:
        metadata["command"] = command
    if metadata:
        response["metadata"] = metadata

    return response


def _build_knowledge_context(
    tool_name: str,
) -> tuple[dict, list, list, dict]:
    if not fk_loader:
        return {}, [], [], {}

    tool_info = fk_loader.get_tool(tool_name)
    if not tool_info:
        return {}, [], [], {}

    caveats = list(tool_info.get("caveats", []))
    advisories = list(tool_info.get("advisories", []))
    corroboration: dict[str, list[str]] = {}
    field_notes: dict[str, str] = {}

    for artifact_name in tool_info.get("artifacts_parsed", []):
        artifact = fk_loader.get_artifact(artifact_name)
        if not artifact:
            continue
        for item in artifact.get("does_not_prove", []):
            advisory = f"This artifact does NOT prove: {item}"
            if advisory not in advisories:
                advisories.append(advisory)
        for key, val in artifact.get("corroborate_with", {}).items():
            if key not in corroboration:
                corroboration[key] = []
            for ref in val:
                if ref not in corroboration[key]:
                    corroboration[key].append(ref)
        for ts in artifact.get("timestamps", []):
            field_notes[ts["field"]] = ts["meaning"]
        for m in artifact.get("common_misinterpretations", []):
            advisory = f"{m['claim']} → {m['correction']}"
            if advisory not in advisories:
                advisories.append(advisory)

    return corroboration, caveats, advisories, field_notes


def reset_call_counter() -> None:
    global _call_counter
    _call_counter = 0
