"""The setup-windows.ps1 phase headers run in order on every path.

In Valhuntir mode without -Examiner the examiner prompt is deferred until after
the join, so Phase 3's work happens later; but the header must still print in
sequence or the user sees Phase 2 jump to Phase 4 and thinks a phase was
skipped. The deferred branch prints the Phase 3 header (with a note that the
prompt comes after the join); the -Standalone/-Examiner else branch prints it
too, so each path shows every number exactly once with no gap.
"""

from __future__ import annotations

from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "setup-windows.ps1"
TEXT = SCRIPT.read_text(encoding="utf-8")

DEFER = "$examinerDeferred = $true"
PHASE3 = 'Write-Header "Phase 3: Examiner Identity"'


def _deferred_branch() -> str:
    """The body of the `if (deferred)` branch, up to its `} else {`."""
    start = TEXT.index(DEFER)
    end = TEXT.index("} else {", start)
    return TEXT[start:end]


def test_all_seven_phase_headers_are_present():
    for n, title in [
        (1, "Prerequisites"),
        (2, "Installing wintools-mcp"),
        (3, "Examiner Identity"),
        (4, "Scanning for Forensic Tools"),
        (5, "Case Directory"),
        (6, "Starting wintools-mcp"),
        (7, "Startup Configuration"),
    ]:
        assert f'Write-Header "Phase {n}: {title}"' in TEXT


def test_the_deferred_examiner_branch_prints_the_phase_3_header():
    # Common path (no -Standalone, no -Examiner): the deferred branch must print
    # Phase 3 in sequence so the user doesn't see a 2 -> 4 gap.
    branch = _deferred_branch()
    assert PHASE3 in branch
    assert "after the join" in branch  # the note explaining the deferral


def test_phase_3_header_appears_once_per_branch():
    # One in the deferred branch, one in the else (-Standalone/-Examiner) branch:
    # each path reaches exactly one, so no path prints a number twice.
    assert TEXT.count(PHASE3) == 2
