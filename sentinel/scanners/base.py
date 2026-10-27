"""The scanner adapter contract.

Every scanner receives an already-:class:`~sentinel.models.ValidatedTarget` and
returns a :class:`~sentinel.models.ScanResult`. An adapter never resolves a
hostname or decides scope itself: by the time it runs, scope has been proven and
the address pinned. Adapters shell out to the Kali-provided tool by absolute
path with a fixed argument array, enforce a timeout, bound their output, and
turn a missing tool into a ``skipped`` result instead of a fabricated finding.

Phase 1 ships this contract and a no-op reference adapter; real adapters land in
phase 2.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..models import ScanResult, ValidatedTarget
from .tools import ToolInfo, detect_tool


@runtime_checkable
class Scanner(Protocol):
    name: str
    #: The check this adapter implements (must be in KNOWN_CHECKS).
    check: str
    #: The Kali tool this adapter drives, if any.
    tool: str

    def run(self, target: ValidatedTarget) -> ScanResult:
        """Run the permitted check against the pinned target and return results."""
        ...


class BaseScanner:
    """Shared adapter behaviour: scope guard and missing-tool handling."""

    name: str = "base"
    check: str = ""
    tool: str = ""

    def preflight(self, target: ValidatedTarget) -> ScanResult | None:
        """Return a terminal ScanResult if the run must not proceed, else None.

        Refuses to run a check the validated target does not permit (defence in
        depth behind the scope engine), and reports a missing tool as skipped.
        """
        if self.check and not target.allows(self.check):
            return ScanResult(
                tool=self.tool or self.name,
                outcome="skipped",
                error=f"check {self.check!r} not permitted for this target",
            )
        if self.tool:
            info: ToolInfo = detect_tool(self.tool)
            if not info.available:
                return ScanResult(
                    tool=self.tool,
                    outcome="skipped",
                    error=f"tool {self.tool!r} not found in this Kali install",
                )
        return None

    def run(self, target: ValidatedTarget) -> ScanResult:  # pragma: no cover
        raise NotImplementedError
