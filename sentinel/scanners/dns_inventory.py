"""DNS / asset-inventory adapter (standard library).

Records the address the target resolved to as an informational inventory
finding. It acts only on the already-validated, pinned address in the
``ValidatedTarget`` — it does not perform its own discovery or expand scope.
Needs no external tool, so it always runs.
"""

from __future__ import annotations

from ..models import Finding, ScanResult, ValidatedTarget
from .base import BaseScanner


class DnsInventoryScanner(BaseScanner):
    name = "dns"
    check = "dns"
    tool = ""  # standard-library only; nothing to detect

    def run(self, target: ValidatedTarget) -> ScanResult:
        skip = self.preflight(target)
        if skip is not None:
            return skip
        finding = Finding(
            asset=target.hostname,
            source_tool="dns",
            title="Resolved address",
            severity="info",
            evidence_summary=(
                f"{target.hostname} resolved to {target.pinned_ip} "
                f"(authorized scope: {', '.join(target.authorized_cidrs)})"
            ),
            remediation="Informational: confirm this address is an owned asset.",
            confidence=1.0,
            status="observed",
            check_key=str(target.pinned_ip),
        )
        return ScanResult(tool="dns", outcome="completed", findings=[finding], exit_code=0)
