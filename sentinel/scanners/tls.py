"""TLS/SSL adapter driving testssl.sh.

Parses testssl's JSON output into findings. The parser is pure and tested; the
live run is gated behind the tool registry and the egress firewall.
"""

from __future__ import annotations

import json
import tempfile

from ..models import Finding, ScanResult, ValidatedTarget
from .base import BaseScanner
from .runner import run_tool
from .tools import detect_tool

# testssl severity -> our severity. OK/INFO/WARN are not reported as findings.
_SEVERITY_MAP = {
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


def parse_testssl(raw: str, asset: str) -> list[Finding]:
    """Parse a testssl JSON document into findings (LOW severity and above)."""
    try:
        records = json.loads(raw)
    except ValueError:
        return []
    if isinstance(records, dict):  # some testssl versions wrap in {"scanResult": [...]}
        records = records.get("scanResult") or records.get("findings") or []
    findings: list[Finding] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        sev = _SEVERITY_MAP.get(str(rec.get("severity", "")).upper())
        if sev is None:
            continue
        rec_id = str(rec.get("id", "finding"))
        findings.append(
            Finding(
                asset=asset,
                source_tool="testssl",
                title=f"TLS: {rec_id}",
                severity=sev,
                evidence_summary=str(rec.get("finding", ""))[:500],
                remediation=str(rec.get("cve", "") or "Review TLS configuration.")[:500],
                confidence=0.85,
                status="observed",
            )
        )
    return findings


class TlsScanner(BaseScanner):
    name = "tls"
    check = "tls"
    tool = "testssl"

    def run(self, target: ValidatedTarget) -> ScanResult:
        skip = self.preflight(target)
        if skip is not None:
            return skip
        info = detect_tool(self.tool)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path = tmp.name
        argv = [
            info.path,
            "--jsonfile", out_path,
            "--quiet",
            "--ip", str(target.pinned_ip),   # pin to the validated address
            f"{target.hostname}:443",
        ]
        run = run_tool(argv, timeout=target_timeout(target))
        if run.timed_out:
            return ScanResult(
                tool=self.tool, outcome="failed", tool_version=info.version,
                error="testssl timed out",
            )
        try:
            with open(out_path, encoding="utf-8") as fh:
                raw = fh.read()
        except OSError as exc:
            return ScanResult(
                tool=self.tool, outcome="failed", exit_code=run.exit_code,
                error=f"could not read testssl output: {exc}",
            )
        findings = parse_testssl(raw, target.hostname)
        return ScanResult(
            tool=self.tool,
            outcome="completed",
            findings=findings,
            exit_code=run.exit_code,
            tool_version=info.version,
        )


def target_timeout(target: ValidatedTarget) -> int:
    # testssl is slower; give it headroom but stay bounded.
    return 600
