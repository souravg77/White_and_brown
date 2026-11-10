"""SSH configuration adapter driving ssh-audit.

Audits the SSH service's cryptographic configuration. It never attempts a login
or password guessing — it inspects the server's advertised algorithms and
reports weak or deprecated ones. The parser is pure and tested.
"""

from __future__ import annotations

import json

from ..models import Finding, ScanResult, ValidatedTarget
from .base import BaseScanner
from .runner import run_tool
from .tools import detect_tool


def parse_ssh_audit(raw: str, asset: str) -> list[Finding]:
    """Parse ssh-audit ``-j`` JSON into findings.

    Reports CVEs the banner is vulnerable to, and algorithms ssh-audit flags for
    removal (``recommendations.critical`` / ``recommendations.warning``).
    """
    try:
        doc = json.loads(raw)
    except ValueError:
        return []
    findings: list[Finding] = []

    for cve in doc.get("cves", []) or []:
        if not isinstance(cve, dict):
            continue
        cvssv2 = cve.get("cvssv2") or 0
        sev = "high" if float(cvssv2 or 0) >= 7 else "medium"
        findings.append(
            Finding(
                asset=asset,
                source_tool="ssh-audit",
                title=f"SSH vulnerable to {cve.get('name', 'CVE')}",
                severity=sev,
                evidence_summary=str(cve.get("description", ""))[:500],
                remediation="Upgrade OpenSSH to a fixed version.",
                confidence=0.8,
            )
        )

    recs = doc.get("recommendations", {}) or {}
    # ssh-audit nests recommendations as {"critical"/"warning": {"del"/"chg": {...}}}
    _severity_by_level = {"critical": "high", "warning": "medium"}
    for level, our_sev in _severity_by_level.items():
        block = recs.get(level, {}) or {}
        for action, algos in block.items():
            for algo_type, names in (algos or {}).items():
                for name in names or []:
                    findings.append(
                        Finding(
                            asset=asset,
                            source_tool="ssh-audit",
                            title=f"Weak SSH {algo_type}: {name}",
                            severity=our_sev,
                            evidence_summary=f"ssh-audit recommends to {action} {name}.",
                            remediation=f"{action} {name} in sshd_config.",
                            confidence=0.8,
                        )
                    )
    return findings


class SshAuditScanner(BaseScanner):
    name = "ssh_audit"
    check = "ssh_audit"
    tool = "ssh-audit"

    def run(self, target: ValidatedTarget) -> ScanResult:
        skip = self.preflight(target)
        if skip is not None:
            return skip
        info = detect_tool(self.tool)
        argv = [info.path, "-j", "-p", "22", str(target.pinned_ip)]
        run = run_tool(argv, timeout=120)
        if run.timed_out or not run.stdout.strip():
            return ScanResult(
                tool=self.tool, outcome="failed", exit_code=run.exit_code,
                tool_version=info.version,
                error=run.stderr or "no output from ssh-audit",
            )
        findings = parse_ssh_audit(run.stdout, target.hostname)
        return ScanResult(
            tool=self.tool,
            outcome="completed",
            findings=findings,
            exit_code=run.exit_code,
            tool_version=info.version,
        )
