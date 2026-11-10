"""HTTP security-header adapter.

Drives ``httpx`` (the Kali-provided HTTP prober) against the pinned target and
reports missing or weak security headers. The parser is a pure function tested
against sample header sets; the live request path is gated behind the tool
registry and the per-job egress firewall.
"""

from __future__ import annotations

import json

from ..models import Finding, ScanResult, ValidatedTarget
from .base import BaseScanner
from .runner import run_tool
from .tools import detect_tool

# header -> (severity if missing, remediation)
_EXPECTED_HEADERS: dict[str, tuple[str, str]] = {
    "strict-transport-security": (
        "medium",
        "Add a Strict-Transport-Security header with a long max-age.",
    ),
    "content-security-policy": (
        "medium",
        "Define a Content-Security-Policy to constrain resource loading.",
    ),
    "x-content-type-options": (
        "low",
        "Set X-Content-Type-Options: nosniff.",
    ),
    "x-frame-options": (
        "low",
        "Set X-Frame-Options (or a CSP frame-ancestors directive).",
    ),
    "referrer-policy": (
        "info",
        "Set a Referrer-Policy such as strict-origin-when-cross-origin.",
    ),
}


def parse_headers(headers: dict[str, str], asset: str) -> list[Finding]:
    """Return a finding for each expected security header that is absent.

    Header names are matched case-insensitively. Only *missing* headers are
    reported here; value-quality checks are a later refinement.
    """
    present = {k.lower() for k in headers}
    findings: list[Finding] = []
    for header, (severity, remediation) in _EXPECTED_HEADERS.items():
        if header not in present:
            findings.append(
                Finding(
                    asset=asset,
                    source_tool="httpx",
                    title=f"Missing security header: {header}",
                    severity=severity,
                    evidence_summary=f"Response did not include a {header} header.",
                    remediation=remediation,
                    confidence=0.9,
                    status="observed",
                )
            )
    return findings


class HttpHeadersScanner(BaseScanner):
    name = "http_headers"
    check = "http_headers"
    tool = "httpx"

    def run(self, target: ValidatedTarget) -> ScanResult:
        skip = self.preflight(target)
        if skip is not None:
            return skip
        info = detect_tool(self.tool)
        argv = [
            info.path,                       # absolute path from the registry
            "-u", target.hostname,
            "-ip", str(target.pinned_ip),    # pin: connect to the validated address
            "-json",
            "-include-response-header",
            "-silent",
            "-no-color",
        ]
        run = run_tool(argv, timeout=120)
        if run.exit_code != 0 or not run.stdout.strip():
            return ScanResult(
                tool=self.tool,
                outcome="failed",
                exit_code=run.exit_code,
                tool_version=info.version,
                error=run.stderr or "no output from httpx",
            )
        try:
            doc = json.loads(run.stdout.strip().splitlines()[0])
            headers = doc.get("header") or doc.get("headers") or {}
        except (ValueError, IndexError) as exc:
            return ScanResult(
                tool=self.tool, outcome="failed", exit_code=run.exit_code,
                error=f"could not parse httpx output: {exc}",
            )
        findings = parse_headers(headers, target.hostname)
        return ScanResult(
            tool=self.tool,
            outcome="completed",
            findings=findings,
            exit_code=run.exit_code,
            tool_version=info.version,
        )
