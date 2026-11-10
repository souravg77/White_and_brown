"""Scanner adapter tests: parsers (pure) and preflight behaviour."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone

import pytest

from sentinel.models import ValidatedTarget
from sentinel.scanners.dns_inventory import DnsInventoryScanner
from sentinel.scanners.http_headers import HttpHeadersScanner, parse_headers
from sentinel.scanners.ssh_audit import parse_ssh_audit
from sentinel.scanners.tls import parse_testssl


def vt(check: str, checks: set[str] | None = None) -> ValidatedTarget:
    return ValidatedTarget(
        hostname="lab.example",
        pinned_ip=ipaddress.ip_address("93.184.216.34"),
        authorized_cidrs=("93.184.216.0/24",),
        permitted_checks=frozenset(checks or {check}),
        mode="white_hat",
        scan_id="abc",
        expires_at=datetime.now(timezone.utc),
    )


# -- HTTP headers -----------------------------------------------------------
def test_parse_headers_flags_missing():
    findings = parse_headers({"Server": "nginx"}, "lab.example")
    titles = {f.title for f in findings}
    assert any("strict-transport-security" in t for t in titles)
    assert any("content-security-policy" in t for t in titles)


def test_parse_headers_none_missing():
    headers = {
        "Strict-Transport-Security": "max-age=63072000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }
    assert parse_headers(headers, "lab.example") == []


def test_parse_headers_case_insensitive():
    # A present header in odd casing must not be reported as missing.
    findings = parse_headers({"strict-transport-security": "max-age=1"}, "lab.example")
    assert all("strict-transport-security" not in f.title for f in findings)


# -- testssl ----------------------------------------------------------------
def test_parse_testssl_emits_low_and_above():
    raw = json.dumps([
        {"id": "cipher_order", "severity": "OK", "finding": "fine"},
        {"id": "BREACH", "severity": "MEDIUM", "finding": "vulnerable to BREACH"},
        {"id": "heartbleed", "severity": "CRITICAL", "finding": "vulnerable"},
    ])
    findings = parse_testssl(raw, "lab.example")
    sevs = sorted(f.severity for f in findings)
    assert sevs == ["critical", "medium"]  # OK is skipped


def test_parse_testssl_bad_json_is_empty():
    assert parse_testssl("not json", "lab.example") == []


# -- ssh-audit --------------------------------------------------------------
def test_parse_ssh_audit_cves_and_recommendations():
    raw = json.dumps({
        "cves": [{"name": "CVE-2023-38408", "cvssv2": 9.8, "description": "RCE"}],
        "recommendations": {
            "critical": {"del": {"kex": ["diffie-hellman-group1-sha1"]}},
            "warning": {"chg": {"mac": ["hmac-sha1"]}},
        },
    })
    findings = parse_ssh_audit(raw, "lab.example")
    titles = " ".join(f.title for f in findings)
    assert "CVE-2023-38408" in titles
    assert "diffie-hellman-group1-sha1" in titles
    assert "hmac-sha1" in titles
    # CVE with high CVSS is high severity.
    assert any(f.severity == "high" and "CVE" in f.title for f in findings)


def test_parse_ssh_audit_empty():
    assert parse_ssh_audit("{}", "lab.example") == []


# -- preflight / registry ---------------------------------------------------
def test_adapter_skips_check_not_permitted():
    scanner = HttpHeadersScanner()
    # Target permits only tls, not http_headers.
    result = scanner.run(vt("tls"))
    assert result.outcome == "skipped"
    assert "not permitted" in result.error


def test_missing_tool_is_skipped_not_faked():
    scanner = HttpHeadersScanner()
    # httpx is absent in this environment -> preflight returns skipped.
    result = scanner.run(vt("http_headers"))
    assert result.outcome == "skipped"
    assert "httpx" in result.error


def test_dns_adapter_runs_without_external_tool():
    result = DnsInventoryScanner().run(vt("dns"))
    assert result.outcome == "completed"
    assert result.findings
    assert result.findings[0].severity == "info"
    assert "93.184.216.34" in result.findings[0].evidence_summary
