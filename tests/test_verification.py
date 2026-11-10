"""Follow-up verification tests — the phase-3 acceptance gate.

Roadmap acceptance: suspected findings remain unverified until supported by
repeatable technical evidence, and a verification timeout leaves a finding
unverified. Model confidence never verifies anything.
"""

from __future__ import annotations

import ipaddress
import time
from datetime import date, datetime, timezone

import pytest

from sentinel.config import Config, TargetPolicy
from sentinel.db import SqliteStore
from sentinel.models import Finding, ScanResult, ValidatedTarget
from sentinel.policy.authorization import Authorization
from sentinel.service import ScanService
from sentinel.verification.verify import (
    FALSE_POSITIVE,
    UNVERIFIED,
    VERIFIED,
    DnsVerifier,
    HeaderVerifier,
    verify_finding,
)

from helpers import fake_resolver

NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)


def vt(checks=("http_headers", "dns")) -> ValidatedTarget:
    return ValidatedTarget(
        hostname="lab.example",
        pinned_ip=ipaddress.ip_address("93.184.216.34"),
        authorized_cidrs=("93.184.216.0/24",),
        permitted_checks=frozenset(checks),
        mode="white_hat",
        scan_id="abc",
        expires_at=NOW,
    )


def header_finding(header="strict-transport-security", tool="httpx") -> Finding:
    return Finding(
        asset="lab.example", source_tool=tool,
        title=f"Missing security header: {header}", severity="medium",
        evidence_summary="", remediation="", confidence=0.9, check_key=header,
    )


def sequence_fetch(*responses):
    """A fake fetcher returning each response in turn (an Exception is raised)."""
    it = iter(responses)

    def _fetch(_target):
        r = next(it)
        if isinstance(r, Exception):
            raise r
        return r

    return _fetch


NO_SLEEP = dict(sleep=lambda _s: None)


# -- header verifier ---------------------------------------------------------
def test_header_absent_every_time_is_verified():
    v = HeaderVerifier(sequence_fetch({"Server": "x"}, {"Server": "x"}), **NO_SLEEP)
    assert v.verify(header_finding(), vt()).outcome == VERIFIED


def test_header_present_every_time_is_false_positive():
    present = {"Strict-Transport-Security": "max-age=1"}
    v = HeaderVerifier(sequence_fetch(present, present), **NO_SLEEP)
    assert v.verify(header_finding(), vt()).outcome == FALSE_POSITIVE


def test_inconsistent_rechecks_stay_unverified():
    v = HeaderVerifier(
        sequence_fetch({}, {"strict-transport-security": "max-age=1"}), **NO_SLEEP
    )
    res = v.verify(header_finding(), vt())
    assert res.outcome == UNVERIFIED
    assert not res.failed  # inconclusive, not a failure


def test_recheck_error_stays_unverified_and_is_a_failure():
    v = HeaderVerifier(sequence_fetch(ConnectionRefusedError()), **NO_SLEEP)
    res = v.verify(header_finding(), vt())
    assert res.outcome == UNVERIFIED
    assert res.failed


def test_header_verifier_waits_between_rechecks():
    waits = []
    v = HeaderVerifier(sequence_fetch({}, {}), interval=0.7, sleep=waits.append)
    v.verify(header_finding(), vt())
    assert waits == [0.7]


# -- dns verifier ------------------------------------------------------------
def test_dns_still_resolving_is_verified():
    f = Finding(asset="lab.example", source_tool="dns", title="Resolved address",
                severity="info", evidence_summary="", remediation="",
                check_key="93.184.216.34")
    v = DnsVerifier(fake_resolver({"lab.example": ["93.184.216.34"]}))
    assert v.verify(f, vt()).outcome == VERIFIED


def test_dns_moved_address_is_false_positive():
    f = Finding(asset="lab.example", source_tool="dns", title="Resolved address",
                severity="info", evidence_summary="", remediation="",
                check_key="93.184.216.34")
    v = DnsVerifier(fake_resolver({"lab.example": ["93.184.216.99"]}))
    assert v.verify(f, vt()).outcome == FALSE_POSITIVE


# -- dispatch ----------------------------------------------------------------
def test_no_verifier_stays_unverified_regardless_of_confidence():
    f = Finding(asset="lab.example", source_tool="testssl", title="TLS: x",
                severity="high", evidence_summary="", remediation="",
                confidence=1.0, check_key="x")
    res = verify_finding(f, vt(), {}, timeout=1)
    assert res.outcome == UNVERIFIED
    assert not res.failed


def test_recheck_not_permitted_stays_unverified():
    v = HeaderVerifier(sequence_fetch({}, {}), **NO_SLEEP)
    res = verify_finding(header_finding(), vt(checks=("dns",)), {"httpx": v}, timeout=1)
    assert res.outcome == UNVERIFIED


def test_verification_timeout_stays_unverified():
    def slow(_target):
        time.sleep(2)
        return {}

    v = HeaderVerifier(slow, **NO_SLEEP)
    start = time.monotonic()
    res = verify_finding(header_finding(), vt(), {"httpx": v}, timeout=0.2)
    assert res.outcome == UNVERIFIED
    assert res.failed
    assert time.monotonic() - start < 1.5  # did not wait for the hung recheck


# -- service integration -----------------------------------------------------
class FakeHeaderScanner:
    """Stands in for the httpx adapter (absent in CI) with fixed findings."""

    name = check = "http_headers"
    tool = "httpx"

    def __init__(self, on_run=None):
        self.on_run = on_run

    def run(self, target):
        if self.on_run:
            self.on_run()
        return ScanResult(
            tool="httpx", outcome="completed", exit_code=0,
            findings=[
                header_finding("strict-transport-security"),
                header_finding("x-frame-options"),
            ],
        )


@pytest.fixture
def make_service(tmp_path, monkeypatch):
    stores = []

    def _make(fetch, on_run=None, timeout=5.0):
        target = TargetPolicy(
            domain="lab.example",
            authorized_cidrs=(ipaddress.ip_network("93.184.216.0/24"),),
            permitted_checks=frozenset({"http_headers"}),
            authorization=Authorization(owner="Lab", valid_until=date(2030, 1, 1)),
        )
        store = SqliteStore(tmp_path / f"v{len(stores)}.sqlite3")
        store.migrate()
        stores.append(store)
        svc = ScanService(
            Config(targets=(target,)), store,
            resolver=fake_resolver({"lab.example": ["93.184.216.34"]}),
            verifiers={"httpx": HeaderVerifier(fetch, **NO_SLEEP)},
            verification_timeout=timeout,
        )
        monkeypatch.setattr(
            "sentinel.service.get_scanner", lambda check: FakeHeaderScanner(on_run)
        )
        return svc

    yield _make
    for s in stores:
        s.close()


def test_service_verifies_and_records_history(make_service):
    # HSTS absent in both rechecks (verified); X-Frame-Options present (false positive).
    xfo = {"X-Frame-Options": "DENY"}
    svc = make_service(sequence_fetch(xfo, xfo, xfo, xfo))
    vt_ = svc.request_scan("lab.example", "http_headers", "shawn", now=NOW)
    summary = svc.process_next(now=NOW)

    assert summary["verification"] == {VERIFIED: 1, FALSE_POSITIVE: 1}
    rows = {r["check_key"]: r for r in svc.store.findings_for_scan(vt_.scan_id)}
    assert rows["strict-transport-security"]["status"] == VERIFIED
    assert rows["x-frame-options"]["status"] == FALSE_POSITIVE

    fp = rows["strict-transport-security"]["fingerprint"]
    assert [v["outcome"] for v in svc.store.verifications_for(fp)] == [VERIFIED]
    kinds = [n["kind"] for n in svc.store.undelivered_notifications()]
    assert kinds.count("finding.status_changed") == 2
    assert svc.store.verify_audit_chain()


def test_service_status_change_not_renotified_when_unchanged(make_service):
    svc = make_service(sequence_fetch(*([{}] * 8)))
    svc.request_scan("lab.example", "http_headers", "shawn", now=NOW)
    svc.process_next(now=NOW)
    before = len(svc.store.undelivered_notifications())
    svc.request_scan("lab.example", "http_headers", "shawn", now=NOW)
    svc.process_next(now=NOW)
    after = svc.store.undelivered_notifications()
    # Second scan: same findings, same verified status -> no new notifications.
    assert len(after) == before


def test_scope_lost_before_verification_leaves_unverified(make_service):
    holder = {}

    def revoke_scope():
        # Scope changes while the scan runs: the target is removed.
        holder["svc"].scope.config = Config(targets=())

    svc = make_service(sequence_fetch(*([{}] * 4)), on_run=revoke_scope)
    holder["svc"] = svc
    vt_ = svc.request_scan("lab.example", "http_headers", "shawn", now=NOW)
    summary = svc.process_next(now=NOW)

    assert summary["verification"] == {UNVERIFIED: 2}
    assert all(r["status"] == UNVERIFIED for r in svc.store.findings_for_scan(vt_.scan_id))
    kinds = [n["kind"] for n in svc.store.undelivered_notifications()]
    assert "verification.failed" in kinds


def test_service_verification_timeout_notifies_failure(make_service):
    def slow(_target):
        time.sleep(1)
        return {}

    svc = make_service(slow, timeout=0.1)
    vt_ = svc.request_scan("lab.example", "http_headers", "shawn", now=NOW)
    summary = svc.process_next(now=NOW)
    assert summary["verification"] == {UNVERIFIED: 2}
    kinds = [n["kind"] for n in svc.store.undelivered_notifications()]
    assert kinds.count("verification.failed") == 2


def test_secrets_redacted_before_persistence(make_service, monkeypatch):
    class LeakyScanner(FakeHeaderScanner):
        def run(self, target):
            f = header_finding()
            f.evidence_summary = "Set-Cookie: sessionid=TOPSECRET; Path=/"
            return ScanResult(tool="httpx", outcome="completed", exit_code=0, findings=[f])

    svc = make_service(sequence_fetch({}, {}))
    monkeypatch.setattr("sentinel.service.get_scanner", lambda check: LeakyScanner())
    vt_ = svc.request_scan("lab.example", "http_headers", "shawn", now=NOW)
    svc.process_next(now=NOW)
    (row,) = svc.store.findings_for_scan(vt_.scan_id)
    assert "TOPSECRET" not in row["evidence_summary"]
