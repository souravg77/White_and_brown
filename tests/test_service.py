"""End-to-end pipeline tests: request -> queue -> process -> persist/notify."""

from __future__ import annotations

import ipaddress
from datetime import date, datetime, timezone

import pytest

from sentinel.config import Config, TargetPolicy
from sentinel.db import SqliteStore
from sentinel.errors import OutOfScopeError
from sentinel.policy.authorization import Authorization
from sentinel.service import ScanService

from helpers import fake_resolver

NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)


@pytest.fixture
def config() -> Config:
    target = TargetPolicy(
        domain="lab.example",
        authorized_cidrs=(ipaddress.ip_network("93.184.216.0/24"),),
        permitted_checks=frozenset({"dns", "tls"}),
        authorization=Authorization(owner="Lab", valid_until=date(2030, 1, 1)),
    )
    return Config(targets=(target,))


@pytest.fixture
def service(config, tmp_path):
    store = SqliteStore(tmp_path / "svc.sqlite3")
    store.migrate()
    resolver = fake_resolver({"lab.example": ["93.184.216.34"]})
    svc = ScanService(config, store, resolver=resolver)
    yield svc
    store.close()


def test_dns_scan_end_to_end(service):
    vt = service.request_scan("lab.example", "dns", "shawn", now=NOW)
    summary = service.process_next(now=NOW)
    assert summary["state"] == "completed"
    assert summary["findings"] == 1
    assert summary["new"] == 1
    # Finding persisted, scan completed, audit chain intact, notification queued.
    findings = service.store.findings_for_scan(vt.scan_id)
    assert len(findings) == 1
    assert service.store.get_scan(vt.scan_id)["state"] == "completed"
    assert service.store.verify_audit_chain() is True
    assert len(service.store.undelivered_notifications()) >= 1


def test_request_scan_rejects_out_of_scope(service):
    with pytest.raises(OutOfScopeError):
        service.request_scan("evil.example", "dns", "shawn", now=NOW)


def test_missing_tool_check_ends_partial(service):
    # tls needs testssl, which is absent here -> adapter skips -> scan is partial.
    service.request_scan("lab.example", "tls", "shawn", now=NOW)
    summary = service.process_next(now=NOW)
    assert summary["state"] == "partial"


def test_idle_queue_returns_none(service):
    assert service.process_next(now=NOW) is None


def test_dedup_across_two_scans(service):
    service.request_scan("lab.example", "dns", "shawn", now=NOW)
    service.process_next(now=NOW)
    service.request_scan("lab.example", "dns", "shawn", now=NOW)
    summary = service.process_next(now=NOW)
    # Same resolved-address finding -> updated, not a second new finding/notification.
    assert summary["new"] == 0
