"""Hash-chained audit log tests."""

from __future__ import annotations

from sentinel.audit import GENESIS, AuditLog


def test_empty_log_head_is_genesis():
    assert AuditLog().head == GENESIS


def test_chain_links_and_verifies():
    log = AuditLog()
    e0 = log.append("scan.requested", "shawn", {"target": "lab.example"})
    e1 = log.append("scan.completed", "worker", {"findings": 2})
    assert e0.prev_hash == GENESIS
    assert e1.prev_hash == e0.entry_hash
    assert log.verify() is True


def test_tampering_breaks_verification():
    log = AuditLog()
    log.append("mode.granted", "shawn", {"target": "lab.example"})
    log.append("scan.completed", "worker", {})
    # Tamper with a past entry's detail in place.
    log.entries()[0].detail["target"] = "evil.example"
    assert log.verify() is False


def test_hash_is_deterministic_for_same_content():
    a = AuditLog()
    b = AuditLog()
    ea = a.append("x", "op", {"k": 1}, at="2026-10-27T00:00:00+00:00")
    eb = b.append("x", "op", {"k": 1}, at="2026-10-27T00:00:00+00:00")
    assert ea.entry_hash == eb.entry_hash
