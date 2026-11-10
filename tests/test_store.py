"""Persistence and job-queue tests (SQLite store)."""

from __future__ import annotations

import pytest

from sentinel.db import SqliteStore
from sentinel.db.schema import MIGRATIONS
from sentinel.models import Finding
from sentinel.verification.fingerprint import fingerprint


@pytest.fixture
def store(tmp_path):
    s = SqliteStore(tmp_path / "t.sqlite3")
    s.migrate()
    yield s
    s.close()


def test_migrate_is_idempotent(tmp_path):
    latest = MIGRATIONS[-1][0]
    s = SqliteStore(tmp_path / "m.sqlite3")
    assert s.migrate() == latest
    assert s.migrate() == latest  # applying again is a no-op
    s.close()


def test_migration_upgrades_existing_v1_database(tmp_path):
    # A database created at v1 picks up later migrations without data loss.
    import sqlite3

    path = tmp_path / "old.sqlite3"
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    conn.executescript(MIGRATIONS[0][2])
    conn.execute("INSERT INTO schema_migrations VALUES (1, 'x')")
    conn.execute(
        "INSERT INTO scans(id, target, check_name, mode, requested_by, created_at)"
        " VALUES ('old', 'lab.example', 'dns', 'white_hat', 'shawn', 'x')"
    )
    conn.close()
    s = SqliteStore(path)
    assert s.migrate() == MIGRATIONS[-1][0]
    assert s.get_scan("old")["target"] == "lab.example"
    s.close()


def test_rescan_keeps_verified_status(store):
    store.enqueue_scan("s1", "lab.example", "http_headers", "white_hat", "shawn")
    f = Finding(
        asset="lab.example", source_tool="httpx", title="Missing security header: x",
        severity="low", evidence_summary="x", remediation="y", check_key="x",
    )
    fp = fingerprint(f)
    store.upsert_finding("s1", f, fp)
    assert store.set_finding_status(fp, "verified", 0.95) == "observed"
    store.upsert_finding("s1", f, fp)  # re-observed on a later scan
    assert store.get_finding(fp)["status"] == "verified"


def test_verification_history_recorded(store):
    store.enqueue_scan("s1", "lab.example", "dns", "white_hat", "shawn")
    f = Finding(asset="a", source_tool="dns", title="t", severity="info",
                evidence_summary="", remediation="", check_key="k")
    fp = fingerprint(f)
    store.upsert_finding("s1", f, fp)
    store.record_verification(fp, "s1", "dns", "verified", "still resolves")
    rows = store.verifications_for(fp)
    assert [r["outcome"] for r in rows] == ["verified"]


def test_scan_queue_claim_marks_running_and_finishes(store):
    store.enqueue_scan("s1", "lab.example", "tls", "white_hat", "shawn", "93.184.216.34")
    claimed = store.claim_next_scan()
    assert claimed["id"] == "s1"
    assert claimed["state"] == "running"
    # Queue is now empty.
    assert store.claim_next_scan() is None
    store.finish_scan("s1", "completed")
    assert store.get_scan("s1")["state"] == "completed"


def test_finish_scan_rejects_non_terminal_state(store):
    store.enqueue_scan("s1", "lab.example", "tls", "white_hat", "shawn")
    store.claim_next_scan()
    with pytest.raises(ValueError):
        store.finish_scan("s1", "running")


def test_findings_dedup_by_fingerprint(store):
    store.enqueue_scan("s1", "lab.example", "tls", "white_hat", "shawn")
    f = Finding(
        asset="lab.example", source_tool="testssl", title="TLS: weak_cipher",
        severity="medium", evidence_summary="x", remediation="y",
    )
    fp = fingerprint(f)
    assert store.upsert_finding("s1", f, fp) == "new"
    # Same fingerprint again updates, does not duplicate.
    assert store.upsert_finding("s1", f, fp) == "updated"
    assert len(store.findings_for_scan("s1")) == 1


def test_audit_chain_persists_and_verifies(store):
    store.record_audit("scan.requested", "shawn", {"target": "lab.example"})
    store.record_audit("scan.completed", "worker", {"findings": 1})
    assert store.verify_audit_chain() is True


def test_notification_idempotency(store):
    assert store.enqueue_notification("k1", "finding.new", {"id": 1}) is True
    assert store.enqueue_notification("k1", "finding.new", {"id": 1}) is False
    assert len(store.undelivered_notifications()) == 1


def test_notification_mark_delivered(store):
    store.enqueue_notification("k1", "finding.new", {"id": 1})
    note = store.undelivered_notifications()[0]
    store.mark_notification_delivered(note["id"])
    assert store.undelivered_notifications() == []
