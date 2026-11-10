"""SQLite-backed persistence and the database job queue.

Everything a scan produces — its row, its findings, audit entries and
notification events — lives here. The queue is the database itself: a worker
claims the next queued scan with an atomic ``BEGIN IMMEDIATE`` transaction
(SQLite's equivalent of ``SELECT ... FOR UPDATE SKIP LOCKED``), so no separate
broker is needed for the single-host build.

Findings are deduplicated by fingerprint, the audit log is hash-chained on
write, and notification events are written with an idempotency key so a retry
never double-sends. Uses only the standard library.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..audit import AuditEntry, GENESIS
from ..models import Finding
from .schema import MIGRATIONS

# Scan lifecycle states. "partial" is kept distinct from "completed" so a scan
# that ran some checks and failed others is never reported as a clean success.
SCAN_STATES = ("queued", "running", "completed", "partial", "failed", "cancelled")
TERMINAL_STATES = ("completed", "partial", "failed", "cancelled")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SqliteStore:
    def __init__(self, path: str | Path = "sentinel.sqlite3") -> None:
        self.path = str(path)
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

    def close(self) -> None:
        self._conn.close()

    # -- migrations ---------------------------------------------------------
    def migrate(self) -> int:
        """Apply any unapplied migrations in order. Returns the schema version."""
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations "
            "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        row = self._conn.execute(
            "SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations"
        ).fetchone()
        current = row["v"]
        for version, _name, sql in MIGRATIONS:
            if version <= current:
                continue
            # executescript() commits any open transaction and runs the DDL in
            # autocommit; record the version immediately after so a crash between
            # the two leaves the migration re-runnable (DDL uses IF-safe guards
            # only where needed, and each migration is applied at most once).
            self._conn.executescript(sql)
            self._conn.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, _utcnow_iso()),
            )
            current = version
        return current

    # -- audit log (hash-chained, persisted) --------------------------------
    def record_audit(
        self, action: str, actor: str, detail: dict[str, Any] | None = None
    ) -> AuditEntry:
        row = self._conn.execute(
            "SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        seq = (row["seq"] + 1) if row else 0
        prev = row["entry_hash"] if row else GENESIS
        draft = AuditEntry(
            seq=seq,
            at=_utcnow_iso(),
            action=action,
            actor=actor,
            detail=detail or {},
            prev_hash=prev,
        )
        entry = AuditEntry(
            seq=draft.seq,
            at=draft.at,
            action=draft.action,
            actor=draft.actor,
            detail=draft.detail,
            prev_hash=draft.prev_hash,
            entry_hash=draft.compute_hash(),
        )
        self._conn.execute(
            "INSERT INTO audit_log(seq, at, action, actor, detail, prev_hash, entry_hash)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                entry.seq,
                entry.at,
                entry.action,
                entry.actor,
                json.dumps(entry.detail, sort_keys=True),
                entry.prev_hash,
                entry.entry_hash,
            ),
        )
        return entry

    def verify_audit_chain(self) -> bool:
        prev = GENESIS
        for i, row in enumerate(
            self._conn.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()
        ):
            if row["seq"] != i or row["prev_hash"] != prev:
                return False
            recomputed = AuditEntry(
                seq=row["seq"],
                at=row["at"],
                action=row["action"],
                actor=row["actor"],
                detail=json.loads(row["detail"]),
                prev_hash=row["prev_hash"],
            ).compute_hash()
            if recomputed != row["entry_hash"]:
                return False
            prev = row["entry_hash"]
        return True

    # -- scan queue ---------------------------------------------------------
    def enqueue_scan(
        self,
        scan_id: str,
        target: str,
        check_name: str,
        mode: str,
        requested_by: str,
        pinned_ip: str | None = None,
    ) -> None:
        self._conn.execute(
            "INSERT INTO scans(id, target, check_name, mode, state, pinned_ip,"
            " requested_by, created_at) VALUES (?, ?, ?, ?, 'queued', ?, ?, ?)",
            (scan_id, target, check_name, mode, pinned_ip, requested_by, _utcnow_iso()),
        )

    def claim_next_scan(self) -> sqlite3.Row | None:
        """Atomically claim the oldest queued scan and mark it running.

        ``BEGIN IMMEDIATE`` takes the write lock before the SELECT, so two
        workers cannot claim the same row.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT * FROM scans WHERE state='queued' ORDER BY created_at LIMIT 1"
            ).fetchone()
            if row is None:
                self._conn.execute("COMMIT")
                return None
            self._conn.execute(
                "UPDATE scans SET state='running', started_at=? WHERE id=?",
                (_utcnow_iso(), row["id"]),
            )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise
        return self._conn.execute(
            "SELECT * FROM scans WHERE id=?", (row["id"],)
        ).fetchone()

    def finish_scan(self, scan_id: str, state: str, error: str = "") -> None:
        if state not in TERMINAL_STATES:
            raise ValueError(f"{state!r} is not a terminal scan state")
        self._conn.execute(
            "UPDATE scans SET state=?, finished_at=?, error=? WHERE id=?",
            (state, _utcnow_iso(), error, scan_id),
        )

    def get_scan(self, scan_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM scans WHERE id=?", (scan_id,)
        ).fetchone()

    # -- findings (fingerprint dedup) ---------------------------------------
    def upsert_finding(self, scan_id: str, finding: Finding, fingerprint: str) -> str:
        """Insert a finding or update the existing one with the same fingerprint.

        Returns ``"new"`` or ``"updated"`` so the caller knows whether to raise a
        new-finding notification.
        """
        now = _utcnow_iso()
        existing = self._conn.execute(
            "SELECT id FROM findings WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
        if existing is None:
            self._conn.execute(
                "INSERT INTO findings(scan_id, fingerprint, asset, source_tool, title,"
                " severity, status, confidence, evidence_summary, remediation,"
                " first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    scan_id, fingerprint, finding.asset, finding.source_tool,
                    finding.title, finding.severity, finding.status,
                    finding.confidence, finding.evidence_summary,
                    finding.remediation, now, now,
                ),
            )
            return "new"
        self._conn.execute(
            "UPDATE findings SET scan_id=?, severity=?, status=?, confidence=?,"
            " evidence_summary=?, remediation=?, last_seen=? WHERE fingerprint=?",
            (
                scan_id, finding.severity, finding.status, finding.confidence,
                finding.evidence_summary, finding.remediation, now, fingerprint,
            ),
        )
        return "updated"

    def findings_for_scan(self, scan_id: str) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)
        ).fetchall()

    # -- notification outbox (idempotent) -----------------------------------
    def enqueue_notification(
        self, idempotency_key: str, kind: str, payload: dict[str, Any]
    ) -> bool:
        """Queue a notification. Returns False if the idempotency key already exists."""
        try:
            self._conn.execute(
                "INSERT INTO notification_outbox(idempotency_key, kind, payload,"
                " created_at) VALUES (?, ?, ?, ?)",
                (idempotency_key, kind, json.dumps(payload, sort_keys=True), _utcnow_iso()),
            )
        except sqlite3.IntegrityError:
            return False
        return True

    def undelivered_notifications(self) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM notification_outbox WHERE delivered_at IS NULL ORDER BY id"
        ).fetchall()

    def mark_notification_delivered(self, notification_id: int) -> None:
        self._conn.execute(
            "UPDATE notification_outbox SET delivered_at=? WHERE id=?",
            (_utcnow_iso(), notification_id),
        )
