"""Database schema as ordered, versioned migrations.

Persistence uses the standard-library ``sqlite3`` module: the desktop build is
single-operator, so a file database with no server and no third-party ORM keeps
the dependency surface small and the security-critical path dependency-free. Each
migration is an (version, SQL) pair applied in order and recorded in
``schema_migrations``; the runner in :mod:`sentinel.db.store` applies only those
not yet seen, so upgrades are additive and repeatable.
"""

from __future__ import annotations

# Each entry: (version, descriptive name, SQL). Append new migrations; never edit
# a released one in place.
MIGRATIONS: list[tuple[int, str, str]] = [
    (
        1,
        "initial schema",
        """
        CREATE TABLE scans (
            id            TEXT PRIMARY KEY,
            target        TEXT NOT NULL,
            check_name    TEXT NOT NULL,
            mode          TEXT NOT NULL,
            state         TEXT NOT NULL DEFAULT 'queued',
            pinned_ip     TEXT,
            requested_by  TEXT NOT NULL,
            created_at    TEXT NOT NULL,
            started_at    TEXT,
            finished_at   TEXT,
            error         TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX idx_scans_state ON scans(state);

        CREATE TABLE findings (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id          TEXT NOT NULL REFERENCES scans(id),
            fingerprint      TEXT NOT NULL,
            asset            TEXT NOT NULL,
            source_tool      TEXT NOT NULL,
            title            TEXT NOT NULL,
            severity         TEXT NOT NULL,
            status           TEXT NOT NULL DEFAULT 'observed',
            confidence       REAL NOT NULL DEFAULT 0,
            evidence_summary TEXT NOT NULL DEFAULT '',
            remediation      TEXT NOT NULL DEFAULT '',
            first_seen       TEXT NOT NULL,
            last_seen        TEXT NOT NULL
        );
        CREATE UNIQUE INDEX idx_findings_fingerprint ON findings(fingerprint);
        CREATE INDEX idx_findings_scan ON findings(scan_id);

        CREATE TABLE audit_log (
            seq        INTEGER PRIMARY KEY,
            at         TEXT NOT NULL,
            action     TEXT NOT NULL,
            actor      TEXT NOT NULL,
            detail     TEXT NOT NULL DEFAULT '{}',
            prev_hash  TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        );

        CREATE TABLE notification_outbox (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            idempotency_key TEXT NOT NULL UNIQUE,
            kind            TEXT NOT NULL,
            payload         TEXT NOT NULL DEFAULT '{}',
            created_at      TEXT NOT NULL,
            delivered_at    TEXT,
            attempts        INTEGER NOT NULL DEFAULT 0,
            last_error      TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX idx_outbox_undelivered ON notification_outbox(delivered_at);
        """,
    ),
    (
        2,
        "follow-up verification",
        """
        ALTER TABLE findings ADD COLUMN check_key TEXT NOT NULL DEFAULT '';

        CREATE TABLE verifications (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint  TEXT NOT NULL REFERENCES findings(fingerprint),
            scan_id      TEXT NOT NULL,
            verifier     TEXT NOT NULL,
            outcome      TEXT NOT NULL,
            evidence     TEXT NOT NULL DEFAULT '',
            attempted_at TEXT NOT NULL
        );
        CREATE INDEX idx_verifications_fingerprint ON verifications(fingerprint);
        """,
    ),
]
