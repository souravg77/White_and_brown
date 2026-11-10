"""Persistence (SQLite via the standard-library sqlite3 module).

Single-operator desktop build: a file database, no server, no ORM, so the
security core stays dependency-free. Holds scans, findings, the hash-chained
audit log and the notification outbox, and backs the job queue.
"""

from __future__ import annotations

from .store import SCAN_STATES, TERMINAL_STATES, SqliteStore

__all__ = ["SqliteStore", "SCAN_STATES", "TERMINAL_STATES"]
