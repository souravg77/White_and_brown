"""Hash-chained audit log.

Every scope decision, scan, mode change and failure is appended here. Each
entry carries the SHA-256 of the previous entry, so any edit or deletion of a
past record breaks the chain and is detectable. This module writes the chain;
persistence (a dedicated table) is a phase-2 concern, but the chaining logic
lives here so it is defined once and tested in isolation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

GENESIS = "0" * 64


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    at: str
    action: str
    actor: str
    detail: dict[str, Any]
    prev_hash: str
    entry_hash: str = ""

    def _payload(self) -> str:
        body = {
            "seq": self.seq,
            "at": self.at,
            "action": self.action,
            "actor": self.actor,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":"))

    def compute_hash(self) -> str:
        return hashlib.sha256(self._payload().encode("utf-8")).hexdigest()


class AuditLog:
    """An append-only, hash-chained log held in memory.

    Phase 1 keeps it in memory and exposes :meth:`verify`; phase 2 persists each
    entry in the same database transaction as the finding or failure it records.
    """

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    @property
    def head(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS

    def append(
        self,
        action: str,
        actor: str,
        detail: dict[str, Any] | None = None,
        *,
        at: str | None = None,
    ) -> AuditEntry:
        prev = self.head
        draft = AuditEntry(
            seq=len(self._entries),
            at=at or _utcnow_iso(),
            action=action,
            actor=actor,
            detail=detail or {},
            prev_hash=prev,
        )
        entry = AuditEntry(**{**asdict(draft), "entry_hash": draft.compute_hash()})
        self._entries.append(entry)
        return entry

    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def verify(self) -> bool:
        """True if the chain is intact: every link and hash is consistent."""
        prev = GENESIS
        for i, entry in enumerate(self._entries):
            if entry.seq != i or entry.prev_hash != prev:
                return False
            recomputed = AuditEntry(
                seq=entry.seq,
                at=entry.at,
                action=entry.action,
                actor=entry.actor,
                detail=entry.detail,
                prev_hash=entry.prev_hash,
            ).compute_hash()
            if recomputed != entry.entry_hash:
                return False
            prev = entry.entry_hash
        return True
