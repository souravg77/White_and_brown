"""Authorization records.

A target is only in scope while a written authorization covers it *and* the
current time is inside that authorization's window. "Public is not permission":
reachability never authorizes a scan. Authorization is also what backs the
advanced-testing ("Brown Hat") capability model in :mod:`sentinel.modes`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone


def _today(now: datetime | None = None) -> date:
    return (now or datetime.now(timezone.utc)).date()


@dataclass(frozen=True)
class Authorization:
    """Who authorized this target, and for what window.

    ``owner`` and ``reference`` are recorded for the audit trail. ``valid_from``
    and ``valid_until`` are inclusive dates; outside them the target is not
    authorized even if it is on the allowlist.
    """

    owner: str
    reference: str = ""
    valid_from: date | None = None
    valid_until: date | None = None

    def is_active(self, now: datetime | None = None) -> bool:
        today = _today(now)
        if self.valid_from is not None and today < self.valid_from:
            return False
        if self.valid_until is not None and today > self.valid_until:
            return False
        return True

    def reason_inactive(self, now: datetime | None = None) -> str | None:
        """Human-readable reason this authorization is not active, or ``None``."""
        today = _today(now)
        if self.valid_from is not None and today < self.valid_from:
            return f"authorization starts {self.valid_from.isoformat()}"
        if self.valid_until is not None and today > self.valid_until:
            return f"authorization expired {self.valid_until.isoformat()}"
        return None
