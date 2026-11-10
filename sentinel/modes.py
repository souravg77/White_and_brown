"""Operating modes and the advanced-testing capability model.

SENTINEL runs in **White Hat** mode by default: reconnaissance, configuration
audits, baseline web scanning and safe verification. **Brown Hat** is the
advanced-testing mode, and it is deliberately *not* a global switch.

Following the design review, advanced testing is modelled as a
:class:`BrownHatGrant`: a capability for one named target, listing exactly which
advanced checks it covers, bounded by an expiry time, tied to an authorization
record and the operator who created it. A grant expires on its own; nothing has
to remember to turn it off. A target is in advanced-testing posture only while a
matching, unexpired grant exists — there is no process-wide "brown hat is on".

Scope enforcement, secret redaction, resource limits and audit logging stay on
in both modes. No component may widen its own grants.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


class Mode(enum.Enum):
    WHITE_HAT = "white_hat"
    BROWN_HAT = "brown_hat"


def _now(now: datetime | None = None) -> datetime:
    return now or datetime.now(timezone.utc)


@dataclass(frozen=True)
class BrownHatGrant:
    """A time-boxed advanced-testing capability for a single target.

    The grant is only meaningful together with an active authorization for the
    same target; this object narrows *what* may be done and *for how long*, it
    never substitutes for authorization.
    """

    target: str
    permitted_checks: frozenset[str]
    granted_by: str
    authorization_reference: str
    expires_at: datetime

    def is_active(self, now: datetime | None = None) -> bool:
        return _now(now) < self.expires_at

    def covers(self, target: str, check: str, now: datetime | None = None) -> bool:
        return (
            self.is_active(now)
            and self.target == target
            and check in self.permitted_checks
        )

    def remaining(self, now: datetime | None = None) -> timedelta:
        return max(self.expires_at - _now(now), timedelta(0))


class ModeManager:
    """Decides, per target and check, which mode applies.

    The manager starts empty: with no grants, every target is White Hat. A
    grant is added only through :meth:`grant_brown_hat`, which an authenticated
    operator action calls; expired grants are ignored and swept lazily.
    """

    def __init__(self) -> None:
        self._grants: list[BrownHatGrant] = []

    def grant_brown_hat(
        self,
        target: str,
        permitted_checks: frozenset[str] | set[str],
        *,
        granted_by: str,
        authorization_reference: str,
        ttl: timedelta,
        now: datetime | None = None,
    ) -> BrownHatGrant:
        if ttl <= timedelta(0):
            raise ValueError("Brown Hat grant TTL must be positive")
        if not permitted_checks:
            raise ValueError("a Brown Hat grant must list at least one check")
        grant = BrownHatGrant(
            target=target,
            permitted_checks=frozenset(permitted_checks),
            granted_by=granted_by,
            authorization_reference=authorization_reference,
            expires_at=_now(now) + ttl,
        )
        self._grants.append(grant)
        return grant

    def revoke(self, target: str) -> int:
        """Drop all grants for a target; returns how many were removed."""
        before = len(self._grants)
        self._grants = [g for g in self._grants if g.target != target]
        return before - len(self._grants)

    def active_grants(self, now: datetime | None = None) -> list[BrownHatGrant]:
        self._grants = [g for g in self._grants if g.is_active(now)]
        return list(self._grants)

    def mode_for(
        self, target: str, check: str, now: datetime | None = None
    ) -> Mode:
        for grant in self.active_grants(now):
            if grant.covers(target, check, now):
                return Mode.BROWN_HAT
        return Mode.WHITE_HAT
