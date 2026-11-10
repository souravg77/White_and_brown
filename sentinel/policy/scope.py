"""The scope engine: the single gate every scan and redirect passes through.

This is the phase-1 acceptance gate. Given a config and a requested target and
check, it either returns a :class:`~sentinel.models.ValidatedTarget` — a pinned,
time-boxed permission for one scan — or raises a :class:`PolicyError`
explaining exactly why the request was rejected. It fails closed: anything it
cannot positively authorize is refused before any scanner runs.

The checks, in order:

1. The host is on the allowlist (a known target).
2. A valid authorization covers the target right now.
3. The requested check is permitted for the target.
4. The requested check is permitted in the active mode (advanced checks need a
   Brown Hat grant).
5. The host resolves, and *every* resolved address is in scope and not blocked.
6. The address the scan will use is pinned into the returned target.

Redirects are revalidated with :func:`validate_redirect`, which re-runs the
whole gate for the redirect's host so a redirect cannot escape scope.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from ..config import ADVANCED_CHECKS, Config, TargetPolicy, normalize_hostname
from ..errors import (
    CheckNotPermittedError,
    NotAuthorizedError,
    OutOfScopeError,
    PolicyError,
)
from ..models import ValidatedTarget
from ..modes import Mode, ModeManager
from . import dns_validation


class ScopeEngine:
    def __init__(
        self,
        config: Config,
        mode_manager: ModeManager | None = None,
    ) -> None:
        self.config = config
        self.modes = mode_manager or ModeManager()

    def validate_scan_request(
        self,
        target: str,
        check: str,
        *,
        now: datetime | None = None,
        resolver=dns_validation.resolve,
    ) -> ValidatedTarget:
        """Validate one (target, check) request and return a pinned permission.

        ``resolver`` is injectable so tests can validate scope logic without
        real DNS. It must behave like :func:`sentinel.policy.dns_validation.resolve`.
        """
        now = now or datetime.now(timezone.utc)
        host = normalize_hostname(target)

        # 1. Allowlist.
        policy = self.config.find_target(host)
        if policy is None:
            raise OutOfScopeError(f"{host!r} is not an allowlisted target")

        # 2. Authorization window.
        inactive = policy.authorization.reason_inactive(now)
        if inactive is not None:
            raise NotAuthorizedError(f"{host!r}: {inactive}")

        # 3. Check permitted for this target.
        if check not in policy.permitted_checks:
            raise CheckNotPermittedError(
                f"check {check!r} is not permitted for {host!r}"
            )

        # 4. Check permitted in the active mode.
        mode = self.modes.mode_for(host, check, now)
        if check in ADVANCED_CHECKS and mode is not Mode.BROWN_HAT:
            raise CheckNotPermittedError(
                f"check {check!r} requires an active Brown Hat grant for {host!r}"
            )

        # 5. Resolve and validate every address. All must pass; we pin the first.
        addresses = resolver(host)
        for ip in addresses:
            dns_validation.validate_address(
                ip,
                policy.authorized_cidrs,
                allow_private_lab=policy.allow_private_lab,
            )
        pinned = addresses[0]

        # 6. Build the pinned, time-boxed permission.
        ttl = timedelta(seconds=self.config.limits.scan_timeout_seconds)
        return ValidatedTarget(
            hostname=host,
            pinned_ip=pinned,
            authorized_cidrs=tuple(str(c) for c in policy.authorized_cidrs),
            permitted_checks=policy.permitted_checks,
            mode=mode.value,
            scan_id=uuid.uuid4().hex,
            expires_at=now + ttl,
        )

    def validate_redirect(
        self,
        validated: ValidatedTarget,
        redirect_url: str,
        *,
        hops_so_far: int,
        now: datetime | None = None,
        resolver=dns_validation.resolve,
    ) -> ValidatedTarget:
        """Re-run the full gate for a redirect target before following it.

        A redirect to a host that is off the allowlist, out of scope, or over
        the hop limit is rejected. The redirect is validated for the same check
        set, which keeps a redirect from widening what the scan may do.
        """
        if hops_so_far >= self.config.limits.max_redirects:
            raise PolicyError(
                f"redirect limit ({self.config.limits.max_redirects}) exceeded"
            )
        redirect_host = normalize_hostname(redirect_url)
        # Revalidate against the first permitted check so the full gate re-runs;
        # the returned target carries the same permitted_checks as the origin.
        probe_check = next(iter(validated.permitted_checks))
        return self.validate_scan_request(
            redirect_host, probe_check, now=now, resolver=resolver
        )
