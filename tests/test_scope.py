"""Scope-engine acceptance tests — the phase-1 gate.

Roadmap acceptance: unlisted hosts, out-of-scope IPs and unsafe redirects are
rejected before any scanner runs. Every rejection path here raises a PolicyError
and never returns a ValidatedTarget.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest

from sentinel.config import Config, TargetPolicy
from sentinel.errors import (
    BlockedDestinationError,
    CheckNotPermittedError,
    NotAuthorizedError,
    OutOfScopeError,
    PolicyError,
)
from sentinel.models import ValidatedTarget
from sentinel.modes import ModeManager
from sentinel.policy.authorization import Authorization
from sentinel.policy.scope import ScopeEngine

from helpers import fake_resolver

import ipaddress

NOW = datetime(2026, 10, 27, tzinfo=timezone.utc)


def engine(config: Config, modes: ModeManager | None = None) -> ScopeEngine:
    return ScopeEngine(config, modes)


def test_allowed_target_returns_pinned_permission(config, resolver):
    vt = engine(config).validate_scan_request(
        "lab.example", "tls", now=NOW, resolver=resolver
    )
    assert isinstance(vt, ValidatedTarget)
    assert vt.hostname == "lab.example"
    assert str(vt.pinned_ip) == "93.184.216.34"
    assert vt.allows("tls")
    assert vt.mode == "white_hat"


def test_unlisted_host_rejected(config, resolver):
    with pytest.raises(OutOfScopeError):
        engine(config).validate_scan_request(
            "not-a-target.example", "tls", now=NOW, resolver=resolver
        )


def test_out_of_scope_ip_rejected(config):
    # Host is allowlisted but resolves outside its authorized /24.
    resolver = fake_resolver({"lab.example": ["8.8.8.8"]})
    with pytest.raises(OutOfScopeError):
        engine(config).validate_scan_request(
            "lab.example", "tls", now=NOW, resolver=resolver
        )


def test_any_resolved_address_out_of_scope_rejects(config):
    # One good address, one out-of-scope address -> reject (all must pass).
    resolver = fake_resolver({"lab.example": ["93.184.216.34", "8.8.8.8"]})
    with pytest.raises(OutOfScopeError):
        engine(config).validate_scan_request(
            "lab.example", "tls", now=NOW, resolver=resolver
        )


def test_metadata_endpoint_blocked_even_if_host_allowlisted(config):
    resolver = fake_resolver({"lab.example": ["169.254.169.254"]})
    with pytest.raises(BlockedDestinationError):
        engine(config).validate_scan_request(
            "lab.example", "tls", now=NOW, resolver=resolver
        )


def test_loopback_blocked_without_lab_opt_in(config):
    resolver = fake_resolver({"lab.example": ["127.0.0.1"]})
    with pytest.raises(BlockedDestinationError):
        engine(config).validate_scan_request(
            "lab.example", "tls", now=NOW, resolver=resolver
        )


def test_expired_authorization_rejected(resolver):
    expired = TargetPolicy(
        domain="lab.example",
        authorized_cidrs=(ipaddress.ip_network("93.184.216.0/24"),),
        permitted_checks=frozenset({"tls"}),
        authorization=Authorization(
            owner="Lab owner",
            valid_from=date(2026, 1, 1),
            valid_until=date(2026, 6, 1),
        ),
    )
    cfg = Config(targets=(expired,))
    with pytest.raises(NotAuthorizedError):
        engine(cfg).validate_scan_request(
            "lab.example", "tls", now=NOW, resolver=resolver
        )


def test_check_not_permitted_for_target(config, resolver):
    with pytest.raises(CheckNotPermittedError):
        engine(config).validate_scan_request(
            "lab.example", "ssh_audit", now=NOW, resolver=resolver
        )


def test_advanced_check_requires_brown_hat_grant(config, resolver):
    # web_active is permitted for the target but is an advanced check; without a
    # Brown Hat grant it must be refused.
    with pytest.raises(CheckNotPermittedError):
        engine(config).validate_scan_request(
            "lab.example", "web_active", now=NOW, resolver=resolver
        )


def test_advanced_check_allowed_with_active_grant(config, resolver):
    modes = ModeManager()
    modes.grant_brown_hat(
        "lab.example",
        {"web_active"},
        granted_by="operator",
        authorization_reference="AUTH-001",
        ttl=timedelta(hours=1),
        now=NOW,
    )
    vt = engine(config, modes).validate_scan_request(
        "lab.example", "web_active", now=NOW, resolver=resolver
    )
    assert vt.mode == "brown_hat"


def test_expired_grant_does_not_authorize_advanced_check(config, resolver):
    modes = ModeManager()
    modes.grant_brown_hat(
        "lab.example",
        {"web_active"},
        granted_by="operator",
        authorization_reference="AUTH-001",
        ttl=timedelta(hours=1),
        now=NOW,
    )
    later = NOW + timedelta(hours=2)
    with pytest.raises(CheckNotPermittedError):
        engine(config, modes).validate_scan_request(
            "lab.example", "web_active", now=later, resolver=resolver
        )


def test_redirect_to_unlisted_host_rejected(config, resolver):
    vt = engine(config).validate_scan_request(
        "lab.example", "web_baseline", now=NOW, resolver=resolver
    )
    with pytest.raises(PolicyError):
        engine(config).validate_redirect(
            vt, "https://evil.example/login", hops_so_far=0, now=NOW, resolver=resolver
        )


def test_redirect_within_scope_allowed(config, resolver):
    vt = engine(config).validate_scan_request(
        "lab.example", "web_baseline", now=NOW, resolver=resolver
    )
    redirected = engine(config).validate_redirect(
        vt, "https://lab.example/dashboard", hops_so_far=0, now=NOW, resolver=resolver
    )
    assert redirected.hostname == "lab.example"


def test_redirect_over_hop_limit_rejected(config, resolver):
    vt = engine(config).validate_scan_request(
        "lab.example", "web_baseline", now=NOW, resolver=resolver
    )
    with pytest.raises(PolicyError):
        engine(config).validate_redirect(
            vt, "https://lab.example/x", hops_so_far=3, now=NOW, resolver=resolver
        )


def test_private_lab_opt_in_allows_authorized_private_range(resolver):
    lab = TargetPolicy(
        domain="internal-lab.example",
        authorized_cidrs=(ipaddress.ip_network("10.10.0.0/24"),),
        permitted_checks=frozenset({"tls"}),
        authorization=Authorization(owner="Lab", valid_until=date(2030, 1, 1)),
        allow_private_lab=True,
    )
    cfg = Config(targets=(lab,))
    r = fake_resolver({"internal-lab.example": ["10.10.0.5"]})
    vt = engine(cfg).validate_scan_request(
        "internal-lab.example", "tls", now=NOW, resolver=r
    )
    assert str(vt.pinned_ip) == "10.10.0.5"


def test_private_lab_opt_in_still_blocks_metadata(resolver):
    lab = TargetPolicy(
        domain="internal-lab.example",
        authorized_cidrs=(ipaddress.ip_network("169.254.0.0/16"),),
        permitted_checks=frozenset({"tls"}),
        authorization=Authorization(owner="Lab", valid_until=date(2030, 1, 1)),
        allow_private_lab=True,
    )
    cfg = Config(targets=(lab,))
    r = fake_resolver({"internal-lab.example": ["169.254.169.254"]})
    with pytest.raises(BlockedDestinationError):
        engine(cfg).validate_scan_request(
            "internal-lab.example", "tls", now=NOW, resolver=r
        )
