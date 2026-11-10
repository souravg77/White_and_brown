"""Dual-mode / Brown Hat capability tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sentinel.modes import Mode, ModeManager

NOW = datetime(2026, 10, 27, tzinfo=timezone.utc)


def test_default_mode_is_white_hat():
    assert ModeManager().mode_for("lab.example", "tls", NOW) is Mode.WHITE_HAT


def test_grant_enables_brown_hat_for_named_target_and_check():
    m = ModeManager()
    m.grant_brown_hat(
        "lab.example", {"web_active"},
        granted_by="op", authorization_reference="A1",
        ttl=timedelta(hours=1), now=NOW,
    )
    assert m.mode_for("lab.example", "web_active", NOW) is Mode.BROWN_HAT
    # A different target is unaffected — Brown Hat is not a global switch.
    assert m.mode_for("other.example", "web_active", NOW) is Mode.WHITE_HAT
    # A check the grant does not cover is unaffected.
    assert m.mode_for("lab.example", "poc", NOW) is Mode.WHITE_HAT


def test_grant_expires_on_its_own():
    m = ModeManager()
    m.grant_brown_hat(
        "lab.example", {"web_active"},
        granted_by="op", authorization_reference="A1",
        ttl=timedelta(hours=1), now=NOW,
    )
    later = NOW + timedelta(hours=2)
    assert m.mode_for("lab.example", "web_active", later) is Mode.WHITE_HAT
    assert m.active_grants(later) == []


def test_revoke_drops_grants():
    m = ModeManager()
    m.grant_brown_hat(
        "lab.example", {"web_active"},
        granted_by="op", authorization_reference="A1",
        ttl=timedelta(hours=1), now=NOW,
    )
    assert m.revoke("lab.example") == 1
    assert m.mode_for("lab.example", "web_active", NOW) is Mode.WHITE_HAT


def test_zero_ttl_rejected():
    with pytest.raises(ValueError):
        ModeManager().grant_brown_hat(
            "lab.example", {"web_active"},
            granted_by="op", authorization_reference="A1",
            ttl=timedelta(0), now=NOW,
        )


def test_empty_check_set_rejected():
    with pytest.raises(ValueError):
        ModeManager().grant_brown_hat(
            "lab.example", set(),
            granted_by="op", authorization_reference="A1",
            ttl=timedelta(hours=1), now=NOW,
        )
