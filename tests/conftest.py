"""Shared test fixtures.

A fake resolver lets the scope tests exercise the full gate without real DNS,
so the security logic is tested deterministically and offline.
"""

from __future__ import annotations

import ipaddress
from datetime import date

import pytest

from sentinel.config import Config, TargetPolicy
from sentinel.policy.authorization import Authorization


from helpers import fake_resolver  # noqa: E402


@pytest.fixture
def authorized_target() -> TargetPolicy:
    return TargetPolicy(
        domain="lab.example",
        authorized_cidrs=(ipaddress.ip_network("93.184.216.0/24"),),
        permitted_checks=frozenset({"dns", "http_headers", "tls", "web_baseline", "web_active"}),
        authorization=Authorization(
            owner="Lab owner",
            reference="AUTH-001",
            valid_from=date(2026, 1, 1),
            valid_until=date(2030, 1, 1),
        ),
    )


@pytest.fixture
def config(authorized_target: TargetPolicy) -> Config:
    return Config(targets=(authorized_target,))


@pytest.fixture
def resolver():
    # lab.example resolves inside its authorized /24.
    return fake_resolver({"lab.example": ["93.184.216.34"]})
