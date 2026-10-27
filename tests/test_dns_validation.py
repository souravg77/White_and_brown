"""Address-validation tests: the never-scan categories and scope math."""

from __future__ import annotations

import ipaddress

import pytest

from sentinel.errors import BlockedDestinationError, OutOfScopeError
from sentinel.policy.dns_validation import (
    hard_blocked_reason,
    sensitive_reason,
    validate_address,
)

PUBLIC_SCOPE = (ipaddress.ip_network("93.184.216.0/24"),)


@pytest.mark.parametrize(
    "addr",
    [
        "169.254.169.254",  # cloud metadata
        "100.100.100.200",  # alibaba metadata
        "224.0.0.1",        # multicast
        "0.0.0.0",          # unspecified
    ],
)
def test_hard_blocked_categories(addr):
    assert hard_blocked_reason(ipaddress.ip_address(addr)) is not None


@pytest.mark.parametrize("addr", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.1.1"])
def test_sensitive_categories(addr):
    assert sensitive_reason(ipaddress.ip_address(addr)) is not None


def test_public_in_scope_ok():
    validate_address(ipaddress.ip_address("93.184.216.34"), PUBLIC_SCOPE)


def test_public_out_of_scope_rejected():
    with pytest.raises(OutOfScopeError):
        validate_address(ipaddress.ip_address("8.8.8.8"), PUBLIC_SCOPE)


def test_private_rejected_without_lab():
    scope = (ipaddress.ip_network("10.0.0.0/8"),)
    with pytest.raises(BlockedDestinationError):
        validate_address(ipaddress.ip_address("10.0.0.5"), scope)


def test_private_allowed_with_lab_and_in_scope():
    scope = (ipaddress.ip_network("10.0.0.0/24"),)
    validate_address(
        ipaddress.ip_address("10.0.0.5"), scope, allow_private_lab=True
    )


def test_ipv4_mapped_ipv6_is_judged_as_ipv4():
    # ::ffff:169.254.169.254 must be blocked as the metadata IP it maps to.
    with pytest.raises(BlockedDestinationError):
        validate_address(
            ipaddress.ip_address("::ffff:169.254.169.254"),
            PUBLIC_SCOPE,
        )


def test_metadata_blocked_before_scope_check():
    # Even if someone lists the metadata IP in scope, it is hard-blocked.
    scope = (ipaddress.ip_network("169.254.169.254/32"),)
    with pytest.raises(BlockedDestinationError):
        validate_address(
            ipaddress.ip_address("169.254.169.254"), scope, allow_private_lab=True
        )
