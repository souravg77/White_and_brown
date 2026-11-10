"""Per-job egress ruleset tests."""

from __future__ import annotations

import pytest

from sentinel.net.egress import (
    build_ruleset,
    namespace_commands,
    ports_for_check,
    teardown_commands,
)


def test_default_drop_policy_present():
    rs = build_ruleset("93.184.216.34", [443])
    assert "policy drop" in rs


def test_only_pinned_ip_and_ports_accepted():
    rs = build_ruleset("93.184.216.34", [80, 443])
    assert "ip daddr 93.184.216.34 tcp dport { 80, 443 } ct state new accept" in rs
    # No other host is granted access.
    assert rs.count("ct state new accept") == 1


def test_metadata_endpoint_dropped():
    rs = build_ruleset("93.184.216.34", [443])
    assert "ip daddr 169.254.169.254 drop" in rs


def test_ipv6_target_uses_ip6_family():
    rs = build_ruleset("2606:2800:220:1:248:1893:25c8:1946", [443])
    assert "ip6 daddr 2606:2800:220:1:248:1893:25c8:1946 tcp dport" in rs


def test_empty_ports_refused():
    with pytest.raises(ValueError):
        build_ruleset("93.184.216.34", [])


def test_ports_for_check():
    assert ports_for_check("tls") == (443,)
    assert ports_for_check("ssh_audit") == (22,)
    with pytest.raises(ValueError):
        ports_for_check("unknown_check")


def test_namespace_commands_are_arg_arrays_no_shell():
    from sentinel.models import ValidatedTarget
    import ipaddress
    from datetime import datetime, timezone

    vt = ValidatedTarget(
        hostname="lab.example",
        pinned_ip=ipaddress.ip_address("93.184.216.34"),
        authorized_cidrs=("93.184.216.0/24",),
        permitted_checks=frozenset({"tls"}),
        mode="white_hat",
        scan_id="abc",
        expires_at=datetime.now(timezone.utc),
    )
    cmds = namespace_commands(vt, "sentinel-abc", "/tmp/rules.nft")
    assert all(isinstance(c, list) for c in cmds)
    assert cmds[0] == ["ip", "netns", "add", "sentinel-abc"]
    assert teardown_commands("sentinel-abc") == [["ip", "netns", "del", "sentinel-abc"]]
