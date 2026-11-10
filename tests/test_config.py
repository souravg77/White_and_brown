"""Config loading / validation tests, including the shipped example file."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.config import load_config, normalize_hostname

EXAMPLE = Path(__file__).resolve().parent.parent / "config" / "targets.example.yaml"


def test_example_config_loads():
    cfg = load_config(EXAMPLE)
    assert cfg.targets
    t = cfg.find_target("security-lab.example")
    assert t is not None
    assert "tls" in t.permitted_checks
    assert t.authorization.owner


def test_missing_authorization_is_rejected(tmp_path):
    bad = tmp_path / "targets.yaml"
    bad.write_text(
        "targets:\n"
        "  - domain: x.example\n"
        "    authorized_cidrs: ['203.0.113.0/24']\n"
        "    permitted_checks: [tls]\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_config(bad)


def test_unknown_check_is_rejected(tmp_path):
    bad = tmp_path / "targets.yaml"
    bad.write_text(
        "targets:\n"
        "  - domain: x.example\n"
        "    authorized_cidrs: ['203.0.113.0/24']\n"
        "    permitted_checks: [tls, nuke_it]\n"
        "    authorization: {owner: me}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_config(bad)


def test_missing_cidrs_is_rejected(tmp_path):
    bad = tmp_path / "targets.yaml"
    bad.write_text(
        "targets:\n"
        "  - domain: x.example\n"
        "    permitted_checks: [tls]\n"
        "    authorization: {owner: me}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_config(bad)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Example.COM.", "example.com"),
        ("https://example.com/path", "example.com"),
        ("example.com:8443", "example.com"),
        ("user@example.com", "example.com"),
        ("[2001:db8::1]", "2001:db8::1"),
    ],
)
def test_normalize_hostname(raw, expected):
    assert normalize_hostname(raw) == expected
