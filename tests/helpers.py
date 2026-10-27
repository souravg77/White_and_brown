"""Test helpers importable by test modules and conftest."""

from __future__ import annotations

import ipaddress


def fake_resolver(mapping: dict[str, list[str]]):
    """Return a resolver that looks hostnames up in ``mapping`` (no real DNS)."""

    def _resolve(hostname: str):
        from sentinel.errors import ResolutionError

        try:
            return [ipaddress.ip_address(hostname)]
        except ValueError:
            pass
        if hostname not in mapping:
            raise ResolutionError(f"no fake record for {hostname!r}")
        return [ipaddress.ip_address(a) for a in mapping[hostname]]

    return _resolve
