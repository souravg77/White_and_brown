"""Configuration loading: targets, authorized CIDRs, permitted checks, limits.

The config file is the allowlist. A host that is not described here cannot be
scanned. Loading is strict: an unparseable CIDR, an unknown check name or a
missing authorization is an error at load time, not a surprise at scan time.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from .policy.authorization import Authorization
from .policy.rate_limits import Limits

# The checks SENTINEL understands. A target's permitted_checks must be a subset.
KNOWN_CHECKS: frozenset[str] = frozenset(
    {
        # White Hat / safe checks
        "dns",
        "http_headers",
        "tls",
        "web_baseline",
        "ssh_audit",
        "ports",
        "secrets",
        "dependencies",
        # Advanced-testing checks (require a Brown Hat grant)
        "web_active",
        "auth_testing",
        "poc",
    }
)

ADVANCED_CHECKS: frozenset[str] = frozenset({"web_active", "auth_testing", "poc"})
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class TargetPolicy:
    """Everything the scope engine needs to judge one target."""

    domain: str
    authorized_cidrs: tuple[IPNetwork, ...]
    permitted_checks: frozenset[str]
    authorization: Authorization
    allow_private_lab: bool = False

    def normalized_domain(self) -> str:
        return normalize_hostname(self.domain)


@dataclass(frozen=True)
class Config:
    targets: tuple[TargetPolicy, ...]
    limits: Limits = field(default_factory=Limits)
    follow_up_verification: bool = True

    def find_target(self, hostname: str) -> TargetPolicy | None:
        host = normalize_hostname(hostname)
        for target in self.targets:
            if target.normalized_domain() == host:
                return target
        return None


def normalize_hostname(hostname: str) -> str:
    """Lower-case, strip a trailing dot, drop an accidental scheme/port/path.

    Normalization is deliberately conservative: it only tidies obvious input
    noise so the allowlist match is reliable. It does not try to be clever
    about IDNs beyond IDNA encoding.
    """
    host = hostname.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    host = host.split("@")[-1]
    if host.startswith("[") and "]" in host:  # bracketed IPv6 literal
        host = host[1 : host.index("]")]
    elif host.count(":") == 1:  # host:port (not an IPv6 literal)
        host = host.split(":", 1)[0]
    host = host.rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        pass
    return host


def _parse_date(value: Any, field_name: str) -> date | None:
    if value is None:
        return None
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise ValueError(f"{field_name}: invalid date {value!r}") from exc


def _parse_target(raw: dict[str, Any]) -> TargetPolicy:
    domain = raw.get("domain")
    if not domain:
        raise ValueError("target is missing 'domain'")

    cidrs_raw = raw.get("authorized_cidrs") or []
    if not cidrs_raw:
        raise ValueError(f"target {domain!r} has no authorized_cidrs")
    cidrs: list[IPNetwork] = []
    for c in cidrs_raw:
        try:
            cidrs.append(ipaddress.ip_network(str(c), strict=False))
        except ValueError as exc:
            raise ValueError(f"target {domain!r}: bad CIDR {c!r}") from exc

    checks = frozenset(raw.get("permitted_checks") or [])
    unknown = checks - KNOWN_CHECKS
    if unknown:
        raise ValueError(f"target {domain!r}: unknown checks {sorted(unknown)}")

    auth_raw = raw.get("authorization") or {}
    owner = auth_raw.get("owner")
    if not owner:
        raise ValueError(f"target {domain!r} has no authorization.owner")
    authorization = Authorization(
        owner=str(owner),
        reference=str(auth_raw.get("reference", "")),
        valid_from=_parse_date(auth_raw.get("valid_from"), "valid_from"),
        valid_until=_parse_date(auth_raw.get("valid_until"), "valid_until"),
    )

    return TargetPolicy(
        domain=str(domain),
        authorized_cidrs=tuple(cidrs),
        permitted_checks=checks,
        authorization=authorization,
        allow_private_lab=bool(raw.get("allow_private_lab", False)),
    )


def load_config(path: str | Path) -> Config:
    """Load and validate a targets YAML file into a :class:`Config`."""
    import yaml  # local import: only needed when loading from a file

    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    targets_raw = data.get("targets")
    if not targets_raw:
        raise ValueError("config has no 'targets'")

    targets = tuple(_parse_target(t) for t in targets_raw)

    limits_raw = data.get("limits") or {}
    limits = Limits(
        max_concurrent_scans=int(limits_raw.get("max_concurrent_scans", 2)),
        max_requests_per_second=float(limits_raw.get("max_requests_per_second", 2.0)),
        scan_timeout_seconds=int(limits_raw.get("scan_timeout_seconds", 600)),
        max_redirects=int(limits_raw.get("max_redirects", 3)),
        max_output_bytes=int(limits_raw.get("max_output_bytes", 10 * 1024 * 1024)),
    )

    assessment = data.get("assessment") or {}
    return Config(
        targets=targets,
        limits=limits,
        follow_up_verification=bool(assessment.get("follow_up_verification", True)),
    )
