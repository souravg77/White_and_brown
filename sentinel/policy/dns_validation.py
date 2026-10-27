"""Destination validation — the network-boundary half of scope enforcement.

Every address a scanner is about to touch passes through here, including the
address behind a redirect. The rules fail closed:

* Metadata, multicast, reserved and unspecified addresses are **hard-blocked**:
  no configuration can authorize them.
* Loopback, private and link-local addresses are blocked unless the target
  explicitly opts into an internal lab (``allow_private_lab``) *and* the
  resolved address falls inside one of its authorized CIDRs.
* The resolved address must fall inside one of the target's authorized CIDRs.

This module does only the address math and lookups; it has no third-party
dependencies on purpose, so the security-critical path has no package supply
chain to trust. The pinned result it returns is what a scanner must connect to,
which is what defeats DNS-rebinding between the check and the connection.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable, Sequence

from ..errors import BlockedDestinationError, OutOfScopeError, ResolutionError

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Cloud-provider metadata endpoints. 169.254.169.254 is link-local and so is
# already caught below, but it is listed explicitly so the block is obvious and
# survives any future loosening of the link-local rule.
_METADATA_IPS: frozenset[IPAddress] = frozenset(
    ipaddress.ip_address(a)
    for a in (
        "169.254.169.254",  # AWS / GCP / Azure / OpenStack IMDS
        "100.100.100.200",  # Alibaba Cloud
        "fd00:ec2::254",    # AWS IMDS over IPv6
    )
)


def _unwrap(ip: IPAddress) -> IPAddress:
    """Collapse IPv4-mapped / 6to4 / Teredo IPv6 forms to the real IPv4 address.

    Alternate encodings are a classic scope-bypass trick, so an address that is
    really IPv4 wearing an IPv6 costume is judged as the IPv4 address it maps to.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip.sixtofour is not None:
            return ip.sixtofour
        if ip.teredo is not None:
            return ip.teredo[1]
    return ip


def hard_blocked_reason(ip: IPAddress) -> str | None:
    """Return why ``ip`` is in a never-scan category, or ``None`` if it is not.

    These categories cannot be overridden by any target configuration.
    """
    ip = _unwrap(ip)
    if ip in _METADATA_IPS:
        return "cloud metadata endpoint"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_reserved:
        return "reserved address"
    return None


def sensitive_reason(ip: IPAddress) -> str | None:
    """Return why ``ip`` is loopback/private/link-local, or ``None``.

    These are blocked by default but may be authorized for an explicit lab.
    """
    ip = _unwrap(ip)
    if ip.is_loopback:
        return "loopback address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_private:
        return "private address"
    return None


def in_scope(ip: IPAddress, authorized_cidrs: Iterable[IPNetwork]) -> bool:
    """True if ``ip`` falls inside one of the authorized CIDRs."""
    ip = _unwrap(ip)
    return any(ip in cidr for cidr in authorized_cidrs)


def validate_address(
    ip: IPAddress,
    authorized_cidrs: Sequence[IPNetwork],
    *,
    allow_private_lab: bool = False,
) -> None:
    """Raise if ``ip`` must not be scanned; return ``None`` if it is in scope.

    Raises :class:`BlockedDestinationError` for never-scan categories and for
    sensitive addresses outside an authorized lab, and :class:`OutOfScopeError`
    when the address is simply not inside the authorized CIDRs.
    """
    ip = _unwrap(ip)

    reason = hard_blocked_reason(ip)
    if reason is not None:
        raise BlockedDestinationError(f"{ip} is a {reason}")

    sensitive = sensitive_reason(ip)
    if sensitive is not None and not allow_private_lab:
        raise BlockedDestinationError(
            f"{ip} is a {sensitive}; not scanned unless an internal lab is "
            f"explicitly authorized (allow_private_lab)"
        )

    if not in_scope(ip, authorized_cidrs):
        raise OutOfScopeError(f"{ip} is outside the authorized scope")


def resolve(hostname: str) -> list[IPAddress]:
    """Resolve ``hostname`` to every A/AAAA address, or raise ResolutionError.

    A literal IP passes straight through. Resolution happens once, here; the
    caller pins the address it validated so a later lookup cannot swap it.
    """
    try:
        return [ipaddress.ip_address(hostname)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ResolutionError(f"could not resolve {hostname!r}: {exc}") from exc
    addresses: list[IPAddress] = []
    seen: set[str] = set()
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.add(addr)
            addresses.append(ipaddress.ip_address(addr))
    if not addresses:
        raise ResolutionError(f"no addresses for {hostname!r}")
    return addresses
