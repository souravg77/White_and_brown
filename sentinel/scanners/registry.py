"""Maps a permitted check to the adapter that implements it.

The worker looks an adapter up here by the validated target's check. Only
low-risk phase-2 adapters are registered; Nmap and ZAP arrive in phase 5 behind
constrained namespaces.
"""

from __future__ import annotations

from .base import BaseScanner
from .dns_inventory import DnsInventoryScanner
from .http_headers import HttpHeadersScanner
from .ssh_audit import SshAuditScanner
from .tls import TlsScanner

_REGISTRY: dict[str, type[BaseScanner]] = {
    DnsInventoryScanner.check: DnsInventoryScanner,
    HttpHeadersScanner.check: HttpHeadersScanner,
    TlsScanner.check: TlsScanner,
    SshAuditScanner.check: SshAuditScanner,
}


def get_scanner(check: str) -> BaseScanner | None:
    cls = _REGISTRY.get(check)
    return cls() if cls is not None else None


def registered_checks() -> list[str]:
    return sorted(_REGISTRY)
