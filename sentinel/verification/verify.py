"""Follow-up verification: repeatable, safe rechecks of supported findings.

A finding starts ``observed`` (a tool reported it). It becomes ``verified`` only
when a deterministic recheck reproduces it every time, ``false_positive`` when
the recheck consistently contradicts it, and stays ``unverified`` otherwise —
including when the recheck errors, times out, gives mixed answers, or no
verifier exists for that kind of finding. Model confidence plays no part.

Rechecks are read-only and minimal: an HTTP ``HEAD`` to the pinned address for a
missing header, a DNS lookup for an inventory record. They run against a
target the scope engine has just revalidated, and in production inside the same
per-job egress namespace as the original scan. Standard library only.
"""

from __future__ import annotations

import concurrent.futures
import http.client
import socket
import ssl
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

from ..models import Finding, ValidatedTarget
from ..policy import dns_validation

VERIFIED = "verified"
FALSE_POSITIVE = "false_positive"
UNVERIFIED = "unverified"

#: How many identical recheck answers make a result "repeatable".
DEFAULT_ATTEMPTS = 2


@dataclass(frozen=True)
class VerificationResult:
    verifier: str
    outcome: str
    confidence: float
    evidence: str
    #: True when the recheck itself failed (error, timeout), as opposed to
    #: giving an inconclusive answer or there being no verifier. Failures are
    #: notified; the other two are not.
    failed: bool = False


class Verifier(Protocol):
    name: str
    #: The permitted check this verifier's recheck falls under.
    check: str

    def verify(self, finding: Finding, target: ValidatedTarget) -> VerificationResult:
        ...


def _unverified(name: str, evidence: str, *, failed: bool = False) -> VerificationResult:
    return VerificationResult(name, UNVERIFIED, 0.5, evidence, failed=failed)


def _decide(name: str, seen: list[bool], what: str) -> VerificationResult:
    """Turn repeated observations into an outcome.

    ``seen[i]`` is True when recheck *i* reproduced the finding. All True means
    verified, all False means false positive, anything else stays unverified.
    """
    n = len(seen)
    hits = sum(seen)
    if hits == n:
        return VerificationResult(name, VERIFIED, 0.95, f"{what} reproduced in {n} of {n} rechecks")
    if hits == 0:
        return VerificationResult(
            name, FALSE_POSITIVE, 0.95, f"{what} not reproduced in any of {n} rechecks"
        )
    return _unverified(name, f"{what} reproduced in {hits} of {n} rechecks (inconsistent)")


# -- HTTP security headers ---------------------------------------------------
class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to the pinned address, with SNI and Host set to the hostname.

    The hostname is never re-resolved: the TCP connection goes to the address
    the scope engine validated.
    """

    def __init__(self, hostname: str, ip: str, *, timeout: float, context: ssl.SSLContext):
        super().__init__(hostname, 443, timeout=timeout, context=context)
        self._pinned_ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def fetch_headers(target: ValidatedTarget, timeout: float = 10.0) -> dict[str, str]:
    """``HEAD /`` against the pinned address; returns response headers.

    Redirects are not followed (http.client never does), so a recheck cannot
    leave the validated host.
    """
    context = ssl.create_default_context()
    conn = _PinnedHTTPSConnection(
        target.hostname, str(target.pinned_ip), timeout=timeout, context=context
    )
    try:
        conn.request("HEAD", "/", headers={"User-Agent": "sentinel-ai-verify"})
        resp = conn.getresponse()
        return {k: v for k, v in resp.getheaders()}
    finally:
        conn.close()


class HeaderVerifier:
    """Rechecks a "missing security header" finding with repeated HEAD requests."""

    name = "http_headers"
    check = "http_headers"

    def __init__(
        self,
        fetch: Callable[[ValidatedTarget], Mapping[str, str]] = fetch_headers,
        *,
        attempts: int = DEFAULT_ATTEMPTS,
        interval: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.fetch = fetch
        self.attempts = attempts
        self.interval = interval
        self.sleep = sleep

    def verify(self, finding: Finding, target: ValidatedTarget) -> VerificationResult:
        header = finding.check_key.strip().lower()
        if not header:
            return _unverified(self.name, "finding has no header name to recheck")
        missing: list[bool] = []
        for i in range(self.attempts):
            if i:
                self.sleep(self.interval)  # stay well under the target's rate limit
            try:
                headers = self.fetch(target)
            except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
                return _unverified(
                    self.name, f"recheck request failed: {type(exc).__name__}", failed=True
                )
            missing.append(header not in {k.lower() for k in headers})
        return _decide(self.name, missing, f"missing {header} header")


# -- DNS inventory -----------------------------------------------------------
class DnsVerifier:
    """Rechecks that a hostname still resolves to the recorded address."""

    name = "dns"
    check = "dns"

    def __init__(
        self,
        resolver: Callable[[str], list] = dns_validation.resolve,
        *,
        attempts: int = DEFAULT_ATTEMPTS,
    ) -> None:
        self.resolver = resolver
        self.attempts = attempts

    def verify(self, finding: Finding, target: ValidatedTarget) -> VerificationResult:
        address = finding.check_key.strip()
        if not address:
            return _unverified(self.name, "finding has no address to recheck")
        seen: list[bool] = []
        for _ in range(self.attempts):
            try:
                addrs = {str(a) for a in self.resolver(target.hostname)}
            except Exception as exc:  # noqa: BLE001 - any resolver failure is a failed recheck
                return _unverified(self.name, f"recheck lookup failed: {exc}", failed=True)
            seen.append(address in addrs)
        return _decide(self.name, seen, f"{target.hostname} -> {address}")


# -- dispatch ----------------------------------------------------------------
def default_verifiers(resolver=dns_validation.resolve) -> dict[str, Verifier]:
    """Verifiers keyed by the finding's ``source_tool``."""
    return {
        "httpx": HeaderVerifier(),
        "dns": DnsVerifier(resolver),
    }


def verify_finding(
    finding: Finding,
    target: ValidatedTarget,
    verifiers: Mapping[str, Verifier],
    *,
    timeout: float = 30.0,
) -> VerificationResult:
    """Run the matching verifier with a hard time limit.

    No verifier, a recheck the target does not permit, a timeout or an
    unexpected error all leave the finding ``unverified``.
    """
    verifier = verifiers.get(finding.source_tool)
    if verifier is None:
        return _unverified("none", "no repeatable verifier for this finding type")
    if not target.allows(verifier.check):
        return _unverified(verifier.name, f"recheck {verifier.check!r} not permitted for target")

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        future = pool.submit(verifier.verify, finding, target)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            return _unverified(verifier.name, f"recheck timed out after {timeout:g}s", failed=True)
        except Exception as exc:  # noqa: BLE001 - a verifier bug must not fail the scan
            return _unverified(verifier.name, f"verifier error: {type(exc).__name__}", failed=True)
    finally:
        # Do not block on a hung recheck; its own socket timeout ends the thread.
        pool.shutdown(wait=False, cancel_futures=True)
