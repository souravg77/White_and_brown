"""Core domain objects passed between the policy, scanner and verification layers.

Kept to the standard library (dataclasses) so the security-critical path has no
third-party dependency. The API and persistence layers may wrap these in
Pydantic / SQLAlchemy models, but the engine itself only needs these.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address

Severity = str  # one of: info, low, medium, high, critical
Status = str    # one of: observed, verified, false_positive, unverified

SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
STATUSES: tuple[str, ...] = ("observed", "verified", "false_positive", "unverified")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ValidatedTarget:
    """The output of the scope engine and the only thing a scanner may act on.

    ``pinned_ip`` is the address that was validated. A scanner must connect to
    this address, not re-resolve the hostname, so a DNS change between the check
    and the connection cannot move the scan off-scope. ``permitted_checks`` is
    already intersected with what the active mode allows.
    """

    hostname: str
    pinned_ip: IPv4Address | IPv6Address
    authorized_cidrs: tuple[str, ...]
    permitted_checks: frozenset[str]
    mode: str
    scan_id: str
    expires_at: datetime
    validated_at: datetime = field(default_factory=_utcnow)

    def allows(self, check: str) -> bool:
        return check in self.permitted_checks


@dataclass
class Finding:
    """A normalized result from a scanner. Mirrors the roadmap's Finding model.

    Evidence is summarized here; detailed evidence is stored separately and
    redacted of secrets before persistence or notification.
    """

    asset: str
    source_tool: str
    title: str
    severity: Severity
    evidence_summary: str
    remediation: str
    confidence: float = 0.0
    status: Status = "observed"
    first_seen: datetime = field(default_factory=_utcnow)
    #: Structured discriminator (header name, testssl id, algorithm, address…)
    #: used for fingerprinting and by follow-up verifiers. Never free text.
    check_key: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity {self.severity!r}")
        if self.status not in STATUSES:
            raise ValueError(f"invalid status {self.status!r}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


class ScanOutcome(str):
    """Marker for the terminal state of a scan or an individual adapter run."""


# A scan or adapter run always ends in exactly one of these states. "partial"
# is distinct from "completed" so a scan that ran some checks and failed others
# is never reported as a clean success.
OUTCOMES: tuple[str, ...] = (
    "completed",
    "partial",
    "failed",
    "skipped",
    "cancelled",
)


@dataclass
class ScanResult:
    """What one scanner adapter produced, including how it ended."""

    tool: str
    outcome: str
    findings: list[Finding] = field(default_factory=list)
    exit_code: int | None = None
    tool_version: str = ""
    started_at: datetime = field(default_factory=_utcnow)
    finished_at: datetime | None = None
    error: str = ""

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ValueError(f"invalid outcome {self.outcome!r}")
