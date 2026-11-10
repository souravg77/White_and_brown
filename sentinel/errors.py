"""Exceptions for SENTINEL AI.

Scope and policy failures are their own exception hierarchy so callers can
distinguish "rejected on purpose" from "something broke". Every scanner path
must fail closed: if scope cannot be proven, the scan does not run.
"""

from __future__ import annotations


class SentinelError(Exception):
    """Base class for all SENTINEL errors."""


class PolicyError(SentinelError):
    """A request was rejected by the scope and policy layer."""


class OutOfScopeError(PolicyError):
    """Target host or resolved address is not within the authorized scope."""


class BlockedDestinationError(PolicyError):
    """Destination is in a category that is never scanned (loopback, metadata, …)."""


class NotAuthorizedError(PolicyError):
    """No valid authorization record covers this target right now."""


class CheckNotPermittedError(PolicyError):
    """The requested check is not permitted for this target or in this mode."""


class ModeError(SentinelError):
    """Invalid operating-mode transition or an expired capability grant."""


class ResolutionError(PolicyError):
    """The target hostname could not be resolved to an address."""
