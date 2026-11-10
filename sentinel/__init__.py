"""SENTINEL AI — a scoped security auditing engine for authorized assets.

Public entry points for the engine. The security-critical core (config, scope,
modes, audit) depends only on the standard library; API, persistence and
desktop layers are optional extras.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .config import Config, TargetPolicy, load_config
from .errors import (
    BlockedDestinationError,
    CheckNotPermittedError,
    NotAuthorizedError,
    OutOfScopeError,
    PolicyError,
    SentinelError,
)
from .models import Finding, ScanResult, ValidatedTarget
from .modes import Mode, ModeManager
from .policy.scope import ScopeEngine

__all__ = [
    "__version__",
    "Config",
    "TargetPolicy",
    "load_config",
    "ScopeEngine",
    "ModeManager",
    "Mode",
    "Finding",
    "ScanResult",
    "ValidatedTarget",
    "SentinelError",
    "PolicyError",
    "OutOfScopeError",
    "BlockedDestinationError",
    "NotAuthorizedError",
    "CheckNotPermittedError",
]
