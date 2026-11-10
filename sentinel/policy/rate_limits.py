"""Resource and rate limits applied to every scan, in every mode.

These are advisory values carried alongside a validated target; the job
orchestrator and scanner adapters are responsible for honouring them. They are
kept here so the policy layer owns the single definition.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    max_concurrent_scans: int = 2
    max_requests_per_second: float = 2.0
    scan_timeout_seconds: int = 600
    max_redirects: int = 3
    max_output_bytes: int = 10 * 1024 * 1024

    def __post_init__(self) -> None:
        for name in (
            "max_concurrent_scans",
            "max_requests_per_second",
            "scan_timeout_seconds",
            "max_redirects",
            "max_output_bytes",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
