"""Job worker (scaffolding).

Manual scans are queued and processed by a background worker. Following the
design review, the queue is the database itself: jobs are claimed with
``SELECT ... FOR UPDATE SKIP LOCKED`` (Postgres) or an equivalent atomic claim
on SQLite, which avoids a separate broker for the single-host desktop build.

Background execution exists to process *manually requested* jobs, verification,
notifications and recovery. It never initiates new scans on its own.

Phase 1 ships the entry point and the claim/lease contract; the real processing
loop, retries and recovery land in later phases.
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class WorkerConfig:
    poll_interval_seconds: float = 2.0
    lease_seconds: int = 900


def run(config: WorkerConfig | None = None) -> None:  # pragma: no cover
    """Placeholder worker loop. Real claim/process/recover logic is phase 2+."""
    config = config or WorkerConfig()
    raise NotImplementedError(
        "worker processing loop is implemented in phase 2 "
        "(see docs/architecture.md and the roadmap)"
    )


if __name__ == "__main__":  # pragma: no cover
    run()
