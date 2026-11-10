"""Job worker loop.

Claims queued scans from the database and processes them through
:class:`sentinel.service.ScanService`. Background execution exists to process
*manually requested* jobs, verification and notifications — it never starts new
scans on its own. The loop is cancellable and recovers on restart because scan
state lives in the database, not in memory.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .config import Config
from .db.store import SqliteStore
from .modes import ModeManager
from .service import ScanService


@dataclass
class WorkerConfig:
    poll_interval_seconds: float = 2.0


def run(
    config: Config,
    store: SqliteStore,
    *,
    mode_manager: ModeManager | None = None,
    worker_config: WorkerConfig | None = None,
    stop=lambda: False,
) -> None:
    """Process queued scans until ``stop()`` returns True.

    ``stop`` is injectable so the desktop app or a signal handler can end the
    loop cleanly; tests pass a predicate that stops when the queue drains.
    """
    worker_config = worker_config or WorkerConfig()
    service = ScanService(config, store, mode_manager)
    while not stop():
        summary = service.process_next()
        if summary is None:
            time.sleep(worker_config.poll_interval_seconds)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(
        "Run the worker from the application entry point with a loaded config "
        "and store; see sentinel.worker.run()."
    )
