"""Scan service: the pipeline that ties scope, the queue, adapters and storage.

``request_scan`` validates scope up front and queues the job. ``process_next``
claims the next job, **revalidates scope** before running anything (the roadmap
requires scope to be rechecked before tools run), runs the adapter for the
check, persists and deduplicates findings, writes audit entries and queues
notifications. A scan that runs some work and fails elsewhere ends ``partial``,
never a clean ``completed``.
"""

from __future__ import annotations

from datetime import datetime

from .config import Config
from .db.store import SqliteStore
from .errors import PolicyError
from .models import ValidatedTarget
from .modes import ModeManager
from .policy import dns_validation
from .policy.scope import ScopeEngine
from .scanners.registry import get_scanner
from .verification.fingerprint import fingerprint


class ScanService:
    def __init__(
        self,
        config: Config,
        store: SqliteStore,
        mode_manager: ModeManager | None = None,
        *,
        resolver=dns_validation.resolve,
    ) -> None:
        self.config = config
        self.store = store
        self.modes = mode_manager or ModeManager()
        self.scope = ScopeEngine(config, self.modes)
        self.resolver = resolver

    def request_scan(
        self, target: str, check: str, requested_by: str, *, now: datetime | None = None
    ) -> ValidatedTarget:
        """Validate scope and queue a scan. Raises PolicyError if out of scope."""
        vt = self.scope.validate_scan_request(
            target, check, now=now, resolver=self.resolver
        )
        self.store.enqueue_scan(
            vt.scan_id, vt.hostname, check, vt.mode, requested_by, str(vt.pinned_ip)
        )
        self.store.record_audit(
            "scan.requested",
            requested_by,
            {"scan_id": vt.scan_id, "target": vt.hostname, "check": check, "mode": vt.mode},
        )
        return vt

    def process_next(self, *, now: datetime | None = None) -> dict | None:
        """Claim and process one queued scan. Returns a summary, or None if idle."""
        row = self.store.claim_next_scan()
        if row is None:
            return None
        scan_id, target, check = row["id"], row["target"], row["check_name"]

        # Revalidate scope before any tool runs; scope may have changed since queueing.
        try:
            vt = self.scope.validate_scan_request(
                target, check, now=now, resolver=self.resolver
            )
            vt = ValidatedTarget(
                hostname=vt.hostname, pinned_ip=vt.pinned_ip,
                authorized_cidrs=vt.authorized_cidrs, permitted_checks=vt.permitted_checks,
                mode=vt.mode, scan_id=scan_id, expires_at=vt.expires_at,
            )
        except PolicyError as exc:
            self.store.finish_scan(scan_id, "failed", f"scope revalidation failed: {exc}")
            self.store.record_audit("scan.rejected", "worker", {"scan_id": scan_id, "reason": str(exc)})
            self.store.enqueue_notification(
                f"{scan_id}:rejected", "scan.failed", {"scan_id": scan_id, "reason": str(exc)}
            )
            return {"scan_id": scan_id, "state": "failed", "reason": str(exc)}

        scanner = get_scanner(check)
        if scanner is None:
            self.store.finish_scan(scan_id, "failed", f"no adapter for check {check!r}")
            self.store.record_audit("scan.failed", "worker", {"scan_id": scan_id, "reason": "no adapter"})
            return {"scan_id": scan_id, "state": "failed", "reason": "no adapter"}

        result = scanner.run(vt)
        new_findings = 0
        for finding in result.findings:
            fp = fingerprint(finding)
            if self.store.upsert_finding(scan_id, finding, fp) == "new":
                new_findings += 1
                self.store.enqueue_notification(
                    f"{scan_id}:{fp}", "finding.new",
                    {"scan_id": scan_id, "title": finding.title, "severity": finding.severity},
                )

        # Map adapter outcome to the scan's terminal state.
        state = {
            "completed": "completed",
            "partial": "partial",
            "skipped": "partial",  # a skipped check is not a clean full success
            "failed": "failed",
            "cancelled": "cancelled",
        }.get(result.outcome, "failed")

        if result.outcome in ("failed", "skipped"):
            self.store.enqueue_notification(
                f"{scan_id}:{result.outcome}", f"scan.{result.outcome}",
                {"scan_id": scan_id, "tool": result.tool, "error": result.error},
            )
        self.store.finish_scan(scan_id, state, result.error)
        self.store.record_audit(
            "scan.finished", "worker",
            {"scan_id": scan_id, "state": state, "tool": result.tool,
             "findings": len(result.findings), "new": new_findings},
        )
        return {
            "scan_id": scan_id, "state": state, "tool": result.tool,
            "findings": len(result.findings), "new": new_findings, "error": result.error,
        }
