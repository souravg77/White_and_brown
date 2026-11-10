"""Scan service: the pipeline that ties scope, the queue, adapters and storage.

``request_scan`` validates scope up front and queues the job. ``process_next``
claims the next job, **revalidates scope** before running anything (the roadmap
requires scope to be rechecked before tools run), runs the adapter for the
check, normalizes and redacts findings, persists and deduplicates them, then
**revalidates scope again** and runs follow-up verification. It writes audit
entries and queues notifications throughout. A scan that runs some work and
fails elsewhere ends ``partial``, never a clean ``completed``.
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
from .models import Finding
from .verification.fingerprint import fingerprint
from .verification.normalize import normalize_finding, redact
from .verification.verify import (
    UNVERIFIED,
    Verifier,
    default_verifiers,
    verify_finding,
)


class ScanService:
    def __init__(
        self,
        config: Config,
        store: SqliteStore,
        mode_manager: ModeManager | None = None,
        *,
        resolver=dns_validation.resolve,
        verifiers: dict[str, Verifier] | None = None,
        verification_timeout: float = 30.0,
    ) -> None:
        self.config = config
        self.store = store
        self.modes = mode_manager or ModeManager()
        self.scope = ScopeEngine(config, self.modes)
        self.resolver = resolver
        self.verifiers = verifiers if verifiers is not None else default_verifiers(resolver)
        self.verification_timeout = verification_timeout

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
        persisted: list[tuple[str, Finding]] = []
        for raw in result.findings:
            finding = normalize_finding(raw)  # redact secrets before anything stores it
            fp = fingerprint(finding)
            if self.store.upsert_finding(scan_id, finding, fp) == "new":
                new_findings += 1
                self.store.enqueue_notification(
                    f"{scan_id}:{fp}", "finding.new",
                    {"scan_id": scan_id, "title": finding.title, "severity": finding.severity},
                )
            persisted.append((fp, finding))

        verification: dict[str, int] = {}
        if self.config.follow_up_verification and persisted:
            verification = self._verify(scan_id, target, check, persisted, now=now)

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
            "verification": verification,
        }

    def _verify(
        self,
        scan_id: str,
        target: str,
        check: str,
        persisted: list[tuple[str, Finding]],
        *,
        now: datetime | None,
    ) -> dict[str, int]:
        """Revalidate scope, then recheck each finding and record the outcome.

        Returns a count of outcomes. If scope no longer holds, nothing is
        rechecked: every finding is recorded unverified and a verification
        failure is notified.
        """
        counts: dict[str, int] = {}
        try:
            vt = self.scope.validate_scan_request(
                target, check, now=now, resolver=self.resolver
            )
        except PolicyError as exc:
            reason = f"scope revalidation before verification failed: {exc}"
            for fp, _finding in persisted:
                self.store.set_finding_status(fp, UNVERIFIED, 0.5)
                self.store.record_verification(fp, scan_id, "scope", UNVERIFIED, reason)
            self.store.record_audit(
                "verification.skipped", "worker", {"scan_id": scan_id, "reason": str(exc)}
            )
            self.store.enqueue_notification(
                f"{scan_id}:verification:scope", "verification.failed",
                {"scan_id": scan_id, "reason": reason},
            )
            return {UNVERIFIED: len(persisted)}

        for fp, finding in persisted:
            res = verify_finding(
                finding, vt, self.verifiers, timeout=self.verification_timeout
            )
            evidence = redact(res.evidence)
            previous = self.store.set_finding_status(fp, res.outcome, res.confidence)
            self.store.record_verification(fp, scan_id, res.verifier, res.outcome, evidence)
            counts[res.outcome] = counts.get(res.outcome, 0) + 1
            if previous != res.outcome:
                self.store.enqueue_notification(
                    f"{scan_id}:{fp}:status:{res.outcome}", "finding.status_changed",
                    {"scan_id": scan_id, "title": finding.title,
                     "from": previous, "to": res.outcome},
                )
            if res.failed:
                self.store.enqueue_notification(
                    f"{scan_id}:{fp}:verification_failed", "verification.failed",
                    {"scan_id": scan_id, "title": finding.title, "reason": evidence},
                )
        self.store.record_audit(
            "verification.completed", "worker", {"scan_id": scan_id, **counts}
        )
        return counts
