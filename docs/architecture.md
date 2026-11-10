# SENTINEL AI — architecture

A modular security auditing engine for **assets you own or are explicitly
authorized to test**, built to run on **Kali Linux** and to drive the security
tooling already present in the Kali install.

## Layers

```
Desktop app (PySide6)  ── operator UI: targets, scan controls, findings, reports
        │                  (optional localhost FastAPI service for headless use)
Scope & policy engine  ── allowlist, pinned DNS, authorization windows, modes,
        │                  address validation, redirect revalidation, rate limits
Job orchestration      ── DB-backed queue (SQLite BEGIN IMMEDIATE atomic claim),
        │                  per-job network namespace + egress firewall, timeouts,
        │                  cancellation, recovery
Scanner adapters       ── one per Kali tool; absolute path + fixed arg array;
        │                  missing tool -> skipped, never simulated
Verification           ── normalize, fingerprint, deduplicate, recheck safely
        │
Persistence (SQLite)   ── scans, findings, hash-chained audit log, outbox
        │
Notifier               ── per-scan digest; immediate alerts for high/critical/fail
```

## The three design-review safeguards

1. **Scope at the network layer, per job.** Not just app-level checks. See
   [network-egress.md](network-egress.md). Phase 1 ships the policy half
   (pinning, validation, redirect revalidation); the namespace firewall is
   phase 2.
2. **Brown Hat is a time-boxed per-target capability**, not a global switch.
   See `sentinel.modes`. A grant names one target, lists the advanced checks it
   covers, is tied to an authorization reference, and expires on its own.
3. **The AI layer is read-only and defended against prompt injection** from
   scanned pages. See [ai-safety.md](ai-safety.md).

## Platform: Kali Linux

SENTINEL detects and uses the tools that ship with Kali (`sentinel.scanners.tools`)
rather than bundling its own. Each tool is located by absolute path, version-
checked at startup, and reported `available` or `missing`. A `missing` tool
makes its check `skipped`. Kali is Debian-based, so the desktop packaging
(`.deb` / AppImage) targets Debian/Ubuntu derivatives generally.

## Why standard-library-only core

`sentinel.config`, `sentinel.policy.*`, `sentinel.modes`, `sentinel.audit` and
`sentinel.models` depend only on the Python standard library. The security
decisions — what is in scope, what is authorized, what mode applies, what the
audit chain says — therefore have no third-party package in their trust path.
Persistence uses the standard-library `sqlite3` module (single-operator desktop
build), so even the data layer adds no third-party dependency. Pydantic, FastAPI
and PySide6 are optional extras used by the API and desktop layers.

## Build order (phases)

1. **Scope and foundation (done).** Config/allowlist, scope engine, modes,
   audit chain, tool detection, adapter contract, tests.
2. **Persistence and adapters (done).** Per-job egress ruleset generator,
   low-risk real adapters (DNS, headers, TLS, SSH), SQLite persistence,
   migrations and the job queue.
3. **Verification (done).** Normalization and secret redaction before
   persistence, fingerprint deduplication, and repeatable rechecks: a finding
   is verified only if every recheck reproduces it, a false positive if every
   recheck contradicts it, and unverified on mixed answers, errors, timeouts or
   when no verifier exists. Scope is revalidated before rechecks run.
4. Notification outbox with digest delivery — **MVP**.
5. Nmap and ZAP in constrained namespaces; minimal dashboard behind a VPN.
6. AI summaries, then advanced (Brown Hat) testing — each tested in the lab first.
