# SENTINEL AI

A modular security auditing tool for **assets you own or are explicitly
authorized to test**, built to run as a desktop application on **Kali Linux**.
SENTINEL drives the security tools already installed in Kali behind a single
scope and policy layer, verifies what they find with repeatable evidence, and
keeps a hash-chained audit record of every scan, finding and failure.

> **Status: phase 2 in progress.** Phase 1 (scope engine, dual-mode capability
> model, audit chain, Kali tool detection, adapter contract, desktop shell) is
> complete. Phase 2 adds SQLite persistence and the database job queue, the
> per-job egress-firewall design and ruleset generator, and the first low-risk
> scanner adapters (DNS, HTTP headers, TLS, ssh-audit). Nmap/ZAP and the
> dashboard follow. See [docs/architecture.md](docs/architecture.md).

## Principles

- **Scope before scanners.** Every tool runs behind the same policy layer. A
  host that is not allowlisted, resolves outside its authorized IPs, or lands on
  a blocked address (loopback, private, link-local, cloud metadata) is rejected
  before any tool starts.
- **Public is not permission.** Reachability never authorizes a scan. Every
  target needs an authorization record with an owner and a time window.
- **Real results only.** A missing or failing tool is recorded as `skipped` or
  `failed`. Results are never simulated.
- **Verified, not guessed.** A finding stays `unverified` until repeatable
  technical evidence supports it. Model confidence never verifies a finding.
- **Scope at the network layer too.** Scope is enforced in the policy engine and
  again by a per-job egress firewall while the tool runs. See
  [docs/network-egress.md](docs/network-egress.md).

## Platform

SENTINEL runs on Kali Linux and uses the tools in the Kali install (nmap,
testssl.sh, ssh-audit, httpx, OWASP ZAP, gitleaks, trivy, semgrep, subfinder,
dnsx) rather than bundling its own. Each is located by absolute path,
version-checked at startup, and reported available or missing. Kali is
Debian-based, so the `.deb` / AppImage packaging targets Debian/Ubuntu
derivatives generally — see [packaging/](packaging/).

## Operating modes

- **White Hat (default):** reconnaissance, configuration audits, baseline web
  scanning and safe verification against authorized assets.
- **Advanced testing ("Brown Hat"):** authenticated testing and controlled
  proof-of-concept checks. It is **not a global switch** — it is granted per
  engagement, for one named target and a fixed time window, tied to an
  authorization record, and it expires on its own (`sentinel.modes`).

In both modes, scope enforcement, secret redaction, resource limits and audit
logging stay on. No component, including any AI component, can change its own
permissions or mode.

## AI's role

The model is read-only: it summarizes evidence and drafts remediation and
reports. It never chooses targets, starts tools, switches modes or marks
findings verified. Scanned content is treated as untrusted input to defend
against prompt injection, and evidence is redacted before any model sees it. See
[docs/ai-safety.md](docs/ai-safety.md).

## Layout

```
sentinel/
  config.py          allowlist + target policy loading
  modes.py           White Hat / Brown Hat capability model
  audit.py           hash-chained audit log
  models.py          Finding, ScanResult, ValidatedTarget
  cli.py             headless CLI (tools / targets / scope dry-run)
  policy/            scope engine, DNS/address validation, authorization, limits
  scanners/          adapter contract + Kali tool detection
  verification/      follow-up verification (phase 3)
  notifications/     outbox (phase 4)
  db/                persistence (phase 2)
  api/               optional localhost control API
desktop/             PySide6 desktop shell
config/targets.example.yaml
docs/                architecture, network-egress, ai-safety
packaging/           .desktop entry + Debian/AppImage plan
tests/               scope-enforcement acceptance tests + unit tests
```

The security-critical core (`config`, `policy`, `modes`, `audit`, `models`)
depends only on the Python standard library, so scope decisions have no
third-party package in their trust path.

## Quick start (development)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,desktop]'

pytest -q                                   # run the test suite
cp config/targets.example.yaml config/targets.yaml   # then edit it
sentinel tools                              # Kali tool health check
sentinel check <your-authorized-host> tls   # scope dry-run (launches nothing)
sentinel-desktop                            # desktop UI
```

## Responsible use

Use SENTINEL only against systems you own or have explicit written permission to
test. Mode switching does not grant permission to test a target. Check your
hosting provider's acceptable-use policy before scanning from it, and stop
immediately if a scan affects anything outside its intended scope.

## License

Not yet chosen.
