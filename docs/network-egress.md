# Per-job network egress enforcement

Scope is enforced **twice**: once in the policy engine before a tool starts
(`sentinel.policy.scope`), and once at the network layer while the tool runs.
This document covers the second layer, which is what stops a spider, a redirect,
a DNS change or a tool bug from reaching a host the operator did not authorize.
App-level checks alone cannot guarantee this, because once a tool is running it
makes its own connections.

## The guarantee

While a scan job runs, the only destinations it can reach are the pinned
addresses in its `ValidatedTarget`, on the permitted ports. Everything else —
other hosts, loopback, RFC 1918, link-local, and the cloud metadata endpoint —
is dropped by the kernel, not by the application.

## Mechanism on Kali Linux

Each scan job runs inside its own **network namespace** with a dedicated veth
pair and an egress firewall built from the job's validated scope:

1. The orchestrator creates a network namespace for the job.
2. It generates an `nftables` ruleset from the job's `authorized_cidrs` and
   permitted ports: `default drop`, then `accept` only the pinned
   address/port pairs. DNS is served by a pinned resolver inside the namespace
   that only answers with the already-validated addresses.
3. The scanner process is launched inside the namespace (`ip netns exec` / a
   namespaced systemd unit). It inherits the firewall and cannot alter it.
4. On job completion or cancellation the namespace and its rules are torn down.

Blocked by the default-drop ruleset, independent of app logic:

- Any address not in the job's `authorized_cidrs`.
- `127.0.0.0/8`, `::1`, RFC 1918, `169.254.0.0/16`, `fe80::/10`.
- `169.254.169.254` and other metadata endpoints (dropped even for a lab).
- IPv6 unless the job explicitly authorizes an IPv6 range.

## Why pinning matters

`ValidatedTarget.pinned_ip` is the address the scope engine checked. The
namespace firewall is built from that pinned value and the job's authorized
CIDRs, and the in-namespace resolver only returns validated addresses. A DNS
record that changes after validation (DNS rebinding) therefore cannot move the
job onto a new address: the kernel has no route to it.

## Degradation

If a job cannot be given its own namespace and firewall (missing privilege,
unsupported host), the orchestrator **refuses to start the job** rather than
fall back to app-level checks only. Failing closed is the whole point of this
layer. The refusal is recorded in the audit log and surfaced as a scan failure.

## Status

Phase 1 ships the policy-layer half (pinning, address validation, redirect
revalidation) and this design. The namespace/nftables orchestration lands in
phase 2 alongside the real scanner adapters, before any tool is wired to a live
target.
