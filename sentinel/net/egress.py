"""Per-job egress firewall: scope enforced at the kernel, not just in app code.

While a scanner runs it can open its own connections (a web spider follows
links, a redirect points elsewhere, a tool has a bug). App-level checks cannot
contain that once the tool is running. So each scan job runs inside its own
network namespace whose egress firewall is built from the job's validated scope:
**default drop**, then accept only the pinned address on the ports the check
needs. Everything else — other hosts, RFC 1918, link-local, loopback-to-network
and the cloud metadata endpoint — is dropped by the kernel.

This module has two parts:

* :func:`build_ruleset` — a pure function that renders the nftables ruleset from
  a pinned IP and a port set. Fully unit-tested; no privileges needed.
* :func:`namespace_commands` — builds the argument arrays that set the namespace
  up on a real Kali host. Returned as lists (never shell strings) so target data
  is never interpolated into a shell. Execution happens only on a privileged
  host and fails closed.

The ruleset is built from ``ValidatedTarget.pinned_ip`` — the exact address the
scope engine checked — so a DNS record that changes after validation cannot move
the job: the kernel has no route to the new address.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence

from ..models import ValidatedTarget

# Ports each check is allowed to reach. Low-risk phase-2 adapters only.
_CHECK_PORTS: dict[str, tuple[int, ...]] = {
    "dns": (53,),
    "http_headers": (80, 443),
    "web_baseline": (80, 443),
    "tls": (443,),
    "ssh_audit": (22,),
    "ports": tuple(),  # nmap defines its own set; handled in phase 5 (constrained)
}

# Addresses that are dropped in every job ruleset regardless of scope, as
# defence in depth behind the scope engine's own hard-block list.
_ALWAYS_DROP = (
    "169.254.169.254",
    "fd00:ec2::254",
)


def ports_for_check(check: str) -> tuple[int, ...]:
    if check not in _CHECK_PORTS:
        raise ValueError(f"no egress port policy for check {check!r}")
    return _CHECK_PORTS[check]


def build_ruleset(pinned_ip: str, ports: Sequence[int]) -> str:
    """Render an nftables ruleset: default-drop egress, accept only pinned/ports.

    Raises ``ValueError`` on an empty port set — a job with nothing to reach
    should not have been started, and an all-open ruleset must never be the
    accidental result.
    """
    ip = ipaddress.ip_address(pinned_ip)
    if not ports:
        raise ValueError("refusing to build a ruleset with no permitted ports")

    family = "ip6" if ip.version == 6 else "ip"
    daddr = f"{family} daddr {ip}"
    port_match = "{ " + ", ".join(str(p) for p in sorted(set(ports))) + " }"

    drop_lines = "\n".join(
        f"        {('ip6' if ipaddress.ip_address(d).version == 6 else 'ip')} "
        f"daddr {d} drop"
        for d in _ALWAYS_DROP
    )

    return f"""\
# Generated per scan job. Default-drop egress; only the pinned destination is
# reachable. Do not edit by hand.
table inet sentinel_job {{
    chain output {{
        type filter hook output priority 0; policy drop;

        # Allow the namespace's own loopback and established flows.
        oifname "lo" accept
        ct state established,related accept

        # Defence in depth: never reach metadata endpoints.
{drop_lines}

        # The one authorized destination for this job.
        {daddr} tcp dport {port_match} ct state new accept
    }}
}}
"""


def namespace_commands(
    target: ValidatedTarget, ns_name: str, ruleset_path: str
) -> list[list[str]]:
    """Argument arrays to create the job's namespace and load its firewall.

    Each element is a fixed argument list (no shell). The caller runs these on a
    privileged Kali host; if any step fails the job must not start.
    """
    return [
        ["ip", "netns", "add", ns_name],
        ["ip", "netns", "exec", ns_name, "ip", "link", "set", "lo", "up"],
        ["ip", "netns", "exec", ns_name, "nft", "-f", ruleset_path],
    ]


def teardown_commands(ns_name: str) -> list[list[str]]:
    return [["ip", "netns", "del", ns_name]]
