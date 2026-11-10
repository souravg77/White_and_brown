"""Deterministic finding fingerprints for deduplication.

A fingerprint identifies "the same issue on the same asset" so repeated scans
update one finding and keep its history, instead of creating duplicates. It is
deliberately independent of volatile fields (timestamps, confidence, evidence
wording): two findings with the same asset, tool, check key and title are the
same finding. Standard library only.
"""

from __future__ import annotations

import hashlib

from ..models import Finding


def fingerprint(finding: Finding, key: str = "") -> str:
    """Return a stable hex fingerprint for a finding.

    ``key`` is an optional extra discriminator (e.g. a port, header name or
    CVE id) for adapters that can produce several findings with the same title
    on one asset.
    """
    parts = [
        finding.asset.strip().lower(),
        finding.source_tool.strip().lower(),
        finding.title.strip().lower(),
        key.strip().lower(),
    ]
    joined = "\x1f".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()
