"""Finding normalization and secret redaction.

Every finding passes through :func:`normalize_finding` before it is persisted,
notified or shown to any model. Tool output can carry credentials, session
cookies, tokens and private keys, so evidence and remediation text are redacted
here, once, on the way in. Text is also trimmed and length-bounded so a huge
tool response cannot bloat the database or an alert. Standard library only.
"""

from __future__ import annotations

import re
from dataclasses import replace

from ..models import Finding

MAX_TEXT = 1000
REDACTED = "[REDACTED]"

# (pattern, replacement). Order matters: whole private-key blocks go first so
# their body is not partially matched by the generic token patterns.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        f"-----BEGIN PRIVATE KEY-----{REDACTED}-----END PRIVATE KEY-----",
    ),
    # Authorization headers: keep the scheme, drop the credential.
    (re.compile(r"(?i)(authorization\s*:\s*\w+\s+)\S+"), rf"\1{REDACTED}"),
    # Cookie and Set-Cookie headers: keep the cookie names, drop the values.
    (re.compile(r"(?i)((?:set-)?cookie\s*:\s*)(.+)"), None),  # handled in _redact_cookies
    # AWS access key ids.
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    # JSON Web Tokens.
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), REDACTED),
    # key=value / key: value secrets.
    (
        re.compile(
            r"(?i)\b((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
            r"session(?:id)?|auth)\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s&;,]+)"
        ),
        rf"\1{REDACTED}",
    ),
]

_COOKIE_PAIR = re.compile(r"([^=;\s]+)=([^;]*)")


def _redact_cookies(match: re.Match[str]) -> str:
    prefix, body = match.group(1), match.group(2)
    return prefix + _COOKIE_PAIR.sub(lambda m: f"{m.group(1)}={REDACTED}", body)


def redact(text: str) -> str:
    """Remove credentials, cookies, tokens and private keys from ``text``."""
    for pattern, replacement in _PATTERNS:
        if replacement is None:
            text = pattern.sub(_redact_cookies, text)
        else:
            text = pattern.sub(replacement, text)
    return text


def _bound(text: str) -> str:
    text = " ".join(text.split())  # collapse whitespace and newlines
    if len(text) > MAX_TEXT:
        text = text[: MAX_TEXT - 1] + "…"
    return text


def normalize_finding(finding: Finding) -> Finding:
    """Return a copy of ``finding`` that is safe to persist and notify.

    Redaction runs before bounding so a secret straddling the cut is still
    removed. Title, asset and tool are trimmed; the structured ``check_key`` is
    left as the adapter set it.
    """
    return replace(
        finding,
        asset=finding.asset.strip().lower(),
        source_tool=finding.source_tool.strip(),
        title=_bound(redact(finding.title)),
        evidence_summary=_bound(redact(finding.evidence_summary)),
        remediation=_bound(redact(finding.remediation)),
    )
