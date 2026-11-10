"""Normalization and secret-redaction tests."""

from __future__ import annotations

from sentinel.models import Finding
from sentinel.verification.normalize import MAX_TEXT, REDACTED, normalize_finding, redact


def test_redacts_authorization_header_keeps_scheme():
    out = redact("Authorization: Bearer abc.def.ghi")
    assert "abc.def.ghi" not in out
    assert out.startswith("Authorization: Bearer ")


def test_redacts_cookie_values_keeps_names():
    out = redact("Set-Cookie: sessionid=s3cr3t; Path=/; HttpOnly")
    assert "s3cr3t" not in out
    assert "sessionid=" in out


def test_redacts_private_key_block():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"
    out = redact(f"found {pem} in file")
    assert "MIIEow" not in out
    assert REDACTED in out


def test_redacts_aws_key_and_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpM"
    out = redact(f"key AKIAABCDEFGHIJKLMNOP token {jwt}")
    assert "AKIAABCDEFGHIJKLMNOP" not in out
    assert jwt not in out


def test_redacts_key_value_secrets():
    out = redact("password=hunter2&api_key: 'xyz123' user=bob")
    assert "hunter2" not in out and "xyz123" not in out
    assert "user=bob" in out  # non-secret fields are kept


def test_plain_text_unchanged():
    text = "Response did not include a strict-transport-security header."
    assert redact(text) == text


def test_normalize_bounds_and_redacts():
    f = Finding(
        asset=" Lab.Example ", source_tool="httpx", title="t",
        severity="low", evidence_summary="token=abc " + "x" * 5000,
        remediation="fix", check_key="Header-Name",
    )
    n = normalize_finding(f)
    assert n.asset == "lab.example"
    assert "abc" not in n.evidence_summary
    assert len(n.evidence_summary) <= MAX_TEXT
    assert n.check_key == "Header-Name"
