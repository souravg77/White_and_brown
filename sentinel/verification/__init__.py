"""Follow-up verification: normalize and redact findings, fingerprint them for
deduplication, and recheck supported findings with safe, repeatable evidence.

A finding is ``verified`` only when every recheck reproduces it, a
``false_positive`` when every recheck contradicts it, and ``unverified``
otherwise (mixed answers, errors, timeouts, or no verifier). Model confidence
never verifies a finding."""
