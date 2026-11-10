"""Notifications (phase 4): a persistent outbox written in the same transaction
as the finding or failure it records, with idempotency keys and retry. Secrets
and private file contents are never sent in an alert."""
