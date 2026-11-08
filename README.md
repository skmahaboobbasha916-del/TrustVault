# TrustVault
Secure document sharing with role-based access control and a tamper-evident audit trail.

## Runtime secrets

Set `FLASK_SECRET_KEY` explicitly in the deployment environment or secret
manager. Production startup rejects missing keys, keys shorter than 32 bytes,
and obviously weak or repetitive keys. Do not put production secrets in source
control. For local development, set `TRUSTVAULT_ENV=development` and provide an
explicit local `FLASK_SECRET_KEY`; the application does not supply a fallback.
Automated tests use a separate test-only key from `tests/conftest.py`.

## Audit timestamp provenance

TrustVault database connections set their MySQL session timezone to UTC. New
audit events are marked `occurred_at_origin = 'UTC'`; their timezone-naive
`DATETIME` values represent UTC and the admin API serializes them with a `Z`
suffix. Existing audit timestamps could not be reliably classified as IST or
UTC. They are marked `UNKNOWN_LEGACY`, retain their original `occurred_at`
values, and are returned without a timezone suffix. Do not infer a timezone or
convert these historical values without independent evidence.

Audit date filters compare the stored `occurred_at` values against the supplied
calendar-date boundaries. They do not represent a universally UTC date range
when results include `UNKNOWN_LEGACY` records. Cursor pagination is
deterministic by stored `occurred_at DESC, id DESC`; ordering across timestamp
origins does not establish verified real-world chronology.

Apply `migrations/20261108_add_audit_timestamp_origin.sql` manually before
deploying the application change. The statement adds a non-null origin column
with `UNKNOWN_LEGACY` as the default, so existing rows are marked while their
timestamps remain untouched. Omitted-origin inserts remain conservative; the
application's audit insert paths explicitly mark new events `UTC`. Verify the
column, default, and row counts after applying the migration. It is not run by
application startup.

## Database setup

For a **new database**, create an empty database and apply
`schema/trustvault_schema.sql`. This clean-install schema includes the tables,
constraints, indexes, audit provenance column, and cursor index; do not then
apply the incremental migrations to the same database. The schema uses MySQL's
`JSON` column type and requires MySQL 5.7.8 or newer (or a compatible MariaDB
release).

For an **existing database**, back it up, pause all audit writers, and apply
`migrations/20261108_add_audit_timestamp_origin.sql`. Apply
`migrations/20261108_add_audit_cursor_index.sql` only if the cursor index is not
already present. Verify the resulting schema before deploying this application
version, then resume writes after confirming all application connections use
UTC. The origin default deliberately remains `UNKNOWN_LEGACY` for writers that
omit the column.
