-- Apply manually before deploying application code that writes the origin.
-- Adding the column with this default marks all existing rows UNKNOWN_LEGACY
-- without changing any occurred_at values. Inserts that omit the origin are
-- conservatively marked UNKNOWN_LEGACY as well.
ALTER TABLE audit_events
    ADD COLUMN occurred_at_origin VARCHAR(24) NOT NULL
        DEFAULT 'UNKNOWN_LEGACY';
