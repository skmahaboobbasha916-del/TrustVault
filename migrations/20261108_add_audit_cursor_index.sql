CREATE INDEX idx_audit_occurred_id
    ON audit_events (occurred_at, id);
