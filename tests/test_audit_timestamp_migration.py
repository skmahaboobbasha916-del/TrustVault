from pathlib import Path


def test_timestamp_origin_migration_marks_existing_rows_without_rewriting_time():
    migration = Path(__file__).parents[1] / "migrations" / "20261108_add_audit_timestamp_origin.sql"
    sql = " ".join(migration.read_text(encoding="utf-8").split())

    assert "ADD COLUMN occurred_at_origin VARCHAR(24) NOT NULL DEFAULT 'UNKNOWN_LEGACY'" in sql
    assert sql.upper().count("ALTER TABLE AUDIT_EVENTS") == 1
    assert "DEFAULT 'UTC'" not in sql
    assert "UPDATE AUDIT_EVENTS" not in sql.upper()
    assert "occurred_at =" not in sql
