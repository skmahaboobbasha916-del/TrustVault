from pathlib import Path
import re


def test_clean_install_schema_contains_tables_columns_and_constraints():
    schema_path = Path(__file__).parents[1] / "schema" / "trustvault_schema.sql"
    sql = " ".join(schema_path.read_text(encoding="utf-8").split())
    normalized = sql.upper()

    for table in ("users", "documents", "document_permissions", "audit_events"):
        assert f"CREATE TABLE {table}" in sql

    expected_columns = (
        "name VARCHAR(255)", "email VARCHAR(320)", "password VARCHAR(255)",
        "role VARCHAR(32)", "owner_id BIGINT UNSIGNED",
        "original_filename VARCHAR(255)", "stored_filename VARCHAR(255)",
        "file_path VARCHAR(1024)", "category VARCHAR(100)",
        "mime_type VARCHAR(255)", "file_size BIGINT UNSIGNED",
        "checksum CHAR(64)", "created_at DATETIME",
        "permission ENUM('READ', 'EDIT')", "granted_at DATETIME",
        "revoked_at DATETIME", "occurred_at DATETIME",
        "occurred_at_origin VARCHAR(24) NOT NULL DEFAULT 'UNKNOWN_LEGACY'",
        "event_type VARCHAR(100)", "action VARCHAR(32)",
        "result VARCHAR(16)", "details JSON",
    )
    for column in expected_columns:
        assert column in sql

    for constraint in (
        "UNIQUE KEY uq_users_email",
        "UNIQUE KEY uq_documents_stored_filename",
        "UNIQUE KEY uq_document_permission_subject",
        "KEY idx_audit_occurred_id",
        "FOREIGN KEY (owner_id) REFERENCES users (id)",
        "FOREIGN KEY (document_id) REFERENCES documents (id)",
        "FOREIGN KEY (actor_user_id) REFERENCES users (id)",
        "ON DELETE SET NULL",
        "ON DELETE RESTRICT",
    ):
        assert constraint in sql
    assert "ENGINE=INNODB" in normalized


def test_clean_install_schema_includes_migration_results_without_destructive_sql():
    schema_path = Path(__file__).parents[1] / "schema" / "trustvault_schema.sql"
    sql = schema_path.read_text(encoding="utf-8").upper()

    assert "OCCURRED_AT_ORIGIN VARCHAR(24) NOT NULL DEFAULT 'UNKNOWN_LEGACY'" in sql
    assert "IDX_AUDIT_OCCURRED_ID (OCCURRED_AT, ID)" in sql
    assert re.search(
        r"(?im)^\s*(DROP\s+TABLE|TRUNCATE\s+TABLE|DELETE\s+FROM|UPDATE\s+)\b",
        sql,
    ) is None
