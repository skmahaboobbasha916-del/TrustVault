
import json
from unittest.mock import MagicMock

import pytest

from models import document_model


@pytest.fixture
def db_mocks(monkeypatch):
    cursor = MagicMock()
    cursor.__enter__ = MagicMock(return_value=cursor)
    cursor.__exit__ = MagicMock(return_value=False)

    connection = MagicMock()
    connection.cursor.return_value = cursor

    monkeypatch.setattr(
        document_model,
        "get_db_connection",
        MagicMock(return_value=connection),
    )

    return connection, cursor


def test_delete_document_record_orders_deletes_audit_and_commits(db_mocks):
    connection, cursor = db_mocks
    cursor.rowcount = 1

    document_model.delete_document_record(10, 42)

    statements = [call.args[0] for call in cursor.execute.call_args_list]

    assert "DELETE FROM document_permissions" in statements[0]
    assert cursor.execute.call_args_list[0].args[1] == (10,)

    assert "DELETE FROM documents" in statements[1]
    assert cursor.execute.call_args_list[1].args[1] == (10,)

    assert "INSERT INTO audit_events" in statements[2]

    audit_params = cursor.execute.call_args_list[2].args[1]

    assert audit_params == (
        42,
        "DOCUMENT_DELETED",
        "DELETE",
        "SUCCESS",
        json.dumps({"document_id": 10}, separators=(",", ":")),
        "UTC",
    )

    assert json.loads(audit_params[4]) == {"document_id": 10}

    connection.commit.assert_called_once_with()
    connection.rollback.assert_not_called()
    connection.close.assert_called_once_with()


def test_document_upload_audit_insert_marks_new_record_utc(db_mocks):
    _, cursor = db_mocks
    cursor.lastrowid = 17

    assert document_model.create_document(
        42,
        "report.pdf",
        "storage-id",
        "/internal/report.pdf",
        "finance",
        "application/pdf",
        123,
        "checksum",
    ) == 17

    sql, params = cursor.execute.call_args_list[1].args

    assert "occurred_at_origin" in sql
    assert params[-1] == "UTC"


def test_permission_delete_failure_rolls_back_and_closes(db_mocks):
    connection, cursor = db_mocks

    cursor.execute.side_effect = RuntimeError("permission delete failed")

    with pytest.raises(RuntimeError, match="permission delete failed"):
        document_model.delete_document_record(10, 42)

    cursor.execute.assert_called_once()

    connection.commit.assert_not_called()
    connection.rollback.assert_called_once_with()
    connection.close.assert_called_once_with()


@pytest.mark.parametrize("rowcount", [0, 2])
def test_document_delete_requires_exactly_one_row_and_rolls_back(
    db_mocks, rowcount
):
    connection, cursor = db_mocks

    def execute(sql, params=None):
        if "DELETE FROM documents" in sql:
            cursor.rowcount = rowcount

    cursor.execute.side_effect = execute

    with pytest.raises(RuntimeError, match="exactly one"):
        document_model.delete_document_record(10, 42)

    assert cursor.execute.call_count == 2

    assert (
        "INSERT INTO audit_events"
        not in cursor.execute.call_args_list[-1].args[0]
    )

    connection.commit.assert_not_called()
    connection.rollback.assert_called_once_with()
    connection.close.assert_called_once_with()


def test_audit_insert_failure_rolls_back_and_closes(db_mocks):
    connection, cursor = db_mocks
    cursor.rowcount = 1

    def execute(sql, params=None):
        if "INSERT INTO audit_events" in sql:
            raise RuntimeError("audit insert failed")

    cursor.execute.side_effect = execute

    with pytest.raises(RuntimeError, match="audit insert failed"):
        document_model.delete_document_record(10, 42)

    assert cursor.execute.call_count == 3

    connection.commit.assert_not_called()
    connection.rollback.assert_called_once_with()
    connection.close.assert_called_once_with()


def test_audit_is_not_inserted_when_document_delete_fails(db_mocks):
    connection, cursor = db_mocks

    def execute(sql, params=None):
        if "DELETE FROM documents" in sql:
            cursor.rowcount = 0

    cursor.execute.side_effect = execute

    with pytest.raises(RuntimeError, match="exactly one"):
        document_model.delete_document_record(10, 42)

    assert all(
        "INSERT INTO audit_events" not in item.args[0]
        for item in cursor.execute.call_args_list
    )

    connection.rollback.assert_called_once_with()
    connection.close.assert_called_once_with()


def test_accessible_document_search_uses_visibility_exists_and_safe_columns(
    db_mocks,
):
    _, cursor = db_mocks

    document_model.get_accessible_documents(42)

    sql, params = cursor.execute.call_args.args
    normalized = " ".join(sql.split())

    assert "INNER JOIN users AS requester ON requester.id = %s" in normalized
    assert "LOWER(requester.role) = 'admin'" in normalized
    assert "EXISTS (SELECT 1 FROM document_permissions" in normalized
    assert "p.revoked_at IS NULL" in normalized
    assert "p.permission IN ('READ', 'EDIT')" in normalized
    assert "file_path" not in normalized
    assert "stored_filename" not in normalized
    assert "UNION" not in normalized

    assert params == (42, 21)


def test_accessible_document_search_applies_bounded_pagination(db_mocks):
    _, cursor = db_mocks

    document_model.get_accessible_documents(42, limit=10)

    sql, params = cursor.execute.call_args.args
    normalized = " ".join(sql.split())

    assert "ORDER BY d.created_at DESC, d.id DESC" in normalized
    assert "LIMIT %s" in normalized

    assert params == (42, 11)


@pytest.mark.parametrize(
    ("filters", "expected_params", "expected_sql"),
    [
        (
            {"filename": "Quarterly"},
            (7, "%quarterly%", 21),
            "LOWER(d.original_filename) LIKE %s",
        ),
        (
            {"owner_name": "Ada"},
            (7, "%ada%", 21),
            "LOWER(owner.name) LIKE %s",
        ),
        (
            {"category": "finance"},
            (7, "finance", 21),
            "d.category = %s",
        ),
        (
            {"start_date": "2025-01-01"},
            (7, "2025-01-01", 21),
            "d.created_at >= %s",
        ),
        (
            {"end_date": "2025-02-01"},
            (7, "2025-02-01", 21),
            "d.created_at < %s",
        ),
        (
            {
                "filename": "Q%_\\1",
                "owner_name": "Ada%",
                "category": "finance",
                "start_date": "2025-01-01",
                "end_date": "2025-02-01",
            },
            (
                7,
                "%q\\%\\_\\\\1%",
                "%ada\\%%",
                "finance",
                "2025-01-01",
                "2025-02-01",
                21,
            ),
            "d.created_at < %s",
        ),
    ],
)
def test_accessible_document_search_binds_filters_and_escapes_like(
    db_mocks,
    filters,
    expected_params,
    expected_sql,
):
    _, cursor = db_mocks

    document_model.get_accessible_documents(7, **filters)

    sql, params = cursor.execute.call_args.args

    assert expected_sql in sql
    assert params == expected_params

    if "filename" in filters or "owner_name" in filters:
        assert "ESCAPE" in sql


@pytest.mark.parametrize("limit", [0, -1, 1.5, True, "10", None])
def test_accessible_document_search_rejects_invalid_limit(db_mocks, limit):
    _, cursor = db_mocks

    with pytest.raises(
        ValueError,
        match="Limit must be a positive integer",
    ):
        document_model.get_accessible_documents(42, limit=limit)

    cursor.execute.assert_not_called()


def test_accessible_document_search_has_no_permission_join_duplicates(db_mocks):
    _, cursor = db_mocks

    document_model.get_accessible_documents(7, filename="report")

    sql = cursor.execute.call_args.args[0]

    assert "EXISTS (" in sql
    assert "INNER JOIN document_permissions" not in sql
    assert "SELECT p.permission" in sql


def test_update_document_metadata_uses_fixed_columns_and_bound_values(
    db_mocks,
):
    _, cursor = db_mocks
    cursor.rowcount = 1

    updated = document_model.update_document_metadata(
        cursor,
        10,
        {
            "original_filename": "new-name.txt",
            "category": "reports",
        },
    )

    sql, params = cursor.execute.call_args.args

    assert sql == (
        "UPDATE documents SET category = %s, "
        "original_filename = %s WHERE id = %s"
    )

    assert params == ("reports", "new-name.txt", 10)
    assert updated == 1


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"owner_id": 42},
        {"file_path": "C:/private/file"},
        {"category": "reports", "checksum": "forged"},
    ],
)
def test_update_document_metadata_rejects_empty_or_immutable_fields(
    db_mocks, fields
):
    _, cursor = db_mocks

    with pytest.raises(ValueError):
        document_model.update_document_metadata(cursor, 10, fields)

    cursor.execute.assert_not_called()
