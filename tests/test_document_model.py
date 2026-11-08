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
    monkeypatch.setattr(document_model, "get_db_connection", MagicMock(return_value=connection))
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
    assert audit_params[:5] == (42, "DOCUMENT_DELETED", "DELETE", "SUCCESS", json.dumps({"document_id": 10}, separators=(",", ":")))
    assert json.loads(audit_params[4]) == {"document_id": 10}
    connection.commit.assert_called_once_with()
    connection.rollback.assert_not_called()
    connection.close.assert_called_once_with()


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
def test_document_delete_requires_exactly_one_row_and_rolls_back(db_mocks, rowcount):
    connection, cursor = db_mocks

    def execute(sql, params=None):
        if "DELETE FROM documents" in sql:
            cursor.rowcount = rowcount

    cursor.execute.side_effect = execute

    with pytest.raises(RuntimeError, match="exactly one"):
        document_model.delete_document_record(10, 42)

    assert cursor.execute.call_count == 2
    assert "INSERT INTO audit_events" not in cursor.execute.call_args_list[-1].args[0]
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

    assert all("INSERT INTO audit_events" not in item.args[0] for item in cursor.execute.call_args_list)
    connection.rollback.assert_called_once_with()
    connection.close.assert_called_once_with()
