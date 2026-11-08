from unittest.mock import MagicMock
from datetime import datetime

import pytest

from models import audit_model


@pytest.fixture
def db_mocks(monkeypatch):
    cursor = MagicMock()
    cursor.__enter__ = MagicMock(return_value=cursor)
    cursor.__exit__ = MagicMock(return_value=False)
    connection = MagicMock()
    connection.cursor.return_value = cursor
    monkeypatch.setattr(audit_model, "get_db_connection", lambda: connection)
    return connection, cursor


def test_list_audit_events_selects_only_explicit_metadata_and_is_stable(db_mocks):
    connection, cursor = db_mocks

    audit_model.list_audit_events()

    sql, params = cursor.execute.call_args.args
    normalized = " ".join(sql.split())
    assert normalized.startswith(
        "SELECT id, occurred_at, occurred_at_origin, actor_user_id, document_id, "
        "target_user_id, event_type, action, result, details FROM audit_events"
    )
    assert "ORDER BY occurred_at DESC, id DESC" in normalized
    assert "LIMIT %s" in normalized
    assert "OFFSET" not in normalized
    for forbidden in (
        "file_path", "stored_filename", "contents", "password", "secret"
    ):
        assert forbidden not in normalized.lower()
    assert params == (21,)
    assert "UPDATE " not in normalized
    assert "DELETE " not in normalized
    connection.close.assert_called_once()


def test_list_audit_events_parameterizes_all_filters_and_pagination(db_mocks):
    connection, cursor = db_mocks

    audit_model.list_audit_events(
        event_type="ACCESS_ATTEMPT' OR 1=1 --",
        action="VIEW",
        result="DENIED",
        actor_user_id=42,
        start_date="2025-01-01",
        end_date="2025-02-01",
        limit=100,
    )

    sql, params = cursor.execute.call_args.args
    normalized = " ".join(sql.split())
    assert "event_type = %s" in normalized
    assert "action = %s" in normalized
    assert "result = %s" in normalized
    assert "actor_user_id = %s" in normalized
    assert "occurred_at >= %s" in normalized
    assert "occurred_at < %s" in normalized
    assert params == (
        "ACCESS_ATTEMPT' OR 1=1 --",
        "VIEW",
        "DENIED",
        42,
        "2025-01-01",
        "2025-02-01",
        101,
    )
    connection.close.assert_called_once()


def test_list_audit_events_closes_connection_on_database_error(db_mocks):
    connection, cursor = db_mocks
    cursor.execute.side_effect = RuntimeError("database details")

    with pytest.raises(RuntimeError, match="database details"):
        audit_model.list_audit_events()

    connection.close.assert_called_once()


def test_list_audit_events_enforces_page_bounds_in_model(db_mocks):
    _, cursor = db_mocks

    audit_model.list_audit_events(limit=500)

    assert cursor.execute.call_args.args[1] == (101,)

    with pytest.raises(ValueError):
        audit_model.list_audit_events(limit=0)


def test_list_audit_events_uses_strict_timestamp_and_id_cursor_boundary(db_mocks):
    _, cursor = db_mocks
    cursor_timestamp = datetime(2025, 1, 2, 3, 4, 5, 123456)

    audit_model.list_audit_events(
        event_type="ACCESS_ATTEMPT",
        cursor_timestamp=cursor_timestamp,
        cursor_id=19,
        limit=2,
    )

    sql, params = cursor.execute.call_args.args
    normalized = " ".join(sql.split())
    assert "(occurred_at < %s OR (occurred_at = %s AND id < %s))" in normalized
    assert "ORDER BY occurred_at DESC, id DESC LIMIT %s" in normalized
    assert "OFFSET" not in normalized
    assert params == (
        "ACCESS_ATTEMPT",
        cursor_timestamp,
        cursor_timestamp,
        19,
        3,
    )


def test_date_filters_compare_stored_values_without_assuming_origin(db_mocks):
    _, cursor = db_mocks

    audit_model.list_audit_events(
        start_date="2025-01-02", end_date="2025-01-03", limit=2
    )

    sql, params = cursor.execute.call_args.args
    normalized = " ".join(sql.split())
    assert "occurred_at >= %s" in normalized
    assert "occurred_at < %s" in normalized
    assert "WHERE occurred_at_origin" not in normalized
    assert params == ("2025-01-02", "2025-01-03", 3)
