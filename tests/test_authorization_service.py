import json
from unittest.mock import MagicMock

import pytest

from services import authorization_service as authorization


@pytest.fixture
def database(monkeypatch):
    connection = MagicMock()
    cursor = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor
    monkeypatch.setattr(authorization, "get_db_connection", lambda: connection)
    return connection, cursor


def user(user_id, role="user"):
    return {"id": user_id, "name": "Test User", "email": "user@example.com", "role": role}


def document(owner_id=1):
    return {"id": 10, "owner_id": owner_id, "name": "test-document"}


def audit_records(cursor):
    return [
        call.args[1]
        for call in cursor.execute.call_args_list
        if "INSERT INTO audit_events" in call.args[0]
    ]


def assert_access_audit(cursor, action, result, reason=None):
    records = audit_records(cursor)
    assert len(records) == 1
    actor_id, document_id, target_id, event_type, audited_action, audited_result, details = records[0]
    assert actor_id == 2
    assert document_id == 10
    assert target_id is None
    assert event_type == "ACCESS_ATTEMPT"
    assert audited_action == action.upper()
    assert audited_result == result
    assert (json.loads(details) if details else None) == ({"reason": reason} if reason else None)


@pytest.mark.parametrize("action", ["view", "download", "modify", "delete", "grant", "revoke"])
def test_owner_can_perform_all_supported_actions(database, action):
    connection, cursor = database
    owner = user(2)
    owned_document = document(owner_id=2)
    cursor.fetchone.side_effect = [owner, owned_document]

    assert authorization.authorize_document(owner["id"], owned_document["id"], action) == owned_document

    assert_access_audit(cursor, action, "SUCCESS")
    connection.commit.assert_called_once()
    connection.close.assert_called_once()


@pytest.mark.parametrize(
    ("action", "allowed"),
    [("view", True), ("download", True), ("modify", False), ("delete", False)],
)
def test_read_permission_limits_actions(database, action, allowed):
    connection, cursor = database
    actor = user(2)
    shared_document = document()
    cursor.fetchone.side_effect = [actor, shared_document, {"permission": "READ"}]

    if allowed:
        assert authorization.authorize_document(actor["id"], shared_document["id"], action) == shared_document
        assert_access_audit(cursor, action, "SUCCESS")
    else:
        with pytest.raises(authorization.AuthorizationError):
            authorization.authorize_document(actor["id"], shared_document["id"], action)
        assert_access_audit(cursor, action, "DENIED", "insufficient_permission")

    connection.commit.assert_called_once()


@pytest.mark.parametrize(
    ("action", "allowed"),
    [("view", True), ("download", True), ("modify", True), ("delete", False)],
)
def test_edit_permission_limits_actions(database, action, allowed):
    connection, cursor = database
    actor = user(2)
    shared_document = document()
    cursor.fetchone.side_effect = [actor, shared_document, {"permission": "EDIT"}]

    if allowed:
        assert authorization.authorize_document(actor["id"], shared_document["id"], action) == shared_document
        assert_access_audit(cursor, action, "SUCCESS")
    else:
        with pytest.raises(authorization.AuthorizationError):
            authorization.authorize_document(actor["id"], shared_document["id"], action)
        assert_access_audit(cursor, action, "DENIED", "insufficient_permission")

    connection.commit.assert_called_once()


@pytest.mark.parametrize(
    ("action", "allowed"),
    [("view", True), ("download", False), ("modify", False), ("delete", False)],
)
def test_admin_permissions_are_limited_to_view(database, action, allowed):
    connection, cursor = database
    admin = user(2, role="admin")
    shared_document = document()
    cursor.fetchone.side_effect = [admin, shared_document]

    if allowed:
        assert authorization.authorize_document(admin["id"], shared_document["id"], action) == shared_document
        assert_access_audit(cursor, action, "SUCCESS")
    else:
        with pytest.raises(authorization.AuthorizationError):
            authorization.authorize_document(admin["id"], shared_document["id"], action)
        assert_access_audit(cursor, action, "DENIED", "insufficient_permission")

    connection.commit.assert_called_once()


def test_revoked_permission_does_not_allow_access(database):
    connection, cursor = database
    actor = user(2)
    shared_document = document()
    cursor.fetchone.side_effect = [actor, shared_document, None]

    with pytest.raises(authorization.AuthorizationError):
        authorization.authorize_document(actor["id"], shared_document["id"], "view")

    assert_access_audit(cursor, "view", "DENIED", "insufficient_permission")
    permission_query = next(
        call.args[0]
        for call in cursor.execute.call_args_list
        if "FROM document_permissions" in call.args[0]
    )
    assert "revoked_at IS NULL" in permission_query
    connection.commit.assert_called_once()


def test_audit_insert_failure_rolls_back_allowed_owner_access(database):
    connection, cursor = database
    owner = user(2)
    owned_document = document(owner_id=2)
    audit_error = RuntimeError("audit insert failed")
    cursor.fetchone.side_effect = [owner, owned_document]

    def raise_for_audit_insert(statement, *args):
        if "INSERT INTO audit_events" in statement:
            raise audit_error

    cursor.execute.side_effect = raise_for_audit_insert

    with pytest.raises(RuntimeError, match="audit insert failed") as exc_info:
        authorization.authorize_document(owner["id"], owned_document["id"], "view")

    assert exc_info.value is audit_error
    connection.rollback.assert_called_once()
    connection.commit.assert_not_called()


def test_owner_cannot_grant_permission_to_self(database):
    connection, cursor = database
    owner = user(2)
    owned_document = document(owner_id=2)
    cursor.fetchone.side_effect = [owner, owned_document, {"id": owner["id"]}]

    with pytest.raises(authorization.AuthorizationError, match="cannot grant permissions to themselves"):
        authorization.grant_document_permission(
            owner["id"], owned_document["id"], owner["id"], "READ"
        )

    records = audit_records(cursor)
    assert len(records) == 1
    actor_id, document_id, target_id, event_type, action, result, details = records[0]
    assert (actor_id, document_id, target_id) == (owner["id"], owned_document["id"], owner["id"])
    assert event_type == "PERMISSION_GRANT_ATTEMPT"
    assert action == "GRANT"
    assert result == "DENIED"
    assert json.loads(details) == {"reason": "owner_cannot_grant_permission_to_self"}
    connection.commit.assert_called_once()


@pytest.mark.parametrize("actor_type", ["owner", "EDIT"])
def test_metadata_modification_is_atomic_for_owner_and_edit_user(
    database, monkeypatch, actor_type
):
    connection, cursor = database
    actor = user(2)
    owned_document = document(owner_id=2 if actor_type == "owner" else 1)
    cursor.fetchone.side_effect = [actor, owned_document]
    cursor.fetchall.return_value = (
        [] if actor_type == "owner" else [{"id": 9, "permission": "EDIT"}]
    )
    update = MagicMock(return_value=1)
    monkeypatch.setattr(authorization, "update_document_metadata", update)

    result = authorization.modify_document_metadata(
        2, 10, {"category": " reports ", "original_filename": "report one.txt"}
    )

    assert result == 10
    assert update.call_args.args[0] is cursor
    assert update.call_args.args[1:] == (
        10,
        {"category": "reports", "original_filename": "report_one.txt"},
    )
    statements = [call.args[0] for call in cursor.execute.call_args_list]
    assert "FROM users WHERE id = %s" in statements[0]
    assert "FOR UPDATE" not in statements[0]
    permission_statement = next(
        statement for statement in statements if "FROM document_permissions" in statement
    )
    document_statement = next(
        statement for statement in statements if "FROM documents WHERE id = %s" in statement
    )
    assert "revoked_at IS NULL" in permission_statement
    assert "FOR UPDATE" in permission_statement
    assert "FOR UPDATE" in document_statement
    assert statements.index(permission_statement) < statements.index(document_statement)
    assert_access_audit(cursor, "modify", "SUCCESS")
    connection.commit.assert_called_once()
    connection.rollback.assert_not_called()
    connection.close.assert_called_once()


@pytest.mark.parametrize(
    ("role", "owner_id", "permission_rows"),
    [
        ("user", 1, [{"id": 9, "permission": "READ"}]),
        ("user", 1, []),  # Includes revoked-only grants: query returns no active rows.
        ("admin", 1, []),
        ("admin", 2, []),
    ],
)
def test_metadata_modification_denies_read_unauthorized_and_admin(
    database, monkeypatch, role, owner_id, permission_rows
):
    connection, cursor = database
    actor = user(2, role=role)
    cursor.fetchone.side_effect = [actor, document(owner_id=owner_id)]
    cursor.fetchall.return_value = permission_rows
    update = MagicMock()
    monkeypatch.setattr(authorization, "update_document_metadata", update)

    with pytest.raises(authorization.AuthorizationError):
        authorization.modify_document_metadata(2, 10, {"category": "reports"})

    assert_access_audit(cursor, "modify", "DENIED", "insufficient_permission")
    update.assert_not_called()
    connection.commit.assert_called_once()
    connection.rollback.assert_not_called()
    connection.close.assert_called_once()
    statements = [call.args[0] for call in cursor.execute.call_args_list]
    permission_statement = next(
        statement for statement in statements if "FROM document_permissions" in statement
    )
    document_statement = next(
        statement for statement in statements if "FROM documents WHERE id = %s" in statement
    )
    assert statements.index(permission_statement) < statements.index(document_statement)


def test_metadata_modification_rolls_back_when_update_fails(database, monkeypatch):
    connection, cursor = database
    cursor.fetchone.side_effect = [user(2), document(owner_id=2)]
    update_error = RuntimeError("metadata update failed")
    update = MagicMock(side_effect=update_error)
    monkeypatch.setattr(authorization, "update_document_metadata", update)

    with pytest.raises(RuntimeError, match="metadata update failed"):
        authorization.modify_document_metadata(2, 10, {"category": "reports"})

    assert audit_records(cursor) == []
    connection.rollback.assert_called_once()
    connection.commit.assert_not_called()
    connection.close.assert_called_once()


def test_metadata_modification_rolls_back_update_when_audit_insert_fails(
    database, monkeypatch
):
    connection, cursor = database
    cursor.fetchone.side_effect = [user(2), document(owner_id=2)]
    update = MagicMock(return_value=1)
    monkeypatch.setattr(authorization, "update_document_metadata", update)

    def fail_audit(statement, *args):
        if "INSERT INTO audit_events" in statement:
            raise RuntimeError("audit insert failed")

    cursor.execute.side_effect = fail_audit

    with pytest.raises(RuntimeError, match="audit insert failed"):
        authorization.modify_document_metadata(2, 10, {"category": "reports"})

    update.assert_called_once()
    connection.rollback.assert_called_once()
    connection.commit.assert_not_called()
    connection.close.assert_called_once()


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"file_path": "C:/private/file"},
        {"owner_id": 99},
        {"original_filename": "../"},
        {"category": 99},
    ],
)
def test_metadata_modification_rejects_invalid_fields_before_opening_connection(
    database, fields
):
    connection, _ = database

    with pytest.raises(ValueError):
        authorization.modify_document_metadata(2, 10, fields)

    connection.cursor.assert_not_called()
    connection.close.assert_not_called()
