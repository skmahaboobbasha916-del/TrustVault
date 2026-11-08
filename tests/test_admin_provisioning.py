from unittest.mock import MagicMock

import pytest

from scripts import provision_admin
from services import admin_provisioning_service as provisioning


@pytest.fixture
def database(monkeypatch):
    connection = MagicMock()
    cursor = MagicMock()
    cursor.__enter__ = MagicMock(return_value=cursor)
    cursor.__exit__ = MagicMock(return_value=False)
    connection.cursor.return_value = cursor
    monkeypatch.setattr(provisioning, "get_db_connection", lambda: connection)
    return connection, cursor


def test_provision_first_admin_updates_existing_user_and_audits_atomically(database):
    connection, cursor = database
    cursor.fetchone.side_effect = [
        {"lock_acquired": 1},
        {"id": 15, "role": "viewer"},
        None,
        None,
    ]
    cursor.rowcount = 1

    user_id = provisioning.provision_first_admin("  ADMIN@EXAMPLE.COM  ")

    assert user_id == 15
    calls = cursor.execute.call_args_list
    assert calls[0].args == (
        "SELECT GET_LOCK(%s, %s) AS lock_acquired",
        (provisioning._PROVISIONING_LOCK_NAME, 5),
    )
    assert "SELECT id, role FROM users WHERE email = %s FOR UPDATE" in calls[1].args[0]
    assert calls[1].args[1] == ("admin@example.com",)
    assert "event_type = %s AND action = %s AND result = %s" in calls[2].args[0]
    assert calls[2].args[1] == (
        "ADMIN_PROVISIONING", "PROMOTE_TO_ADMIN", "SUCCESS"
    )
    assert "LOWER(TRIM(role)) = 'admin'" in calls[3].args[0]
    assert calls[4].args == (
        "UPDATE users SET role = %s WHERE id = %s",
        ("admin", 15),
    )
    audit_sql, audit_values = calls[5].args
    assert "INSERT INTO audit_events" in audit_sql
    assert "occurred_at_origin" in audit_sql
    assert audit_values == (
        15, "ADMIN_PROVISIONING", "PROMOTE_TO_ADMIN", "SUCCESS", "UTC"
    )
    assert "RELEASE_LOCK" in calls[6].args[0]
    connection.begin.assert_called_once_with()
    connection.commit.assert_called_once_with()
    connection.rollback.assert_not_called()
    connection.close.assert_called_once_with()


@pytest.mark.parametrize(
    ("target", "prior_provision", "existing_admin", "message"),
    [
        (None, None, None, "No existing user"),
        ({"id": 15, "role": " ADMIN "}, None, None, "already an administrator"),
        ({"id": 15, "role": "viewer"}, {"id": 8}, None, "already been used"),
        ({"id": 15, "role": "viewer"}, None, {"id": 20}, "already been used"),
    ],
)
def test_provision_first_admin_denials_roll_back_without_changes(
    database, target, prior_provision, existing_admin, message
):
    connection, cursor = database
    cursor.fetchone.side_effect = [
        {"lock_acquired": 1}, target, prior_provision, existing_admin
    ]

    with pytest.raises(provisioning.AdminProvisioningError, match=message):
        provisioning.provision_first_admin("user@example.com")

    sql_statements = [call.args[0] for call in cursor.execute.call_args_list]
    assert not any(statement.startswith("UPDATE users") for statement in sql_statements)
    assert not any("INSERT INTO audit_events" in statement for statement in sql_statements)
    connection.commit.assert_not_called()
    connection.rollback.assert_called_once_with()
    connection.close.assert_called_once_with()


def test_provision_first_admin_rejects_when_lock_is_unavailable(database):
    connection, cursor = database
    cursor.fetchone.return_value = {"lock_acquired": 0}

    with pytest.raises(provisioning.AdminProvisioningError, match="already running"):
        provisioning.provision_first_admin("user@example.com")

    connection.begin.assert_not_called()
    connection.commit.assert_not_called()
    connection.close.assert_called_once_with()


def test_provision_first_admin_rolls_back_unexpected_audit_failure(database):
    connection, cursor = database
    cursor.fetchone.side_effect = [
        {"lock_acquired": 1},
        {"id": 15, "role": "viewer"},
        None,
        None,
    ]
    cursor.rowcount = 1

    def fail_audit(statement, params=None):
        if "INSERT INTO audit_events" in statement:
            raise RuntimeError("audit insert failed")

    cursor.execute.side_effect = fail_audit

    with pytest.raises(RuntimeError, match="audit insert failed"):
        provisioning.provision_first_admin("user@example.com")

    connection.commit.assert_not_called()
    connection.rollback.assert_called_once_with()
    connection.close.assert_called_once_with()


def test_cli_requires_exact_confirmation_before_calling_service(monkeypatch, capsys):
    provision = MagicMock(return_value=15)
    monkeypatch.setattr(provision_admin, "provision_first_admin", provision)
    monkeypatch.setattr("builtins.input", lambda _: "no")

    result = provision_admin.main(["--email", "user@example.com"])

    assert result == 1
    assert "cancelled" in capsys.readouterr().err
    provision.assert_not_called()


def test_cli_runs_service_only_after_explicit_confirmation(monkeypatch, capsys):
    provision = MagicMock(return_value=15)
    monkeypatch.setattr(provision_admin, "provision_first_admin", provision)
    monkeypatch.setattr(
        "builtins.input",
        lambda _: "PROMOTE user@example.com TO ADMIN",
    )

    result = provision_admin.main(["--email", "USER@EXAMPLE.COM"])

    assert result == 0
    assert "user ID 15" in capsys.readouterr().out
    provision.assert_called_once_with("user@example.com")
