from datetime import date, datetime
import time
from unittest.mock import MagicMock

import pytest

from app import app as trustvault_app
from routes import admin_routes


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setitem(trustvault_app.config, "TESTING", True)
    monkeypatch.setitem(trustvault_app.config, "SECRET_KEY", "test-secret")
    return trustvault_app.test_client()


def authenticate(client, user_id=42, role="viewer"):
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["role"] = role


def audit_row(**overrides):
    row = {
        "id": 7,
        "occurred_at": datetime(2025, 1, 2, 3, 4, 5),
        "occurred_at_origin": "UNKNOWN_LEGACY",
        "actor_user_id": 42,
        "document_id": 9,
        "target_user_id": 11,
        "event_type": "ACCESS_ATTEMPT",
        "action": "VIEW",
        "result": "SUCCESS",
        "details": '{"reason":"insufficient_permission"}',
    }
    row.update(overrides)
    return row


def configure_admin(monkeypatch, list_events):
    monkeypatch.setattr(
        admin_routes,
        "get_current_user",
        lambda user_id: {"id": user_id, "role": "admin"},
    )
    monkeypatch.setattr(admin_routes, "list_audit_events", list_events)


def issue_cursor(client, monkeypatch, event_type=None):
    authenticate(client)
    list_events = MagicMock(return_value=[
        audit_row(id=3),
        audit_row(id=2),
    ])
    configure_admin(monkeypatch, list_events)
    query = "?limit=1"
    if event_type is not None:
        query += f"&event_type={event_type}"
    response = client.get(f"/api/admin/audit-events{query}")
    assert response.status_code == 200
    assert response.get_json()["next_cursor"]
    return response.get_json()["next_cursor"], list_events


def test_audit_api_requires_authentication(client, monkeypatch):
    get_user = MagicMock()
    list_events = MagicMock()
    monkeypatch.setattr(admin_routes, "get_current_user", get_user)
    monkeypatch.setattr(admin_routes, "list_audit_events", list_events)

    response = client.get("/api/admin/audit-events")

    assert response.status_code == 401
    get_user.assert_not_called()
    list_events.assert_not_called()


def test_audit_api_uses_database_role_not_session_role(client, monkeypatch):
    authenticate(client, user_id=42, role="admin")
    get_user = MagicMock(return_value={"id": 42, "role": "viewer"})
    list_events = MagicMock()
    monkeypatch.setattr(admin_routes, "get_current_user", get_user)
    monkeypatch.setattr(admin_routes, "list_audit_events", list_events)

    response = client.get("/api/admin/audit-events")

    assert response.status_code == 403
    get_user.assert_called_once_with(42)
    list_events.assert_not_called()


def test_audit_api_denies_non_admin_even_if_session_role_is_admin(client, monkeypatch):
    authenticate(client, role="admin")
    monkeypatch.setattr(
        admin_routes, "get_current_user", lambda user_id: {"id": user_id, "role": "user"}
    )
    list_events = MagicMock()
    monkeypatch.setattr(admin_routes, "list_audit_events", list_events)

    response = client.get("/api/admin/audit-events")

    assert response.status_code == 403
    assert response.get_json() == {
        "message": "Administrator access is required."
    }
    list_events.assert_not_called()


def test_audit_api_returns_records_for_database_admin(client, monkeypatch):
    authenticate(client, user_id=42, role="viewer")
    get_user = MagicMock(return_value={"id": 42, "role": " ADMIN "})
    row = audit_row()
    list_events = MagicMock(return_value=[row])
    monkeypatch.setattr(admin_routes, "get_current_user", get_user)
    monkeypatch.setattr(admin_routes, "list_audit_events", list_events)

    response = client.get("/api/admin/audit-events")

    assert response.status_code == 200
    assert response.get_json() == {
        "items": [{
            **row,
            "occurred_at": "2025-01-02T03:04:05.000000",
            "details": {"reason": "insufficient_permission"},
        }],
        "limit": 20,
        "next_cursor": None,
    }
    get_user.assert_called_once_with(42)
    list_events.assert_called_once_with(
        event_type=None,
        action=None,
        result=None,
        actor_user_id=None,
        start_date=None,
        end_date=None,
        limit=20,
        cursor_timestamp=None,
        cursor_id=None,
    )


def test_audit_api_passes_filters_dates_and_pagination(client, monkeypatch):
    authenticate(client, user_id=42)
    monkeypatch.setattr(
        admin_routes, "get_current_user", lambda user_id: {"id": user_id, "role": "admin"}
    )
    list_events = MagicMock(return_value=[])
    monkeypatch.setattr(admin_routes, "list_audit_events", list_events)

    response = client.get(
        "/api/admin/audit-events?event_type=UPLOAD&action=upload&result=SUCCESS"
        "&actor_user_id=17&start_date=2025-01-01&end_date=2025-01-31"
        "&limit=1000&user_id=999"
    )

    assert response.status_code == 200
    list_events.assert_called_once_with(
        event_type="UPLOAD",
        action="upload",
        result="SUCCESS",
        actor_user_id=17,
        start_date=date(2025, 1, 1),
        end_date=date(2025, 2, 1),
        limit=100,
        cursor_timestamp=None,
        cursor_id=None,
    )
    assert response.get_json()["limit"] == 100
    assert response.get_json()["next_cursor"] is None


def test_audit_api_returns_cursor_after_extra_row_and_accepts_next_page(
    client, monkeypatch
):
    authenticate(client)
    timestamp = datetime(2025, 1, 2, 3, 4, 5, 123456)
    first_page_rows = [
        audit_row(id=30, occurred_at=timestamp),
        audit_row(id=29, occurred_at=timestamp),
        audit_row(id=28, occurred_at=datetime(2025, 1, 2, 3, 4, 4)),
    ]
    list_events = MagicMock(side_effect=[
        first_page_rows,
        [audit_row(id=28, occurred_at=datetime(2025, 1, 2, 3, 4, 4))],
    ])
    configure_admin(monkeypatch, list_events)

    first_response = client.get("/api/admin/audit-events?limit=2")

    assert first_response.status_code == 200
    first_payload = first_response.get_json()
    assert [row["id"] for row in first_payload["items"]] == [30, 29]
    assert first_payload["next_cursor"]

    second_response = client.get(
        "/api/admin/audit-events?limit=2&cursor=" + first_payload["next_cursor"]
    )

    assert second_response.status_code == 200
    second_payload = second_response.get_json()
    assert [row["id"] for row in second_payload["items"]] == [28]
    assert second_payload["next_cursor"] is None
    second_call = list_events.call_args_list[1]
    assert second_call.kwargs["cursor_timestamp"] == timestamp
    assert second_call.kwargs["cursor_id"] == 29


def test_audit_api_serializes_utc_origin_with_explicit_z(client, monkeypatch):
    authenticate(client)
    configure_admin(
        monkeypatch, lambda **_: [audit_row(occurred_at_origin="UTC")]
    )

    response = client.get("/api/admin/audit-events")

    assert response.status_code == 200
    item = response.get_json()["items"][0]
    assert item["occurred_at"] == "2025-01-02T03:04:05.000000Z"
    assert item["occurred_at_origin"] == "UTC"


def test_audit_api_never_labels_unknown_timestamp_as_gmt_or_utc(
    client, monkeypatch
):
    authenticate(client)
    configure_admin(
        monkeypatch,
        lambda **_: [audit_row(occurred_at_origin="UNKNOWN_LEGACY")],
    )

    response = client.get("/api/admin/audit-events")

    assert response.status_code == 200
    item = response.get_json()["items"][0]
    assert item["occurred_at"] == "2025-01-02T03:04:05.000000"
    assert "GMT" not in response.get_data(as_text=True)
    assert "UTC" not in item["occurred_at"]


def test_audit_api_rejects_old_cursor_version(client, monkeypatch):
    authenticate(client)
    configure_admin(monkeypatch, lambda **_: [])
    fingerprint = admin_routes._filter_fingerprint(None, None, None, None, None, None)
    with trustvault_app.app_context():
        old_cursor = admin_routes._cursor_serializer().dumps({
            "version": 1,
            "occurred_at": "2025-01-02T03:04:05.000000",
            "id": 7,
            "filters": fingerprint,
        })

    response = client.get("/api/admin/audit-events?cursor=" + old_cursor)

    assert response.status_code == 400


def test_date_filter_and_cursor_use_stored_values_for_mixed_origins(
    client, monkeypatch
):
    authenticate(client)
    mixed_rows = [
        audit_row(id=30, occurred_at=datetime(2025, 1, 2, 3),
                  occurred_at_origin="UNKNOWN_LEGACY"),
        audit_row(id=29, occurred_at=datetime(2025, 1, 2, 2),
                  occurred_at_origin="UTC"),
        audit_row(id=28, occurred_at=datetime(2025, 1, 2, 1),
                  occurred_at_origin="UNKNOWN_LEGACY"),
    ]
    list_events = MagicMock(side_effect=[mixed_rows, [mixed_rows[2]]])
    configure_admin(monkeypatch, list_events)

    first = client.get(
        "/api/admin/audit-events?start_date=2025-01-02&end_date=2025-01-02&limit=2"
    )
    assert first.status_code == 200
    assert [row["id"] for row in first.get_json()["items"]] == [30, 29]
    assert [row["occurred_at_origin"] for row in first.get_json()["items"]] == [
        "UNKNOWN_LEGACY", "UTC"
    ]
    first_call = list_events.call_args_list[0]
    assert first_call.kwargs["start_date"] == date(2025, 1, 2)
    assert first_call.kwargs["end_date"] == date(2025, 1, 3)

    next_page = client.get(
        "/api/admin/audit-events?start_date=2025-01-02&end_date=2025-01-02"
        "&limit=2&cursor=" + first.get_json()["next_cursor"]
    )
    assert next_page.status_code == 200
    assert [row["id"] for row in next_page.get_json()["items"]] == [28]
    assert list_events.call_args_list[1].kwargs["cursor_timestamp"] == mixed_rows[1]["occurred_at"]
    assert list_events.call_args_list[1].kwargs["cursor_id"] == 29


@pytest.mark.parametrize("cursor", ["garbage", ""])
def test_audit_api_rejects_invalid_cursor(client, monkeypatch, cursor):
    authenticate(client)
    list_events = MagicMock(return_value=[])
    configure_admin(monkeypatch, list_events)

    response = client.get("/api/admin/audit-events?cursor=" + cursor)

    assert response.status_code == 400
    assert response.get_json() == {"message": "Invalid audit query filters."}
    list_events.assert_not_called()


def test_audit_api_rejects_tampered_cursor(client, monkeypatch):
    token, list_events = issue_cursor(client, monkeypatch)
    replacement = "A" if token[10] != "A" else "B"
    tampered = token[:10] + replacement + token[11:]

    response = client.get("/api/admin/audit-events?cursor=" + tampered)

    assert response.status_code == 400
    assert response.get_json() == {"message": "Invalid audit query filters."}
    assert list_events.call_count == 1


def test_audit_api_rejects_expired_cursor(client, monkeypatch):
    token, list_events = issue_cursor(client, monkeypatch)
    original_time = time.time
    monkeypatch.setattr(
        "itsdangerous.timed.time.time",
        lambda: original_time() + admin_routes._CURSOR_MAX_AGE_SECONDS + 1,
    )

    response = client.get("/api/admin/audit-events?limit=1&cursor=" + token)

    assert response.status_code == 400
    assert response.get_json() == {"message": "Invalid audit query filters."}
    assert list_events.call_count == 1


def test_audit_api_cursor_is_invalidated_when_signing_key_changes(
    client, monkeypatch
):
    token, list_events = issue_cursor(client, monkeypatch)
    monkeypatch.setitem(
        trustvault_app.config, "SECRET_KEY", "rotated-explicit-test-signing-key"
    )
    authenticate(client)

    response = client.get("/api/admin/audit-events?limit=1&cursor=" + token)

    assert response.status_code == 400
    assert response.get_json() == {"message": "Invalid audit query filters."}
    assert list_events.call_count == 1


def test_audit_api_rejects_cursor_bound_to_different_filters(client, monkeypatch):
    token, list_events = issue_cursor(
        client, monkeypatch, event_type="ACCESS_ATTEMPT"
    )

    response = client.get(
        "/api/admin/audit-events?event_type=UPLOAD&limit=1&cursor=" + token
    )

    assert response.status_code == 400
    assert response.get_json() == {"message": "Invalid audit query filters."}
    assert list_events.call_count == 1


@pytest.mark.parametrize(
    "query",
    [
        "actor_user_id=",
        "actor_user_id=0",
        "actor_user_id=abc",
        "limit=0",
        "limit=-1",
        "offset=-1",
        "offset=0",
        "start_date=2025-02-30",
        "start_date=2025-02-02&end_date=2025-02-01",
        "end_date=9999-12-31",
    ],
)
def test_audit_api_rejects_invalid_filters(client, monkeypatch, query):
    authenticate(client)
    monkeypatch.setattr(
        admin_routes, "get_current_user", lambda user_id: {"id": user_id, "role": "admin"}
    )
    list_events = MagicMock()
    monkeypatch.setattr(admin_routes, "list_audit_events", list_events)

    response = client.get(f"/api/admin/audit-events?{query}")

    assert response.status_code == 400
    assert response.get_json() == {"message": "Invalid audit query filters."}
    list_events.assert_not_called()


def test_audit_api_excludes_sensitive_fields_and_filters_detail_keys(
    client, monkeypatch
):
    authenticate(client)
    monkeypatch.setattr(
        admin_routes, "get_current_user", lambda user_id: {"id": user_id, "role": "admin"}
    )
    list_events = MagicMock(return_value=[audit_row(
        file_path="C:/private/file",
        stored_filename="random-secret.bin",
        document_contents="secret contents",
        password="hash",
        secret="token",
        details=(
            '{"reason":"insufficient_permission","file_path":"C:/private/file",'
            '"password":"secret"}'
        ),
    )])
    monkeypatch.setattr(admin_routes, "list_audit_events", list_events)

    response = client.get("/api/admin/audit-events")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    for forbidden in (
        "file_path", "stored_filename", "document_contents", "password",
        "secret", "C:/private/file", "random-secret.bin",
    ):
        assert forbidden not in body
    assert response.get_json()["items"][0]["details"] == {
        "reason": "insufficient_permission"
    }


@pytest.mark.parametrize("failure_source", ["role", "query"])
def test_audit_api_returns_generic_database_error(client, monkeypatch, failure_source):
    authenticate(client)
    if failure_source == "role":
        monkeypatch.setattr(
            admin_routes,
            "get_current_user",
            MagicMock(side_effect=RuntimeError("database password leaked")),
        )
    else:
        monkeypatch.setattr(
            admin_routes,
            "get_current_user",
            lambda user_id: {"id": user_id, "role": "admin"},
        )
        monkeypatch.setattr(
            admin_routes,
            "list_audit_events",
            MagicMock(side_effect=RuntimeError("internal SQL details")),
        )

    response = client.get("/api/admin/audit-events")

    assert response.status_code == 500
    assert response.get_json() == {
        "message": "Audit records could not be retrieved."
    }
    assert "leaked" not in response.get_data(as_text=True)
    assert "SQL details" not in response.get_data(as_text=True)


@pytest.mark.parametrize(
    ("case", "expected_status"),
    [
        ("unauthenticated", 401),
        ("non_admin", 403),
        ("invalid_filter", 400),
        ("success", 200),
        ("database_error", 500),
    ],
)
def test_audit_api_sets_no_store_for_success_and_error_responses(
    client, monkeypatch, case, expected_status
):
    get_user = MagicMock()
    list_events = MagicMock(return_value=[])
    monkeypatch.setattr(admin_routes, "get_current_user", get_user)
    monkeypatch.setattr(admin_routes, "list_audit_events", list_events)

    if case != "unauthenticated":
        authenticate(client)
        get_user.return_value = {
            "id": 42,
            "role": "viewer" if case == "non_admin" else "admin",
        }
    if case == "database_error":
        list_events.side_effect = RuntimeError("internal database message")

    query = "?start_date=not-a-date" if case == "invalid_filter" else ""
    response = client.get(f"/api/admin/audit-events{query}")

    assert response.status_code == expected_status
    assert response.headers["Cache-Control"] == "no-store"
