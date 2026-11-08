from datetime import date, datetime
from html import unescape
import re
from unittest.mock import MagicMock
from urllib.parse import urlsplit, parse_qs

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


def dashboard_row(**overrides):
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


def make_admin(monkeypatch, events):
    get_user = MagicMock(return_value={"id": 42, "role": "admin"})
    list_events = MagicMock(return_value=events)
    monkeypatch.setattr(admin_routes, "get_current_user", get_user)
    monkeypatch.setattr(admin_routes, "list_audit_events", list_events)
    return get_user, list_events


def test_dashboard_requires_session_and_returns_401(client, monkeypatch):
    get_user = MagicMock()
    list_events = MagicMock()
    monkeypatch.setattr(admin_routes, "get_current_user", get_user)
    monkeypatch.setattr(admin_routes, "list_audit_events", list_events)

    response = client.get("/admin/audit")

    assert response.status_code == 401
    assert response.headers["Cache-Control"] == "no-store"
    get_user.assert_not_called()
    list_events.assert_not_called()


def test_admin_audit_stylesheet_is_served_and_linked(client, monkeypatch):
    authenticate(client)
    make_admin(monkeypatch, [])

    page = client.get("/admin/audit")
    stylesheet = client.get("/static/css/admin_audit.css")

    assert page.status_code == 200
    assert '/static/css/admin_audit.css' in page.get_data(as_text=True)
    assert stylesheet.status_code == 200
    assert stylesheet.mimetype == "text/css"
    css = stylesheet.get_data(as_text=True)
    for selector in (
        ".dashboard-shell", ".filter-panel", ".audit-table",
        ".status-success", ".status-denied", ".status-failure",
        ".timestamp-origin-utc", ".timestamp-origin-unknown",
    ):
        assert selector in css
    assert "@media (max-width: 900px)" in css
    assert "@media (max-width: 560px)" in css


def test_audit_table_scroll_region_is_keyboard_accessible(client, monkeypatch):
    authenticate(client)
    make_admin(monkeypatch, [])

    page = client.get("/admin/audit")
    body = page.get_data(as_text=True)
    scroll_region = re.search(
        r'<div class="table-scroll-region"([^>]*)>', body
    )

    assert page.status_code == 200
    assert scroll_region
    assert 'role="region"' in scroll_region.group(1)
    assert 'aria-label="Scrollable audit events table"' in scroll_region.group(1)
    assert 'tabindex="0"' in scroll_region.group(1)
    css_response = client.get("/static/css/admin_audit.css")
    assert ".table-scroll-region:focus-visible" in css_response.get_data(as_text=True)


def test_dashboard_uses_database_role_and_denies_non_admin(client, monkeypatch):
    authenticate(client, role="admin")
    get_user = MagicMock(return_value={"id": 42, "role": "viewer"})
    list_events = MagicMock()
    monkeypatch.setattr(admin_routes, "get_current_user", get_user)
    monkeypatch.setattr(admin_routes, "list_audit_events", list_events)

    response = client.get("/admin/audit")

    assert response.status_code == 403
    assert response.headers["Cache-Control"] == "no-store"
    get_user.assert_called_once_with(42)
    list_events.assert_not_called()


def test_admin_dashboard_displays_only_safe_audit_metadata_and_timestamp_origins(
    client, monkeypatch
):
    authenticate(client, role="viewer")
    get_user, _ = make_admin(monkeypatch, [
        dashboard_row(
            event_type="<script>alert(1)</script>",
            occurred_at_origin="UTC",
            file_path="C:/private/document.pdf",
            stored_filename="internal-id.pdf",
            password="secret-hash",
            document_contents="private body",
        ),
        dashboard_row(id=8, occurred_at_origin="UNKNOWN_LEGACY"),
    ])

    response = client.get("/admin/audit")

    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    get_user.assert_called_once_with(42)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "<script>alert(1)</script>" not in body
    assert "2025-01-02T03:04:05.000000Z" in body
    assert "Timezone unknown" in body
    assert "UTC" in body
    for forbidden in (
        "file_path", "stored_filename", "C:/private/document.pdf",
        "internal-id.pdf", "secret-hash", "private body",
    ):
        assert forbidden not in body


def test_dashboard_reuses_audit_filters_and_signed_cursor_navigation(
    client, monkeypatch
):
    authenticate(client)
    first_time = datetime(2025, 2, 3, 4, 5, 6, 123456)
    first_page = [
        dashboard_row(id=30, occurred_at=first_time),
        dashboard_row(id=29, occurred_at=first_time),
        dashboard_row(id=28, occurred_at=datetime(2025, 2, 3, 4, 5, 5)),
    ]
    get_user = MagicMock(return_value={"id": 42, "role": "admin"})
    list_events = MagicMock(side_effect=[first_page, [first_page[2]]])
    monkeypatch.setattr(admin_routes, "get_current_user", get_user)
    monkeypatch.setattr(admin_routes, "list_audit_events", list_events)

    response = client.get(
        "/admin/audit?event_type=UPLOAD&action=VIEW&result=SUCCESS"
        "&actor_user_id=17&start_date=2025-02-01&end_date=2025-02-03&limit=2"
    )

    assert response.status_code == 200
    first_call = list_events.call_args_list[0]
    assert first_call.kwargs == {
        "event_type": "UPLOAD",
        "action": "VIEW",
        "result": "SUCCESS",
        "actor_user_id": 17,
        "start_date": date(2025, 2, 1),
        "end_date": date(2025, 2, 4),
        "limit": 2,
        "cursor_timestamp": None,
        "cursor_id": None,
    }

    body = unescape(response.get_data(as_text=True))
    next_link = re.search(r'<a href="([^"]+)">Next page</a>', body)
    assert next_link
    next_href = next_link.group(1)
    query = parse_qs(urlsplit(next_href).query)
    assert query["event_type"] == ["UPLOAD"]
    assert query["action"] == ["VIEW"]
    assert query["result"] == ["SUCCESS"]
    assert query["actor_user_id"] == ["17"]
    assert query["start_date"] == ["2025-02-01"]
    assert query["end_date"] == ["2025-02-03"]
    assert query["limit"] == ["2"]
    assert query["cursor"]

    next_response = client.get(next_href)

    assert next_response.status_code == 200
    second_call = list_events.call_args_list[1]
    assert second_call.kwargs["cursor_timestamp"] == first_time
    assert second_call.kwargs["cursor_id"] == 29
    assert second_call.kwargs["event_type"] == "UPLOAD"
    assert second_call.kwargs["start_date"] == date(2025, 2, 1)
    assert second_call.kwargs["end_date"] == date(2025, 2, 4)


def test_empty_actor_filter_from_html_form_does_not_break_cursor_navigation(
    client, monkeypatch
):
    authenticate(client)
    rows = [
        dashboard_row(id=12, occurred_at=datetime(2025, 1, 3)),
        dashboard_row(id=11, occurred_at=datetime(2025, 1, 2)),
        dashboard_row(id=10, occurred_at=datetime(2025, 1, 1)),
    ]
    _, list_events = make_admin(monkeypatch, [])
    list_events.side_effect = [rows, [rows[2]]]

    first = client.get("/admin/audit?actor_user_id=&limit=2")

    assert first.status_code == 200
    assert list_events.call_args_list[0].kwargs["actor_user_id"] is None
    body = unescape(first.get_data(as_text=True))
    next_link = re.search(r'<a href="([^"]+)">Next page</a>', body)
    assert next_link
    next_href = next_link.group(1)
    query = parse_qs(urlsplit(next_href).query)
    assert "actor_user_id" not in query

    second = client.get(next_href)

    assert second.status_code == 200
    assert list_events.call_args_list[1].kwargs["actor_user_id"] is None
    assert list_events.call_args_list[1].kwargs["cursor_id"] == 11


def test_dashboard_rejects_invalid_filters_without_querying(client, monkeypatch):
    authenticate(client)
    _, list_events = make_admin(monkeypatch, [])

    response = client.get("/admin/audit?start_date=2025-02-30")

    assert response.status_code == 400
    assert response.get_data(as_text=True) == "Invalid audit query filters."
    assert response.headers["Cache-Control"] == "no-store"
    list_events.assert_not_called()
