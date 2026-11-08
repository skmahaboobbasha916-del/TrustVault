
import re

import pytest

from app import create_app
from routes import auth_routes, document_routes


@pytest.fixture
def app():
    application = create_app({
        "TESTING": True,
        "SECRET_KEY": "csrf-integration-test-secret-key-32",
    })
    assert application.config["WTF_CSRF_ENABLED"] is True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def form_csrf_token(client, path="/api/auth/login"):
    response = client.get(path)
    assert response.status_code == 200

    match = re.search(
        r'name="csrf_token"\s+value="([^"]+)"',
        response.get_data(as_text=True),
    )
    assert match
    return match.group(1)


def authenticate(client, user_id=2):
    with client.session_transaction() as session:
        session["user_id"] = user_id


def test_missing_form_token_is_rejected(client):
    response = client.post(
        "/api/auth/login",
        data={
            "email": "user@example.com",
            "password": "password",
        },
    )

    assert response.status_code == 400


def test_invalid_form_token_is_rejected(client):
    response = client.post(
        "/api/auth/login",
        data={
            "email": "user@example.com",
            "password": "password",
            "csrf_token": "invalid-token",
        },
    )

    assert response.status_code == 400


def test_valid_form_token_is_accepted(client, monkeypatch):
    monkeypatch.setattr(
        auth_routes,
        "register_user",
        lambda *_: (True, "created"),
    )
    token = form_csrf_token(client, "/api/auth/register")

    response = client.post(
        "/api/auth/register",
        data={
            "name": "Test User",
            "email": "user@example.com",
            "password": "password",
            "csrf_token": token,
        },
    )

    assert response.status_code == 201


def test_valid_json_csrf_header_is_accepted(client, monkeypatch):
    deleted = []

    monkeypatch.setattr(
        document_routes,
        "delete_document",
        lambda user_id, document_id: deleted.append(
            (user_id, document_id)
        ),
    )

    token = form_csrf_token(client)
    authenticate(client, user_id=42)

    response = client.delete(
        "/api/documents/10",
        headers={"X-CSRFToken": token},
    )

    assert response.status_code == 200
    assert deleted == [(42, 10)]


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("delete", "/api/documents/10", None),
        ("patch", "/api/documents/10", {"category": "reports"}),
        (
            "post",
            "/api/documents/10/permissions",
            {"target_user_id": 3, "permission": "READ"},
        ),
        ("delete", "/api/documents/10/permissions/3", None),
    ],
)
def test_json_mutation_routes_reject_missing_csrf_header(
    client, method, path, payload
):
    authenticate(client)
    request = getattr(client, method)

    response = (
        request(path, json=payload)
        if payload is not None
        else request(path)
    )

    assert response.status_code == 400


def test_logout_rejects_missing_csrf_token(client):
    authenticate(client, user_id=42)

    response = client.post("/api/auth/logout")

    assert response.status_code == 400

    with client.session_transaction() as session:
        assert session["user_id"] == 42


def test_invalid_json_csrf_header_is_rejected(client):
    authenticate(client, user_id=42)

    response = client.delete(
        "/api/documents/10",
        headers={"X-CSRFToken": "invalid-token"},
    )

    assert response.status_code == 400
