from unittest.mock import MagicMock

import pytest
from flask import Flask

from routes import document_routes
from services.authorization_service import AuthorizationError


@pytest.fixture
def client():
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test-secret", WTF_CSRF_ENABLED=False)
    app.register_blueprint(document_routes.document_bp, url_prefix="/api/documents")
    return app.test_client()


def authenticate(client, user_id=2):
    with client.session_transaction() as session:
        session["user_id"] = user_id


def test_grant_requires_authentication(client, monkeypatch):
    grant = MagicMock()
    monkeypatch.setattr(document_routes, "grant_document_permission", grant)

    response = client.post(
        "/api/documents/10/permissions",
        json={"target_user_id": 3, "permission": "READ"},
    )

    assert response.status_code == 401
    grant.assert_not_called()


@pytest.mark.parametrize("permission", ["READ", "EDIT"])
def test_grant_valid_permission_uses_session_user_id(client, monkeypatch, permission):
    authenticate(client, user_id=2)
    grant = MagicMock(return_value=17)
    monkeypatch.setattr(document_routes, "grant_document_permission", grant)

    response = client.post(
        "/api/documents/10/permissions",
        json={
            "target_user_id": 3,
            "permission": permission.lower(),
            "user_id": 999,
            "role": "admin",
        },
    )

    assert response.status_code == 201
    assert response.get_json() == {"permission_id": 17}
    grant.assert_called_once_with(2, 10, 3, permission)


def test_grant_rejects_invalid_permission(client, monkeypatch):
    authenticate(client)
    grant = MagicMock()
    monkeypatch.setattr(document_routes, "grant_document_permission", grant)

    response = client.post(
        "/api/documents/10/permissions",
        json={"target_user_id": 3, "permission": "DELETE"},
    )

    assert response.status_code == 400
    grant.assert_not_called()


def test_grant_rejects_missing_target_user_id(client, monkeypatch):
    authenticate(client)
    grant = MagicMock()
    monkeypatch.setattr(document_routes, "grant_document_permission", grant)

    response = client.post(
        "/api/documents/10/permissions",
        json={"permission": "READ"},
    )

    assert response.status_code == 400
    grant.assert_not_called()


@pytest.mark.parametrize("target_user_id", [0, "3"])
def test_grant_rejects_invalid_target_user_id(client, monkeypatch, target_user_id):
    authenticate(client)
    grant = MagicMock()
    monkeypatch.setattr(document_routes, "grant_document_permission", grant)

    response = client.post(
        "/api/documents/10/permissions",
        json={"target_user_id": target_user_id, "permission": "READ"},
    )

    assert response.status_code == 400
    grant.assert_not_called()


def test_grant_maps_authorization_error_to_404(client, monkeypatch):
    authenticate(client)
    grant = MagicMock(side_effect=AuthorizationError("owner required"))
    monkeypatch.setattr(document_routes, "grant_document_permission", grant)

    response = client.post(
        "/api/documents/10/permissions",
        json={"target_user_id": 3, "permission": "READ"},
    )

    assert response.status_code == 404
    grant.assert_called_once_with(2, 10, 3, "READ")


def test_revoke_requires_authentication(client, monkeypatch):
    revoke = MagicMock()
    monkeypatch.setattr(document_routes, "revoke_document_permission", revoke)

    response = client.delete("/api/documents/10/permissions/3")

    assert response.status_code == 401
    revoke.assert_not_called()


def test_revoke_uses_session_user_id(client, monkeypatch):
    authenticate(client, user_id=2)
    revoke = MagicMock(return_value=True)
    monkeypatch.setattr(document_routes, "revoke_document_permission", revoke)

    response = client.delete(
        "/api/documents/10/permissions/3",
        json={"user_id": 999, "role": "admin"},
    )

    assert response.status_code == 200
    assert response.get_json() == {"message": "Permission revoked."}
    revoke.assert_called_once_with(2, 10, 3)


def test_revoke_maps_authorization_error_to_404(client, monkeypatch):
    authenticate(client)
    revoke = MagicMock(side_effect=AuthorizationError("owner required"))
    monkeypatch.setattr(document_routes, "revoke_document_permission", revoke)

    response = client.delete("/api/documents/10/permissions/3")

    assert response.status_code == 404
    revoke.assert_called_once_with(2, 10, 3)
