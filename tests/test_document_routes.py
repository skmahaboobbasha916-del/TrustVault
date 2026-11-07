from unittest.mock import MagicMock

import pytest
from flask import Flask

from routes import document_routes
from services.authorization_service import AuthorizationError


@pytest.fixture
def client():
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test-secret")
    app.register_blueprint(document_routes.document_bp, url_prefix="/api/documents")
    return app.test_client()


def authenticate(client, user_id=2):
    with client.session_transaction() as session:
        session["user_id"] = user_id


def authorized_document(file_path):
    return {
        "id": 10,
        "owner_id": 1,
        "file_path": str(file_path),
        "original_filename": "report.txt",
    }


def test_unauthenticated_user_receives_401(client, monkeypatch):
    authorize = MagicMock()
    monkeypatch.setattr(document_routes, "authorize_document", authorize)

    response = client.get("/api/documents/10/download")

    assert response.status_code == 401
    authorize.assert_not_called()


@pytest.mark.parametrize("access_type", ["owner", "READ", "EDIT"])
def test_authorized_users_can_download(client, monkeypatch, tmp_path, access_type):
    authenticate(client)
    stored_file = tmp_path / "stored-document.txt"
    stored_file.write_bytes(b"trusted document contents")
    document = authorized_document(stored_file)
    authorize = MagicMock(return_value=document)
    monkeypatch.setattr(document_routes, "authorize_document", authorize)

    response = client.get("/api/documents/10/download")

    assert response.status_code == 200
    assert response.data == b"trusted document contents"
    content_disposition = response.headers["Content-Disposition"]
    assert content_disposition.startswith("attachment;")
    assert "report.txt" in content_disposition
    authorize.assert_called_once_with(2, 10, "download")


@pytest.mark.parametrize("denial_reason", ["no permission", "permission revoked", "document not found"])
def test_unauthorized_or_missing_document_receives_404(client, monkeypatch, denial_reason):
    authenticate(client)
    authorize = MagicMock(side_effect=AuthorizationError(denial_reason))
    monkeypatch.setattr(document_routes, "authorize_document", authorize)

    response = client.get("/api/documents/10/download")

    assert response.status_code == 404
    authorize.assert_called_once_with(2, 10, "download")


def test_missing_physical_file_receives_404(client, monkeypatch, tmp_path):
    authenticate(client)
    document = authorized_document(tmp_path / "missing-document.txt")
    authorize = MagicMock(return_value=document)
    monkeypatch.setattr(document_routes, "authorize_document", authorize)
    monkeypatch.setattr(document_routes.os.path, "isfile", lambda path: False)

    response = client.get("/api/documents/10/download")

    assert response.status_code == 404
    authorize.assert_called_once_with(2, 10, "download")
