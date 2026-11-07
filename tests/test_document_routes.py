from unittest.mock import MagicMock
from datetime import datetime

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


def accessible_document(document_id, access_level, owner_id=1):
    return {
        "document_id": document_id,
        "owner_id": owner_id,
        "original_filename": f"document-{document_id}.txt",
        "category": "reports",
        "mime_type": "text/plain",
        "file_size": 128,
        "created_at": datetime(2025, 1, document_id),
        "access_level": access_level,
    }


def test_document_list_requires_authentication(client, monkeypatch):
    get_documents = MagicMock()
    monkeypatch.setattr(document_routes, "get_accessible_documents", get_documents)

    response = client.get("/api/documents/")

    assert response.status_code == 401
    get_documents.assert_not_called()


@pytest.mark.parametrize(
    "document, access_level",
    [
        (accessible_document(10, "OWNER", owner_id=2), "OWNER"),
        (accessible_document(11, "READ"), "READ"),
        (accessible_document(12, "EDIT"), "EDIT"),
    ],
)
def test_document_list_returns_owned_and_shared_documents(
    client, monkeypatch, document, access_level
):
    authenticate(client, user_id=2)
    get_documents = MagicMock(return_value=[document])
    monkeypatch.setattr(document_routes, "get_accessible_documents", get_documents)

    response = client.get("/api/documents/")

    assert response.status_code == 200
    assert response.get_json() == [{
        **document,
        "created_at": document["created_at"].strftime("%a, %d %b %Y %H:%M:%S GMT"),
    }]
    assert response.get_json()[0]["access_level"] == access_level


def test_document_list_passes_session_user_id_only(client, monkeypatch):
    authenticate(client, user_id=42)
    get_documents = MagicMock(return_value=[])
    monkeypatch.setattr(document_routes, "get_accessible_documents", get_documents)

    response = client.get("/api/documents/?user_id=999")

    assert response.status_code == 200
    get_documents.assert_called_once_with(42)


def test_document_list_does_not_return_revoked_permission_documents(client, monkeypatch):
    authenticate(client)
    # The model returns only active permissions, so the revoked document is absent.
    active_documents = [accessible_document(11, "READ")]
    get_documents = MagicMock(return_value=active_documents)
    monkeypatch.setattr(document_routes, "get_accessible_documents", get_documents)

    response = client.get("/api/documents/")

    assert response.status_code == 200
    assert [item["document_id"] for item in response.get_json()] == [11]


def test_document_list_returns_generic_500_on_model_failure(client, monkeypatch):
    authenticate(client)
    get_documents = MagicMock(side_effect=RuntimeError("database credentials leaked"))
    monkeypatch.setattr(document_routes, "get_accessible_documents", get_documents)

    response = client.get("/api/documents/")

    assert response.status_code == 500
    assert response.get_data(as_text=True) == "Document listing failed."
    assert "database credentials leaked" not in response.get_data(as_text=True)


def test_document_list_excludes_internal_storage_fields(client, monkeypatch):
    authenticate(client)
    document = accessible_document(10, "OWNER", owner_id=2)
    get_documents = MagicMock(return_value=[document])
    monkeypatch.setattr(document_routes, "get_accessible_documents", get_documents)

    response = client.get("/api/documents/")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "file_path" not in body
    assert "stored_filename" not in body
