from unittest.mock import MagicMock
from datetime import datetime

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


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("filename=Q1", {"filename": "Q1"}),
        ("owner_name=Ada", {"owner_name": "Ada"}),
        ("category=reports", {"category": "reports"}),
        ("start_date=2025-01-01", {"start_date": datetime(2025, 1, 1).date()}),
        (
            "filename=report&owner_name=Ada&category=reports&start_date=2025-01-01&end_date=2025-01-31",
            {
                "filename": "report",
                "owner_name": "Ada",
                "category": "reports",
                "start_date": datetime(2025, 1, 1).date(),
                "end_date": datetime(2025, 2, 1).date(),
            },
        ),
    ],
)
def test_document_list_passes_search_filters(client, monkeypatch, query, expected):
    authenticate(client, user_id=42)
    get_documents = MagicMock(return_value=[])
    monkeypatch.setattr(document_routes, "get_accessible_documents", get_documents)

    response = client.get(f"/api/documents/?{query}")

    assert response.status_code == 200
    get_documents.assert_called_once_with(
        42,
        filename=expected.get("filename"),
        owner_name=expected.get("owner_name"),
        category=expected.get("category"),
        start_date=expected.get("start_date"),
        end_date=expected.get("end_date"),
    )


@pytest.mark.parametrize(
    "query",
    [
        "start_date=2025-02-30",
        "end_date=9999-12-31",
        "end_date=not-a-date",
        "start_date=2025-03-01&end_date=2025-02-28",
        "start_date=2025-1-01",
    ],
)
def test_document_list_rejects_invalid_date_filters(client, monkeypatch, query):
    authenticate(client)
    get_documents = MagicMock()
    monkeypatch.setattr(document_routes, "get_accessible_documents", get_documents)

    response = client.get(f"/api/documents/?{query}")

    assert response.status_code == 400
    assert response.get_data(as_text=True) == "Invalid document search filters."
    get_documents.assert_not_called()


def test_document_list_search_uses_session_identity_and_ignores_user_id_query(
    client, monkeypatch
):
    authenticate(client, user_id=42)
    get_documents = MagicMock(return_value=[])
    monkeypatch.setattr(document_routes, "get_accessible_documents", get_documents)

    response = client.get("/api/documents/?user_id=999&filename=report")

    assert response.status_code == 200
    get_documents.assert_called_once_with(
        42,
        filename="report",
        owner_name=None,
        category=None,
        start_date=None,
        end_date=None,
    )


def test_document_delete_requires_authentication(client, monkeypatch):
    delete = MagicMock()
    monkeypatch.setattr(document_routes, "delete_document", delete)

    response = client.delete("/api/documents/10")

    assert response.status_code == 401
    delete.assert_not_called()


def test_document_delete_returns_success_and_passes_session_user_id(
    client, monkeypatch
):
    authenticate(client, user_id=42)
    delete = MagicMock()
    monkeypatch.setattr(document_routes, "delete_document", delete)

    response = client.delete("/api/documents/10?user_id=999")

    assert response.status_code == 200
    assert response.get_json() == {"message": "Document deleted successfully."}
    delete.assert_called_once_with(42, 10)


def test_document_delete_maps_authorization_error_to_404(client, monkeypatch):
    authenticate(client, user_id=42)
    delete = MagicMock(side_effect=AuthorizationError("private authorization detail"))
    monkeypatch.setattr(document_routes, "delete_document", delete)

    response = client.delete("/api/documents/10")

    assert response.status_code == 404
    assert response.get_json() == {"message": "Document not found."}
    assert "private authorization detail" not in response.get_data(as_text=True)
    delete.assert_called_once_with(42, 10)


def test_document_delete_maps_missing_file_to_404(client, monkeypatch):
    authenticate(client, user_id=42)
    delete = MagicMock(side_effect=FileNotFoundError("C:/private/uploads/secret.txt"))
    monkeypatch.setattr(document_routes, "delete_document", delete)

    response = client.delete("/api/documents/10")

    assert response.status_code == 404
    assert response.get_json() == {"message": "Document not found."}
    assert "C:/private/uploads/secret.txt" not in response.get_data(as_text=True)
    delete.assert_called_once_with(42, 10)


def test_document_delete_returns_generic_500_without_internal_details(
    client, monkeypatch
):
    authenticate(client, user_id=42)
    delete = MagicMock(
        side_effect=RuntimeError("failure at C:/private/uploads/secret.txt")
    )
    monkeypatch.setattr(document_routes, "delete_document", delete)

    response = client.delete("/api/documents/10")

    assert response.status_code == 500
    assert response.get_json() == {"message": "Document deletion failed."}
    body = response.get_data(as_text=True)
    assert "C:/private/uploads/secret.txt" not in body
    assert "failure at" not in body
    delete.assert_called_once_with(42, 10)


@pytest.mark.parametrize("access_type", ["owner", "EDIT"])
def test_document_metadata_patch_allows_owner_and_edit_user(
    client, monkeypatch, access_type
):
    authenticate(client, user_id=42)
    modify = MagicMock(return_value=10)
    monkeypatch.setattr(document_routes, "modify_document_metadata", modify)

    response = client.patch(
        "/api/documents/10",
        json={"category": "reports", "original_filename": "report.txt"},
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "message": "Document metadata updated successfully.",
        "document_id": 10,
    }
    modify.assert_called_once_with(
        42, 10, {"category": "reports", "original_filename": "report.txt"}
    )


@pytest.mark.parametrize("access_type", ["READ", "admin"])
def test_document_metadata_patch_denies_read_and_admin_users(
    client, monkeypatch, access_type
):
    authenticate(client, user_id=42)
    modify = MagicMock(side_effect=AuthorizationError("private access details"))
    monkeypatch.setattr(document_routes, "modify_document_metadata", modify)

    response = client.patch("/api/documents/10", json={"category": "reports"})

    assert response.status_code == 404
    assert response.get_json() == {"message": "Document not found."}
    assert "private access details" not in response.get_data(as_text=True)
    modify.assert_called_once_with(42, 10, {"category": "reports"})


def test_document_metadata_patch_requires_authentication(client, monkeypatch):
    modify = MagicMock()
    monkeypatch.setattr(document_routes, "modify_document_metadata", modify)

    response = client.patch("/api/documents/10", json={"category": "reports"})

    assert response.status_code == 401
    assert response.get_json() == {"message": "Authentication is required."}
    modify.assert_not_called()


@pytest.mark.parametrize("body", [None, {}, [], "invalid"])
def test_document_metadata_patch_rejects_empty_or_non_object_json(
    client, monkeypatch, body
):
    authenticate(client)
    modify = MagicMock()
    monkeypatch.setattr(document_routes, "modify_document_metadata", modify)

    if body == "invalid":
        response = client.patch(
            "/api/documents/10", data="not-json", content_type="application/json"
        )
    elif body is None:
        response = client.patch("/api/documents/10")
    else:
        response = client.patch("/api/documents/10", json=body)

    assert response.status_code == 400
    assert response.get_json() == {
        "message": "A non-empty JSON object is required."
    }
    modify.assert_not_called()


@pytest.mark.parametrize(
    "body",
    [
        {"user_id": 999, "category": "reports"},
        {"role": "admin", "category": "reports"},
        {"file_path": "C:/private/file"},
        {"checksum": "forged"},
    ],
)
def test_document_metadata_patch_rejects_unexpected_fields(
    client, monkeypatch, body
):
    authenticate(client, user_id=42)
    modify = MagicMock()
    monkeypatch.setattr(document_routes, "modify_document_metadata", modify)

    response = client.patch("/api/documents/10", json=body)

    assert response.status_code == 400
    assert response.get_json() == {
        "message": "Unsupported document metadata field."
    }
    modify.assert_not_called()


def test_document_metadata_patch_returns_generic_error_without_internal_details(
    client, monkeypatch
):
    authenticate(client)
    modify = MagicMock(side_effect=RuntimeError("failure at C:/private/file"))
    monkeypatch.setattr(document_routes, "modify_document_metadata", modify)

    response = client.patch("/api/documents/10", json={"category": "reports"})

    assert response.status_code == 500
    assert response.get_json() == {
        "message": "Document metadata update failed."
    }
    assert "C:/private/file" not in response.get_data(as_text=True)

def test_paginated_document_list_returns_next_cursor(
    client, monkeypatch
):
    authenticate(client, user_id=42)

    documents = [
        accessible_document(12, "OWNER", owner_id=42),
        accessible_document(11, "READ"),
        accessible_document(10, "EDIT"),
    ]

    get_documents = MagicMock(return_value=documents)
    monkeypatch.setattr(
        document_routes, "get_accessible_documents", get_documents
    )

    response = client.get("/api/documents/paginated?limit=2")

    assert response.status_code == 200

    body = response.get_json()
    assert [item["document_id"] for item in body["documents"]] == [12, 11]
    assert body["has_more"] is True
    assert body["limit"] == 2
    assert body["next_cursor"] is not None

    with client.application.app_context():
        cursor_date, cursor_id = document_routes._decode_document_cursor(
        body["next_cursor"]
    )
    assert cursor_date == documents[1]["created_at"]
    assert cursor_id == 11

    get_documents.assert_called_once_with(
        42,
        filename=None,
        owner_name=None,
        category=None,
        start_date=None,
        end_date=None,
        limit=2,
        cursor_created_at=None,
        cursor_document_id=None,
    )


def test_paginated_document_list_passes_decoded_cursor(
    client, monkeypatch
):
    authenticate(client, user_id=42)

    cursor_date = datetime(2025, 1, 5)
    with client.application.app_context():
        cursor = document_routes._get_document_cursor_serializer().dumps({
            "created_at": cursor_date.isoformat(),
            "document_id": 5,
    })
    get_documents = MagicMock(return_value=[])
    monkeypatch.setattr(
        document_routes, "get_accessible_documents", get_documents
    )

    response = client.get(
        f"/api/documents/paginated?cursor={cursor}"
    )

    assert response.status_code == 200
    get_documents.assert_called_once_with(
        42,
        filename=None,
        owner_name=None,
        category=None,
        start_date=None,
        end_date=None,
        limit=20,
        cursor_created_at=cursor_date,
        cursor_document_id=5,
    )


def test_paginated_document_list_rejects_tampered_cursor(
    client, monkeypatch
):
    authenticate(client)

    get_documents = MagicMock()
    monkeypatch.setattr(
        document_routes, "get_accessible_documents", get_documents
    )

    response = client.get(
        "/api/documents/paginated?cursor=invalid-tampered-token"
    )

    assert response.status_code == 400
    get_documents.assert_not_called()


@pytest.mark.parametrize("limit", ["0", "-1", "abc"])
def test_paginated_document_list_rejects_invalid_limit(
    client, monkeypatch, limit
):
    authenticate(client)

    get_documents = MagicMock()
    monkeypatch.setattr(
        document_routes, "get_accessible_documents", get_documents
    )

    response = client.get(
        f"/api/documents/paginated?limit={limit}"
    )

    assert response.status_code == 400
    get_documents.assert_not_called()


def test_paginated_document_list_caps_limit_at_50(
    client, monkeypatch
):
    authenticate(client, user_id=42)

    get_documents = MagicMock(return_value=[])
    monkeypatch.setattr(
        document_routes, "get_accessible_documents", get_documents
    )

    response = client.get("/api/documents/paginated?limit=100")

    assert response.status_code == 200
    assert response.get_json()["limit"] == 50

    assert get_documents.call_args.kwargs["limit"] == 50