from unittest.mock import MagicMock, call

import pytest
from flask import Flask

from controllers import document_controller
from services.authorization_service import AuthorizationError


@pytest.fixture
def app(tmp_path):
    app = Flask(__name__)
    app.config["UPLOAD_FOLDER"] = str(tmp_path / "uploads")
    (tmp_path / "uploads").mkdir()
    return app


def test_authorization_happens_before_filesystem_operations(app, monkeypatch):
    authorize = MagicMock(side_effect=AuthorizationError("denied"))
    realpath = MagicMock(wraps=document_controller.os.path.realpath)
    isfile = MagicMock(wraps=document_controller.os.path.isfile)
    remove = MagicMock(wraps=document_controller.os.remove)
    delete_record = MagicMock()
    monkeypatch.setattr(document_controller, "authorize_document", authorize)
    monkeypatch.setattr(document_controller.os.path, "realpath", realpath)
    monkeypatch.setattr(document_controller.os.path, "isfile", isfile)
    monkeypatch.setattr(document_controller.os, "remove", remove)
    monkeypatch.setattr(document_controller, "delete_document_record", delete_record)

    with app.app_context(), pytest.raises(AuthorizationError):
        document_controller.delete_document(42, 10)

    authorize.assert_called_once_with(42, 10, "delete")
    realpath.assert_not_called()
    isfile.assert_not_called()
    remove.assert_not_called()
    delete_record.assert_not_called()


@pytest.mark.parametrize("outside_name", ["outside.txt", "uploads-elsewhere/outside.txt"])
def test_rejects_paths_outside_upload_folder(app, monkeypatch, tmp_path, outside_name):
    outside_path = tmp_path / outside_name
    outside_path.parent.mkdir(parents=True, exist_ok=True)
    outside_path.write_text("must remain", encoding="utf-8")
    authorize = MagicMock(return_value={"file_path": str(outside_path)})
    remove = MagicMock()
    delete_record = MagicMock()
    monkeypatch.setattr(document_controller, "authorize_document", authorize)
    monkeypatch.setattr(document_controller.os, "remove", remove)
    monkeypatch.setattr(document_controller, "delete_document_record", delete_record)

    with app.app_context(), pytest.raises(ValueError, match="outside the upload directory"):
        document_controller.delete_document(42, 10)

    assert outside_path.read_text(encoding="utf-8") == "must remain"
    remove.assert_not_called()
    delete_record.assert_not_called()


def test_missing_physical_file_does_not_delete_database_record(app, monkeypatch):
    missing_path = app.config["UPLOAD_FOLDER"] + "/missing.txt"
    authorize = MagicMock(return_value={"file_path": missing_path})
    remove = MagicMock()
    delete_record = MagicMock()
    monkeypatch.setattr(document_controller, "authorize_document", authorize)
    monkeypatch.setattr(document_controller.os, "remove", remove)
    monkeypatch.setattr(document_controller, "delete_document_record", delete_record)

    with app.app_context(), pytest.raises(FileNotFoundError):
        document_controller.delete_document(42, 10)

    remove.assert_not_called()
    delete_record.assert_not_called()


def test_database_failure_after_file_removal_propagates(app, monkeypatch, tmp_path):
    file_path = tmp_path / "uploads" / "document.txt"
    file_path.write_text("document", encoding="utf-8")
    authorize = MagicMock(return_value={"file_path": str(file_path)})
    delete_record = MagicMock(side_effect=RuntimeError("database unavailable"))
    monkeypatch.setattr(document_controller, "authorize_document", authorize)
    monkeypatch.setattr(document_controller, "delete_document_record", delete_record)

    with app.app_context(), pytest.raises(RuntimeError, match="database unavailable"):
        document_controller.delete_document(42, 10)

    assert not file_path.exists()
    delete_record.assert_called_once_with(10, 42)
