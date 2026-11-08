import os
import uuid
import hashlib
from datetime import date, timedelta

from flask import current_app
from werkzeug.utils import secure_filename

from models.document_model import create_document, delete_document_record
from services.authorization_service import authorize_document


ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "txt", "png", "jpg", "jpeg"
}


def normalize_document_search_dates(start_date=None, end_date=None):
    """Validate ISO calendar dates and return an inclusive start/exclusive end."""
    parsed_start = _parse_search_date(start_date) if start_date else None
    parsed_end = _parse_search_date(end_date) if end_date else None

    if parsed_start is not None and parsed_end is not None and parsed_start > parsed_end:
        raise ValueError("Invalid date range.")

    try:
        exclusive_end = parsed_end + timedelta(days=1) if parsed_end is not None else None
    except OverflowError as error:
        raise ValueError("Invalid date range.") from error
    return parsed_start, exclusive_end


def _parse_search_date(value):
    if not isinstance(value, str):
        raise ValueError("Invalid date.")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise ValueError("Invalid date.") from error
    if parsed.isoformat() != value:
        raise ValueError("Invalid date.")
    return parsed


def upload_document(file, owner_id, category=None):

    if not file or not file.filename:
        raise ValueError("Please select a file.")

    original_filename = secure_filename(file.filename)

    if "." not in original_filename:
        raise ValueError("Invalid file type.")

    extension = original_filename.rsplit(".", 1)[1].lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("File type not allowed.")

    stored_filename = f"{uuid.uuid4().hex}.{extension}"

    upload_folder = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_folder, exist_ok=True)

    file_path = os.path.join(upload_folder, stored_filename)

    try:
        file.save(file_path)

        file_size = os.path.getsize(file_path)

        if file_size == 0 or file_size > 10 * 1024 * 1024:
            raise ValueError("File must be between 1 byte and 10 MB.")

        sha256 = hashlib.sha256()

        with open(file_path, "rb") as uploaded_file:
            for chunk in iter(lambda: uploaded_file.read(8192), b""):
                sha256.update(chunk)

        checksum = sha256.hexdigest()

        document_id = create_document(
            owner_id,
            original_filename,
            stored_filename,
            file_path,
            category,
            file.mimetype,
            file_size,
            checksum
        )

        return document_id

    except Exception:
        if os.path.exists(file_path):
            os.remove(file_path)
        raise


def delete_document(session_user_id, document_id):
    """Authorize and delete a document's file, then its database record."""
    document = authorize_document(session_user_id, document_id, "delete")

    stored_path = document.get("file_path")
    if not isinstance(stored_path, str) or not stored_path:
        raise ValueError("Document file path is invalid.")

    upload_folder = current_app.config["UPLOAD_FOLDER"]
    resolved_upload_folder = os.path.realpath(upload_folder)
    resolved_file_path = os.path.realpath(stored_path)

    try:
        common_path = os.path.commonpath(
            [resolved_upload_folder, resolved_file_path]
        )
    except ValueError as error:
        raise ValueError("Document file path is outside the upload directory.") from error

    if (common_path != resolved_upload_folder
            or resolved_file_path == resolved_upload_folder):
        raise ValueError("Document file path is outside the upload directory.")

    if not os.path.isfile(resolved_file_path):
        raise FileNotFoundError("Document file not found.")

    os.remove(resolved_file_path)
    delete_document_record(document_id, session_user_id)
