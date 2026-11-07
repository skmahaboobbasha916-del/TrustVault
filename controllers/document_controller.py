import os
import uuid
import hashlib

from flask import current_app
from werkzeug.utils import secure_filename

from models.document_model import create_document


ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "txt", "png", "jpg", "jpeg"
}


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