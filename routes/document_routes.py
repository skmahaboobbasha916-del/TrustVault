import os

from flask import Blueprint, request, session, render_template, send_file
from controllers.document_controller import upload_document
from services.authorization_service import AuthorizationError, authorize_document

document_bp = Blueprint("documents", __name__)


@document_bp.route("/<int:document_id>/download", methods=["GET"])
def download_document(document_id):
    if "user_id" not in session:
        return "Authentication is required.", 401

    try:
        document = authorize_document(session["user_id"], document_id, "download")
    except AuthorizationError:
        return "Document not found.", 404
    except Exception:
        return "Document download failed.", 500

    file_path = document.get("file_path")
    if not file_path or not os.path.isfile(file_path):
        return "Document file not found.", 404

    try:
        return send_file(
            file_path,
            as_attachment=True,
            download_name=document.get("original_filename"),
        )
    except OSError:
        return "Document file not found.", 404
    except Exception:
        return "Document download failed.", 500

@document_bp.route("/upload-page", methods=["GET"])
def upload_page():
    if "user_id" not in session:
        return "Please log in first.", 401

    return render_template("upload.html")

@document_bp.route("/upload", methods=["POST"])
def upload():
    if "user_id" not in session:
        return "Please log in first.", 401

    file = request.files.get("document")
    category = request.form.get("category", "").strip()

    try:
        document_id = upload_document(
            file,
            session["user_id"],
            category
        )

        return f"Document uploaded successfully. ID: {document_id}", 201

    except ValueError as error:
        return str(error), 400

    except Exception:
        return "Document upload failed.", 500
