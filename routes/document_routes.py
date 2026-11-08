import os

from flask import Blueprint, jsonify, request, session, render_template, send_file
from controllers.document_controller import (
    delete_document,
    normalize_document_search_dates,
    upload_document,
)
from models.document_model import get_accessible_documents
from services.authorization_service import (
    AuthorizationError,
    authorize_document,
    grant_document_permission,
    revoke_document_permission,
)

document_bp = Blueprint("documents", __name__)


@document_bp.route("/<int:document_id>", methods=["DELETE"])
def delete_document_route(document_id):
    if "user_id" not in session:
        return jsonify({"message": "Authentication is required."}), 401

    try:
        delete_document(session["user_id"], document_id)
        return jsonify({"message": "Document deleted successfully."}), 200
    except (AuthorizationError, FileNotFoundError):
        return jsonify({"message": "Document not found."}), 404
    except Exception:
        return jsonify({"message": "Document deletion failed."}), 500


@document_bp.route("/", methods=["GET"])
def list_documents():
    if "user_id" not in session:
        return "Authentication is required.", 401

    try:
        filename = request.args.get("filename", "").strip() or None
        owner_name = request.args.get("owner_name", "").strip() or None
        category = request.args.get("category", "").strip() or None
        start_value = request.args.get("start_date", "").strip() or None
        end_value = request.args.get("end_date", "").strip() or None
        start_date, end_date = normalize_document_search_dates(
            start_value, end_value
        )

        if any((filename, owner_name, category, start_date, end_date)):
            documents = get_accessible_documents(
                session["user_id"],
                filename=filename,
                owner_name=owner_name,
                category=category,
                start_date=start_date,
                end_date=end_date,
            )
        else:
            # Preserve compatibility with the existing no-filter model call.
            documents = get_accessible_documents(session["user_id"])
        return jsonify(documents), 200
    except ValueError:
        return "Invalid document search filters.", 400
    except Exception:
        return "Document listing failed.", 500


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


@document_bp.route("/<int:document_id>/permissions", methods=["POST"])
def grant_permission(document_id):
    if "user_id" not in session:
        return "Authentication is required.", 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return "A JSON request body is required.", 400

    target_user_id = payload.get("target_user_id")
    permission = payload.get("permission")
    if type(target_user_id) is not int or target_user_id <= 0:
        return "A valid target_user_id is required.", 400
    if not isinstance(permission, str):
        return "Invalid permission.", 400
    permission = permission.strip().upper()
    if permission not in {"READ", "EDIT"}:
        return "Invalid permission.", 400

    try:
        permission_id = grant_document_permission(
            session["user_id"], document_id, target_user_id, permission
        )
        return {"permission_id": permission_id}, 201
    except ValueError:
        return "Invalid permission.", 400
    except AuthorizationError:
        return "Document not found.", 404
    except Exception:
        return "Permission grant failed.", 500


@document_bp.route("/<int:document_id>/permissions/<int:target_user_id>", methods=["DELETE"])
def revoke_permission(document_id, target_user_id):
    if "user_id" not in session:
        return "Authentication is required.", 401

    try:
        revoke_document_permission(session["user_id"], document_id, target_user_id)
        return {"message": "Permission revoked."}, 200
    except AuthorizationError:
        return "Document not found.", 404
    except Exception:
        return "Permission revocation failed.", 500


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
