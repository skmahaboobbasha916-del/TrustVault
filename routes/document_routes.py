
import os
from datetime import datetime
from itsdangerous import URLSafeSerializer, BadSignature
from flask import (
    Blueprint,
    current_app,
    jsonify,
    request,
    session,
    render_template,
    send_file,
    redirect,
    url_for,
)

from controllers.document_controller import (
    delete_document,
    normalize_document_search_dates,
    upload_document,
)

from models.document_model import (
    get_accessible_documents,
    get_documents_by_owner,
)

from models.user_model import get_all_users

from services.authorization_service import (
    AuthorizationError,
    authorize_document,
    grant_document_permission,
    modify_document_metadata,
    revoke_document_permission,
)


document_bp = Blueprint("documents", __name__)


def _get_document_cursor_serializer():
    return URLSafeSerializer(
        current_app.config["SECRET_KEY"],
        salt="trustvault-document-pagination-v1",
    )


def _encode_document_cursor(document):
    created_at = document["created_at"]
    document_id = document["document_id"]

    if not isinstance(created_at, datetime):
        raise ValueError("Invalid document timestamp.")

    if created_at.tzinfo is not None:
        raise ValueError("Document timestamp must be timezone-naive.")

    if type(document_id) is not int or document_id < 1:
        raise ValueError("Invalid document ID.")

    return _get_document_cursor_serializer().dumps({
        "created_at": created_at.isoformat(),
        "document_id": document_id,
    })


def _decode_document_cursor(token):
    try:
        payload = _get_document_cursor_serializer().loads(token)

        if not isinstance(payload, dict):
            raise ValueError("Invalid cursor.")

        if set(payload) != {"created_at", "document_id"}:
            raise ValueError("Invalid cursor.")

        created_at = datetime.fromisoformat(payload["created_at"])
        document_id = payload["document_id"]

        if created_at.tzinfo is not None:
            raise ValueError("Invalid cursor timestamp.")

        if type(document_id) is not int or document_id < 1:
            raise ValueError("Invalid cursor document ID.")

        return created_at, document_id

    except (BadSignature, TypeError, KeyError, ValueError):
        raise ValueError("Invalid or tampered pagination cursor.")


@document_bp.route("/<int:document_id>", methods=["DELETE"])
def delete_document_route(document_id):
    if "user_id" not in session:
        return jsonify({"message": "Authentication is required."}), 401

    try:
        delete_document(session["user_id"], document_id)

        return jsonify({
            "message": "Document deleted successfully."
        }), 200

    except (AuthorizationError, FileNotFoundError):
        return jsonify({"message": "Document not found."}), 404

    except Exception:
        return jsonify({"message": "Document deletion failed."}), 500


@document_bp.route("/<int:document_id>", methods=["PATCH"])
def modify_document_metadata_route(document_id):
    if "user_id" not in session:
        return jsonify({"message": "Authentication is required."}), 401

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict) or not payload:
        return jsonify({
            "message": "A non-empty JSON object is required."
        }), 400

    if not set(payload).issubset({"category", "original_filename"}):
        return jsonify({
            "message": "Unsupported document metadata field."
        }), 400

    try:
        modify_document_metadata(
            session["user_id"],
            document_id,
            payload,
        )

        return jsonify({
            "message": "Document metadata updated successfully.",
            "document_id": document_id,
        }), 200

    except ValueError:
        return jsonify({"message": "Invalid document metadata."}), 400

    except AuthorizationError:
        return jsonify({"message": "Document not found."}), 404

    except Exception:
        return jsonify({
            "message": "Document metadata update failed."
        }), 500


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
            start_value,
            end_value,
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
            documents = get_accessible_documents(session["user_id"])

        return jsonify(documents), 200

    except ValueError:
        return "Invalid document search filters.", 400

    except Exception:
        return "Document listing failed.", 500


@document_bp.route("/paginated", methods=["GET"])
def list_documents_paginated():
    if "user_id" not in session:
        return "Authentication is required.", 401

    try:
        filename = request.args.get("filename", "").strip() or None
        owner_name = request.args.get("owner_name", "").strip() or None
        category = request.args.get("category", "").strip() or None

        start_value = request.args.get("start_date", "").strip() or None
        end_value = request.args.get("end_date", "").strip() or None

        start_date, end_date = normalize_document_search_dates(
            start_value,
            end_value,
        )

        limit = int(request.args.get("limit", "20"))

        if limit < 1:
            raise ValueError("Invalid limit.")

        limit = min(limit, 50)

        cursor_token = request.args.get("cursor", "").strip() or None

        cursor_created_at = None
        cursor_document_id = None

        if cursor_token:
            cursor_created_at, cursor_document_id = (
                _decode_document_cursor(cursor_token)
            )

        documents = get_accessible_documents(
            session["user_id"],
            filename=filename,
            owner_name=owner_name,
            category=category,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            cursor_created_at=cursor_created_at,
            cursor_document_id=cursor_document_id,
        )

        has_more = len(documents) > limit
        documents = documents[:limit]

        next_cursor = None

        if has_more and documents:
            next_cursor = _encode_document_cursor(documents[-1])

        return jsonify({
            "documents": documents,
            "has_more": has_more,
            "next_cursor": next_cursor,
            "limit": limit,
        }), 200

    except (ValueError, TypeError):
        return "Invalid document search or pagination parameters.", 400

    except Exception:
        return "Document listing failed.", 500


@document_bp.route("/<int:document_id>/download", methods=["GET"])
def download_document(document_id):
    if "user_id" not in session:
        return "Authentication is required.", 401

    try:
        document = authorize_document(
            session["user_id"],
            document_id,
            "download",
        )

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
            session["user_id"],
            document_id,
            target_user_id,
            permission,
        )

        return {"permission_id": permission_id}, 201

    except ValueError:
        return "Invalid permission.", 400

    except AuthorizationError:
        return "Document not found.", 404

    except Exception:
        return "Permission grant failed.", 500


@document_bp.route(
    "/<int:document_id>/permissions/<int:target_user_id>",
    methods=["DELETE"],
)
def revoke_permission(document_id, target_user_id):
    if "user_id" not in session:
        return "Authentication is required.", 401

    try:
        revoke_document_permission(
            session["user_id"],
            document_id,
            target_user_id,
        )

        return {"message": "Permission revoked."}, 200

    except AuthorizationError:
        return "Document not found.", 404

    except Exception:
        return "Permission revocation failed.", 500


@document_bp.route("/revoke-page", methods=["POST"])
def revoke_document_page():
    if "user_id" not in session:
        return "Please log in first.", 401

    document_id = request.form.get("document_id", type=int)
    target_user_id = request.form.get("target_user_id", type=int)

    if not document_id or not target_user_id:
        return "Please select a document and user.", 400

    try:
        revoke_document_permission(
            session["user_id"],
            document_id,
            target_user_id,
        )

        return "Permission revoked successfully.", 200

    except AuthorizationError:
        return "Document not found or active permission not found.", 403

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
            category,
        )

        return (
            f"Document uploaded successfully. ID: {document_id}",
            201,
        )

    except ValueError as error:
        return str(error), 400

    except Exception:
        return "Document upload failed.", 500


@document_bp.route("/share-page", methods=["GET", "POST"])
def share_document_page():
    if "user_id" not in session:
        return "Please log in first.", 401

    user_id = session["user_id"]

    try:
        documents = get_documents_by_owner(user_id)
        users = get_all_users()

        if request.method == "POST":
            document_id = request.form.get("document_id", type=int)
            target_user_id = request.form.get("target_user_id", type=int)
            permission = request.form.get("permission", "").strip().upper()

            if not document_id or not target_user_id:
                return "Please select a document and user.", 400

            permission_id = grant_document_permission(
                user_id,
                document_id,
                target_user_id,
                permission,
            )

            return (
                f"Permission granted successfully. "
                f"Permission ID: {permission_id}",
                201,
            )

        documents = [
            {
                **document,
                "document_id": document["id"],
            }
            for document in documents
        ]

        users = [
            user for user in users
            if user["id"] != user_id
        ]

        response = render_template(
            "share_document.html",
            documents=documents,
            users=users,
        )

        print(
            "REVOKE FORM PRESENT:",
            "Revoke Access" in response,
        )

        return response

    except ValueError:
        return "Invalid permission or selection.", 400

    except AuthorizationError:
        return "Permission could not be granted.", 403

    except Exception:
        current_app.logger.exception("Document sharing page failed.")
        return "Document sharing page failed.", 500

@document_bp.route("/<int:document_id>/edit", methods=["GET", "POST"])
def edit_document_page(document_id):
    if "user_id" not in session:
        return "Please log in first.", 401

    user_id = session["user_id"]

    try:
        if request.method == "POST":
            original_filename = request.form.get(
                "original_filename", ""
            ).strip()

            category = request.form.get("category", "").strip()

            fields = {
                "original_filename": original_filename,
                "category": category or None,
            }

            modify_document_metadata(user_id, document_id, fields)

            return redirect(url_for("dashboard.user_dashboard"))

        document = authorize_document(
            user_id,
            document_id,
            "modify",
        )

        return render_template(
            "edit_document.html",
            document=document,
        )

    except ValueError:
        return "Invalid document metadata.", 400

    except AuthorizationError:
        return "You are not authorized to edit this document.", 403

    except Exception:
        current_app.logger.exception("Document edit failed.")
        return "Document edit failed.", 500
