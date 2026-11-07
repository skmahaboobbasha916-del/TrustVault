from flask import Blueprint, request, session, render_template
from controllers.document_controller import upload_document

document_bp = Blueprint("documents", __name__)

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