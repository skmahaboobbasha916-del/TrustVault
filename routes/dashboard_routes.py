
from flask import Blueprint, render_template, request, session, redirect, url_for

from models.document_model import get_accessible_documents
from controllers.document_controller import normalize_document_search_dates
from services.authorization_service import get_current_user

from routes.document_routes import (
    _encode_document_cursor,
    _decode_document_cursor,
)

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard", methods=["GET"])
def user_dashboard():
    user_id = session.get("user_id")

    if not user_id:
        return redirect(url_for("auth.login"))

    try:
        user = get_current_user(user_id)

        if not user:
            session.clear()
            return redirect(url_for("auth.login"))

        if user.get("role", "").lower() == "admin":
            return redirect("/admin/audit")

        filename = request.args.get("filename", "").strip() or None
        owner_name = request.args.get("owner_name", "").strip() or None
        category = request.args.get("category", "").strip() or None

        start_value = request.args.get("start_date", "").strip() or None
        end_value = request.args.get("end_date", "").strip() or None

        start_date, end_date = normalize_document_search_dates(
            start_value, end_value
        )

        limit = min(max(int(request.args.get("limit", "20")), 1), 50)

        cursor_token = request.args.get("cursor", "").strip() or None
        cursor_created_at = None
        cursor_document_id = None

        if cursor_token:
            cursor_created_at, cursor_document_id = (
                _decode_document_cursor(cursor_token)
            )

        documents = get_accessible_documents(
            user_id,
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

        return render_template(
            "dashboard.html",
            user=user,
            documents=documents,
            next_cursor=next_cursor,
            has_more=has_more,
            filters={
                "filename": filename or "",
                "owner_name": owner_name or "",
                "category": category or "",
                "start_date": start_value or "",
                "end_date": end_value or "",
                "limit": limit,
            },
        )

    except (ValueError, TypeError):
        return "Invalid search or pagination parameters.", 400

    except Exception:
        return "Dashboard could not be loaded.", 500
