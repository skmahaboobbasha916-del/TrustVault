from datetime import date, datetime, timedelta
import hashlib
import hmac
import json

from flask import (
    Blueprint,
    current_app,
    jsonify,
    render_template,
    request,
    session,
)
from itsdangerous import BadSignature, URLSafeTimedSerializer

from models.audit_model import AUDIT_EVENT_FIELDS, list_audit_events
from services.authorization_service import get_current_user


admin_bp = Blueprint("admin", __name__)
admin_dashboard_bp = Blueprint("admin_dashboard", __name__)
_MAX_PAGE_SIZE = 100
_CURSOR_MAX_AGE_SECONDS = 3600
_CURSOR_SALT = "trustvault-admin-audit-cursor-v1"
_CURSOR_VERSION = 2
_AUDIT_REASONS = {
    "authentication_required",
    "document_not_found",
    "insufficient_permission",
    "owner_required",
    "target_user_not_found",
    "active_grant_not_found",
    "owner_cannot_grant_permission_to_self",
}


def _optional_text_filter(name):
    value = request.args.get(name, "").strip()
    return value or None


def _parse_positive_integer(name, default, maximum=None):
    raw_value = request.args.get(name)
    if raw_value is None:
        return default
    if not raw_value.isdecimal():
        raise ValueError(f"Invalid {name}.")
    value = int(raw_value)
    if value <= 0:
        raise ValueError(f"Invalid {name}.")
    return min(value, maximum) if maximum is not None else value


def _filter_fingerprint(event_type, action, result, actor_user_id,
                        start_date, end_date):
    filters = {
        "event_type": event_type,
        "action": action,
        "result": result,
        "actor_user_id": actor_user_id,
        "start_date": start_date.isoformat() if start_date is not None else None,
        "end_date": end_date.isoformat() if end_date is not None else None,
    }
    canonical = json.dumps(filters, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _cursor_serializer():
    secret_key = current_app.secret_key
    if not secret_key:
        raise RuntimeError("Flask secret key is not configured.")
    return URLSafeTimedSerializer(secret_key, salt=_CURSOR_SALT)


def _encode_cursor(row, filter_fingerprint):
    timestamp = row.get("occurred_at")
    cursor_id = row.get("id")
    if (not isinstance(timestamp, datetime) or timestamp.tzinfo is not None
            or type(cursor_id) is not int or cursor_id < 1):
        raise RuntimeError("Audit row cannot be used as a pagination cursor.")
    return _cursor_serializer().dumps({
        "version": _CURSOR_VERSION,
        "occurred_at": timestamp.isoformat(timespec="microseconds"),
        "id": cursor_id,
        "filters": filter_fingerprint,
    })


def _decode_cursor(token, filter_fingerprint):
    if len(token) > 2048:
        raise ValueError("Invalid cursor.")
    try:
        payload = _cursor_serializer().loads(
            token, max_age=_CURSOR_MAX_AGE_SECONDS
        )
    except BadSignature as error:
        raise ValueError("Invalid cursor.") from error

    if not isinstance(payload, dict):
        raise ValueError("Invalid cursor.")
    timestamp_text = payload.get("occurred_at")
    cursor_id = payload.get("id")
    token_fingerprint = payload.get("filters")
    if (payload.get("version") != _CURSOR_VERSION
            or not isinstance(timestamp_text, str)
            or type(cursor_id) is not int or cursor_id < 1
            or not isinstance(token_fingerprint, str)
            or not hmac.compare_digest(token_fingerprint, filter_fingerprint)):
        raise ValueError("Invalid cursor.")
    try:
        timestamp = datetime.fromisoformat(timestamp_text)
    except ValueError as error:
        raise ValueError("Invalid cursor.") from error
    if (timestamp.tzinfo is not None
            or timestamp.isoformat(timespec="microseconds") != timestamp_text):
        raise ValueError("Invalid cursor.")
    return timestamp, cursor_id


def _serialize_audit_timestamp(timestamp, origin):
    """Serialize UTC values with an offset and unknown legacy values as-is."""
    if not isinstance(timestamp, datetime) or timestamp.tzinfo is not None:
        raise RuntimeError("Audit timestamp is invalid.")
    serialized = timestamp.isoformat(timespec="microseconds")
    if origin == "UTC":
        return serialized + "Z"
    if origin == "UNKNOWN_LEGACY":
        return serialized
    raise RuntimeError("Audit timestamp origin is invalid.")


def _parse_date(name):
    value = request.args.get(name, "").strip()
    if not value:
        return None
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"Invalid {name}.") from error
    if parsed.isoformat() != value:
        raise ValueError(f"Invalid {name}.")
    return parsed


def _safe_audit_details(value):
    """Expose only detail keys currently written by TrustVault audit helpers."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return None
    if not isinstance(value, dict):
        return None
    safe_details = {}
    reason = value.get("reason")
    if isinstance(reason, str) and reason in _AUDIT_REASONS:
        safe_details["reason"] = reason
    permission = value.get("permission")
    if isinstance(permission, str) and permission.upper() in {"READ", "EDIT"}:
        safe_details["permission"] = permission.upper()
    for key in ("requested_document_id", "document_id"):
        identifier = value.get(key)
        if type(identifier) is int and identifier > 0:
            safe_details[key] = identifier
    return safe_details


def _require_current_admin():
    if "user_id" not in session:
        return None, (401, "Authentication is required.")

    user = get_current_user(session["user_id"])
    if user is None:
        return None, (401, "Authentication is required.")
    if str(user.get("role", "")).strip().lower() != "admin":
        return None, (403, "Administrator access is required.")
    return user, None


def _audit_page_from_request_args(args):
    event_type = _optional_text_filter("event_type")
    action = _optional_text_filter("action")
    result = _optional_text_filter("result")
    raw_actor_user_id = args.get("actor_user_id")
    actor_user_id = None
    if raw_actor_user_id is not None:
        if not raw_actor_user_id.isdecimal() or int(raw_actor_user_id) <= 0:
            raise ValueError("Invalid actor_user_id.")
        actor_user_id = int(raw_actor_user_id)

    start_date = _parse_date("start_date")
    end_date = _parse_date("end_date")
    if start_date is not None and end_date is not None and start_date > end_date:
        raise ValueError("Invalid date range.")
    try:
        end_exclusive = (
            end_date + timedelta(days=1) if end_date is not None else None
        )
    except OverflowError as error:
        raise ValueError("Invalid date range.") from error

    if "offset" in args:
        raise ValueError("Offset pagination is no longer supported.")
    limit = _parse_positive_integer("limit", 20, _MAX_PAGE_SIZE)
    filter_fingerprint = _filter_fingerprint(
        event_type, action, result, actor_user_id, start_date, end_date
    )
    cursor_token = args.get("cursor")
    cursor_timestamp = cursor_id = None
    if cursor_token:
        cursor_timestamp, cursor_id = _decode_cursor(
            cursor_token, filter_fingerprint
        )
    elif "cursor" in args:
        raise ValueError("Invalid cursor.")

    rows = list_audit_events(
        event_type=event_type,
        action=action,
        result=result,
        actor_user_id=actor_user_id,
        start_date=start_date,
        end_date=end_exclusive,
        limit=limit,
        cursor_timestamp=cursor_timestamp,
        cursor_id=cursor_id,
    )

    # Enforce the response allowlist as well as the model SELECT list.
    has_more = len(rows) > limit
    page_rows = rows[:limit]
    items = []
    for row in page_rows:
        item = {field: row.get(field) for field in AUDIT_EVENT_FIELDS}
        item["occurred_at"] = _serialize_audit_timestamp(
            item["occurred_at"], item["occurred_at_origin"]
        )
        item["details"] = _safe_audit_details(item["details"])
        items.append(item)
    next_cursor = (
        _encode_cursor(page_rows[-1], filter_fingerprint)
        if has_more and page_rows else None
    )
    filters = {
        "event_type": event_type or "",
        "action": action or "",
        "result": result or "",
        "actor_user_id": str(actor_user_id) if actor_user_id is not None else "",
        "start_date": start_date.isoformat() if start_date is not None else "",
        "end_date": end_date.isoformat() if end_date is not None else "",
    }
    return {
        "items": items,
        "limit": limit,
        "next_cursor": next_cursor,
    }, filters


def _dashboard_request_args():
    """Normalize an empty HTML number control without changing API semantics."""
    args = request.args.copy()
    if args.get("actor_user_id") == "":
        args.pop("actor_user_id", None)
    return args


@admin_bp.route("/audit-events", methods=["GET"])
def admin_audit_events():
    try:
        # Use the current database role; session['role'] is intentionally ignored.
        _, auth_error = _require_current_admin()
        if auth_error:
            status, message = auth_error
            return jsonify({"message": message}), status

        page, _ = _audit_page_from_request_args(request.args)
        return jsonify({
            "items": page["items"],
            "limit": page["limit"],
            "next_cursor": page["next_cursor"],
        }), 200
    except ValueError:
        return jsonify({"message": "Invalid audit query filters."}), 400
    except Exception:
        return jsonify({"message": "Audit records could not be retrieved."}), 500


@admin_dashboard_bp.after_request
def prevent_dashboard_caching(response):
    response.headers["Cache-Control"] = "no-store"
    return response


@admin_dashboard_bp.route("/admin/audit", methods=["GET"])
def admin_audit_dashboard():
    try:
        _, auth_error = _require_current_admin()
        if auth_error:
            _, message = auth_error
            return message, auth_error[0]
        page, filters = _audit_page_from_request_args(_dashboard_request_args())
        return render_template(
            "admin_audit.html",
            items=page["items"],
            limit=page["limit"],
            next_cursor=page["next_cursor"],
            filters=filters,
        ), 200
    except ValueError:
        return "Invalid audit query filters.", 400
    except Exception:
        return "Audit records could not be retrieved.", 500
