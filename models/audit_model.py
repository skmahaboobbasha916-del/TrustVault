from datetime import datetime

from config.db import get_db_connection


AUDIT_EVENT_FIELDS = (
    "id",
    "occurred_at",
    "occurred_at_origin",
    "actor_user_id",
    "document_id",
    "target_user_id",
    "event_type",
    "action",
    "result",
    "details",
)


def list_audit_events(event_type=None, action=None, result=None,
                      actor_user_id=None, start_date=None, end_date=None,
                      limit=20, cursor_timestamp=None, cursor_id=None):
    """Fetch audit metadata ordered by stored timestamp value, then ID.

    DATETIME values with different provenance are comparable as stored values,
    but the order does not establish real-world chronology across origins.
    """
    if type(limit) is not int or limit < 1:
        raise ValueError("Limit must be a positive integer.")
    if (cursor_timestamp is None) != (cursor_id is None):
        raise ValueError("Both cursor values are required.")
    if cursor_timestamp is not None:
        if not isinstance(cursor_timestamp, datetime):
            raise ValueError("Cursor timestamp is invalid.")
        if cursor_timestamp.tzinfo is not None:
            raise ValueError("Cursor timestamp must be timezone-naive.")
        if type(cursor_id) is not int or cursor_id < 1:
            raise ValueError("Cursor ID is invalid.")
    limit = min(limit, 100)

    conditions = []
    params = []

    for column, value in (
        ("event_type", event_type),
        ("action", action),
        ("result", result),
        ("actor_user_id", actor_user_id),
    ):
        if value is not None:
            conditions.append(f"{column} = %s")
            params.append(value)
    if start_date is not None:
        conditions.append("occurred_at >= %s")
        params.append(start_date)
    if end_date is not None:
        conditions.append("occurred_at < %s")
        params.append(end_date)
    if cursor_timestamp is not None:
        conditions.append(
            "(occurred_at < %s OR (occurred_at = %s AND id < %s))"
        )
        params.extend((cursor_timestamp, cursor_timestamp, cursor_id))

    selected_fields = ", ".join(AUDIT_EVENT_FIELDS)
    where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""
    sql = (
        f"SELECT {selected_fields} FROM audit_events{where_clause} "
        "ORDER BY occurred_at DESC, id DESC LIMIT %s"
    )
    # One extra row lets the route determine whether a subsequent page exists.
    params.append(limit + 1)

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(sql, tuple(params))
            return cursor.fetchall()
    finally:
        connection.close()
