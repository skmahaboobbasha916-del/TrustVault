import json
from datetime import datetime

from config.db import get_db_connection

DOCUMENT_METADATA_FIELDS = frozenset({"category", "original_filename"})


def update_document_metadata(cursor, document_id, fields):
    """Update only allowlisted metadata on the caller's transaction cursor."""
    if not isinstance(fields, dict) or not fields:
        raise ValueError("At least one document metadata field is required.")
    if not set(fields).issubset(DOCUMENT_METADATA_FIELDS):
        raise ValueError("Unsupported document metadata field.")

    # Identifiers come exclusively from this fixed allowlist. Field values and
    # the document ID remain bound parameters.
    ordered_fields = [
        field for field in ("category", "original_filename") if field in fields
    ]
    assignments = ", ".join(f"{field} = %s" for field in ordered_fields)
    values = tuple(fields[field] for field in ordered_fields) + (document_id,)
    cursor.execute(
        f"UPDATE documents SET {assignments} WHERE id = %s",
        values,
    )
    return cursor.rowcount


def create_document(owner_id, original_filename, stored_filename,
                    file_path, category, mime_type, file_size, checksum):

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            sql = """
                INSERT INTO documents (
                    owner_id, original_filename, stored_filename,
                    file_path, category, mime_type, file_size, checksum
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """

            cursor.execute(sql, (
                owner_id, original_filename, stored_filename,
                file_path, category, mime_type, file_size, checksum
            ))

            document_id = cursor.lastrowid

            cursor.execute(
                """
                INSERT INTO audit_events (
                    actor_user_id, document_id, target_user_id,
                    event_type, action, result, details, occurred_at_origin
                )
                VALUES (%s, %s, NULL, %s, %s, %s, NULL, %s)
                """,
                (
                    owner_id,
                    document_id,
                    "DOCUMENT_UPLOADED",
                    "UPLOAD",
                    "SUCCESS",
                    "UTC",
                ),
            )

        connection.commit()
        return document_id

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_documents_by_owner(owner_id):
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM documents WHERE owner_id = %s ORDER BY created_at DESC",
                (owner_id,)
            )
            return cursor.fetchall()

    finally:
        connection.close()


def _literal_substring_pattern(value):
    """Build a LIKE pattern that treats user supplied wildcard characters literally."""
    escaped = str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def get_accessible_documents(user_id, filename=None, owner_name=None,
                             category=None, start_date=None, end_date=None,
                             limit=20, cursor_created_at=None,
                             cursor_document_id=None):
    """Return searchable metadata the current user may view.

    The requester role is read from the database in this query. Admins receive
    listing/view visibility only; other actions still use authorize_document.
    """
    if type(limit) is not int or limit < 1:
        raise ValueError("Limit must be a positive integer.")

    limit = min(limit, 50)
    if (cursor_created_at is None) != (cursor_document_id is None):
        raise ValueError("Both cursor values are required.")

    if cursor_created_at is not None:
        if not isinstance(cursor_created_at, datetime):
            raise ValueError("Cursor timestamp is invalid.")
        if cursor_created_at.tzinfo is not None:
            raise ValueError("Cursor timestamp must be timezone-naive.")
        if type(cursor_document_id) is not int or cursor_document_id < 1:
            raise ValueError("Document cursor ID is invalid.")
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            conditions = [
                "(d.owner_id = requester.id "
                "OR LOWER(requester.role) = 'admin' "
                "OR EXISTS ("
                "SELECT 1 FROM document_permissions AS p "
                "WHERE p.document_id = d.id AND p.user_id = requester.id "
                "AND p.permission IN ('READ', 'EDIT') AND p.revoked_at IS NULL))"
            ]
            params = [user_id]

            if filename:
                conditions.append("LOWER(d.original_filename) LIKE %s ESCAPE '\\\\'")
                params.append(_literal_substring_pattern(filename).lower())
            if owner_name:
                conditions.append("LOWER(owner.name) LIKE %s ESCAPE '\\\\'")
                params.append(_literal_substring_pattern(owner_name).lower())
            if category:
                conditions.append("d.category = %s")
                params.append(category)
            if start_date is not None:
                conditions.append("d.created_at >= %s")
                params.append(start_date)
            if end_date is not None:
                conditions.append("d.created_at < %s")
                params.append(end_date)
            if cursor_created_at is not None:
                conditions.append(
                    "(d.created_at < %s OR "
                    "(d.created_at = %s AND d.id < %s))"
                )
                params.extend((
                    cursor_created_at,
                    cursor_created_at,
                    cursor_document_id
                ))

            sql = """
                SELECT
                    d.id AS document_id,
                    d.owner_id,
                    owner.name AS owner_name,
                    d.original_filename,
                    d.category,
                    d.mime_type,
                    d.file_size,
                    d.created_at,
                    CASE
                        WHEN d.owner_id = requester.id THEN 'OWNER'
                        WHEN LOWER(requester.role) = 'admin' THEN 'ADMIN'
                        ELSE (
                            SELECT p.permission
                            FROM document_permissions AS p
                            WHERE p.document_id = d.id
                              AND p.user_id = requester.id
                              AND p.permission IN ('READ', 'EDIT')
                              AND p.revoked_at IS NULL
                            ORDER BY p.id DESC
                            LIMIT 1
                        )
                    END AS access_level
                FROM documents AS d
                INNER JOIN users AS owner ON owner.id = d.owner_id
                INNER JOIN users AS requester ON requester.id = %s
                WHERE """ + " AND ".join(conditions) + """
                ORDER BY d.created_at DESC, d.id DESC
                LIMIT %s
            """
            params.append(limit + 1)

            cursor.execute(sql, tuple(params))
            return cursor.fetchall()

    finally:
        connection.close()


def delete_document_record(document_id, actor_user_id):
    """Delete one document row and record the deletion in the same transaction."""
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM document_permissions WHERE document_id = %s",
                (document_id,),
            )

            cursor.execute(
                "DELETE FROM documents WHERE id = %s",
                (document_id,),
            )

            if cursor.rowcount != 1:
                raise RuntimeError("Expected exactly one document row to be deleted.")

            cursor.execute(
                """
                INSERT INTO audit_events (
                    actor_user_id, document_id, target_user_id,
                    event_type, action, result, details, occurred_at_origin
                )
                VALUES (%s, NULL, NULL, %s, %s, %s, %s, %s)
                """,
                (
                    actor_user_id,
                    "DOCUMENT_DELETED",
                    "DELETE",
                    "SUCCESS",
                    json.dumps({"document_id": document_id}, separators=(",", ":")),
                    "UTC",
                ),
            )

        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
