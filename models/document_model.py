import json

from config.db import get_db_connection


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
                    event_type, action, result, details
                )
                VALUES (%s, %s, NULL, %s, %s, %s, NULL)
                """,
                (
                    owner_id,
                    document_id,
                    "DOCUMENT_UPLOADED",
                    "UPLOAD",
                    "SUCCESS",
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


def get_accessible_documents(user_id):
    """Return document metadata for documents owned by or shared with a user."""
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    d.id AS document_id,
                    d.owner_id,
                    d.original_filename,
                    d.category,
                    d.mime_type,
                    d.file_size,
                    d.created_at,
                    'OWNER' AS access_level
                FROM documents AS d
                WHERE d.owner_id = %s

                UNION ALL

                SELECT
                    d.id AS document_id,
                    d.owner_id,
                    d.original_filename,
                    d.category,
                    d.mime_type,
                    d.file_size,
                    d.created_at,
                    p.permission AS access_level
                FROM documents AS d
                INNER JOIN document_permissions AS p
                    ON p.document_id = d.id
                WHERE p.user_id = %s
                  AND p.revoked_at IS NULL
                  AND d.owner_id <> %s
                ORDER BY created_at DESC
                """,
                (user_id, user_id, user_id),
            )
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
                    event_type, action, result, details
                )
                VALUES (%s, NULL, NULL, %s, %s, %s, %s)
                """,
                (
                    actor_user_id,
                    "DOCUMENT_DELETED",
                    "DELETE",
                    "SUCCESS",
                    json.dumps({"document_id": document_id}, separators=(",", ":")),
                ),
            )

        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
