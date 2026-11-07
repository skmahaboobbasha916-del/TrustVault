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