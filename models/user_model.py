from config.db import get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash


def create_user(name, email, password, role="viewer"):
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            hashed_password = generate_password_hash(password)

            sql = """
                INSERT INTO users (name, email, password, role)
                VALUES (%s, %s, %s, %s)
            """

            cursor.execute(sql, (name, email, hashed_password, role))

        connection.commit()
        return True

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_user_by_email(email):
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM users WHERE email = %s",
                (email,)
            )
            return cursor.fetchone()
    finally:
        connection.close()