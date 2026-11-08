"""One-time administrative account provisioning outside the web application."""

from config.db import get_db_connection


_PROVISIONING_LOCK_NAME = "trustvault_one_time_admin_provisioning"
_PROVISIONING_LOCK_TIMEOUT_SECONDS = 5


class AdminProvisioningError(Exception):
    """Raised when the one-time admin promotion cannot be completed safely."""


def provision_first_admin(email):
    """Promote an existing user only when TrustVault has no admin yet.

    This operation is intended for the local CLI. A MySQL advisory lock
    serializes concurrent invocations, while the target user row, role update,
    and audit insert are handled in one transaction.
    """
    if not isinstance(email, str):
        raise ValueError("A valid email address is required.")
    normalized_email = email.strip().lower()
    if not normalized_email or len(normalized_email) > 320:
        raise ValueError("A valid email address is required.")

    connection = get_db_connection()
    lock_acquired = False
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT GET_LOCK(%s, %s) AS lock_acquired",
                (_PROVISIONING_LOCK_NAME, _PROVISIONING_LOCK_TIMEOUT_SECONDS),
            )
            lock_row = cursor.fetchone()
            lock_acquired = bool(
                lock_row and lock_row.get("lock_acquired") == 1
            )
        if not lock_acquired:
            raise AdminProvisioningError(
                "Admin provisioning is already running; try again later."
            )

        connection.begin()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, role FROM users WHERE email = %s FOR UPDATE",
                (normalized_email,),
            )
            target = cursor.fetchone()
            if target is None:
                raise AdminProvisioningError(
                    "No existing user matches that email address."
                )

            if str(target.get("role", "")).strip().lower() == "admin":
                raise AdminProvisioningError(
                    "The selected user is already an administrator."
                )

            cursor.execute(
                """SELECT id FROM audit_events
                   WHERE event_type = %s AND action = %s AND result = %s
                   LIMIT 1 FOR UPDATE""",
                ("ADMIN_PROVISIONING", "PROMOTE_TO_ADMIN", "SUCCESS"),
            )
            if cursor.fetchone() is not None:
                raise AdminProvisioningError(
                    "One-time admin provisioning has already been used."
                )

            cursor.execute(
                """SELECT id FROM users
                   WHERE LOWER(TRIM(role)) = 'admin'
                   LIMIT 1 FOR UPDATE"""
            )
            if cursor.fetchone() is not None:
                raise AdminProvisioningError(
                    "One-time admin provisioning has already been used."
                )

            cursor.execute(
                "UPDATE users SET role = %s WHERE id = %s",
                ("admin", target["id"]),
            )
            if cursor.rowcount != 1:
                raise AdminProvisioningError(
                    "The selected user could not be promoted."
                )

            cursor.execute(
                """INSERT INTO audit_events
                   (actor_user_id, document_id, target_user_id, event_type,
                    action, result, details, occurred_at_origin)
                   VALUES (NULL, NULL, %s, %s, %s, %s, NULL, %s)""",
                (
                    target["id"],
                    "ADMIN_PROVISIONING",
                    "PROMOTE_TO_ADMIN",
                    "SUCCESS",
                    "UTC",
                ),
            )

        connection.commit()
        return target["id"]
    except Exception:
        connection.rollback()
        raise
    finally:
        try:
            if lock_acquired:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT RELEASE_LOCK(%s)", (_PROVISIONING_LOCK_NAME,)
                    )
        except Exception:
            # Closing this connection also releases any remaining advisory lock.
            pass
        finally:
            connection.close()
