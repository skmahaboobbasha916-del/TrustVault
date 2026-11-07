"""MySQL-backed authorization and audit helpers for TrustVault documents.

The caller must pass the user ID from Flask's authenticated session. This
module loads the user's current role and permissions from MySQL for each
authorization decision; it does not accept a role from the caller.
"""

import json

from config.db import get_db_connection


class AuthorizationError(Exception):
    """Raised when a document action is not authorized."""


class AuthenticationRequired(AuthorizationError):
    """Raised when the session user ID does not identify a current user."""


_ACTIONS = {"view", "download", "modify", "delete", "grant", "revoke"}
_READ_ACTIONS = {"view", "download"}
_EDIT_ACTIONS = {"view", "download", "modify"}


def _audit(cursor, actor_user_id, document_id, target_user_id,
           event_type, action, result, details=None):
    """Insert one audit row using only values accepted by the supplied schema."""
    cursor.execute(
        """INSERT INTO audit_events
           (actor_user_id, document_id, target_user_id, event_type,
            action, result, details)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (
            actor_user_id,
            document_id,
            target_user_id,
            event_type,
            action,
            result,
            json.dumps(details, separators=(",", ":")) if details is not None else None,
        ),
    )


def _audit_access(cursor, user, document_id, action, result, reason=None):
    details = {"reason": reason} if reason else None
    _audit(
        cursor,
        user["id"] if user else None,
        document_id,
        None,
        "ACCESS_ATTEMPT",
        action.upper(),
        result,
        details,
    )


def get_current_user(session_user_id):
    """Fetch the current user and role using only the authenticated session ID.

    Returns a user dictionary without the password hash, or None if the ID is
    absent or no longer exists. Never pass a form-supplied ID to this function.
    """
    if session_user_id is None:
        return None

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, name, email, role FROM users WHERE id = %s",
                (session_user_id,),
            )
            return cursor.fetchone()
    finally:
        connection.close()


def authorize_document(session_user_id, document_id, action):
    """Authorize an action, audit its outcome, and return the document row.

    Supported actions: view, download, modify, delete, grant, revoke.
    Owners have full control. Active READ and EDIT grants apply as documented;
    admins may view but receive no implicit download, edit, or delete rights.
    Every call reads the current user, document, and active grant from MySQL.

    Raises AuthenticationRequired or AuthorizationError on denial. Audit
    insertion is part of the same transaction; an audit write failure therefore
    fails closed rather than allowing an unrecorded operation.
    """
    normalized_action = str(action).strip().lower() if action is not None else ""
    if normalized_action not in _ACTIONS:
        raise ValueError("Unsupported document action.")

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            user = None
            if session_user_id is not None:
                cursor.execute(
                    "SELECT id, name, email, role FROM users WHERE id = %s",
                    (session_user_id,),
                )
                user = cursor.fetchone()

            if user is None:
                _audit_access(cursor, None, None, normalized_action, "DENIED",
                              "authentication_required")
                connection.commit()
                raise AuthenticationRequired("Authentication is required.")

            cursor.execute(
                "SELECT * FROM documents WHERE id = %s",
                (document_id,),
            )
            document = cursor.fetchone()

            if document is None:
                # Keep the attempted ID in details, since a missing document
                # cannot satisfy an audit_events document foreign key.
                _audit(
                    cursor, user["id"], None, None, "ACCESS_ATTEMPT",
                    normalized_action.upper(), "DENIED",
                    {"reason": "document_not_found", "requested_document_id": document_id},
                )
                connection.commit()
                raise AuthorizationError("Document not found or access denied.")

            is_owner = document["owner_id"] == user["id"]
            is_admin = str(user.get("role", "")).strip().lower() == "admin"
            permission = None

            if not is_owner and not is_admin:
                cursor.execute(
                    """SELECT permission FROM document_permissions
                       WHERE document_id = %s AND user_id = %s
                         AND revoked_at IS NULL
                       LIMIT 1""",
                    (document["id"], user["id"]),
                )
                permission_row = cursor.fetchone()
                if permission_row:
                    permission = str(permission_row["permission"]).upper()

            allowed = False
            if is_owner:
                allowed = True
            elif is_admin:
                allowed = normalized_action == "view"
            elif permission == "EDIT":
                allowed = normalized_action in _EDIT_ACTIONS
            elif permission == "READ":
                allowed = normalized_action in _READ_ACTIONS

            _audit_access(
                cursor,
                user,
                document["id"],
                normalized_action,
                "SUCCESS" if allowed else "DENIED",
                None if allowed else "insufficient_permission",
            )
            connection.commit()

            if not allowed:
                raise AuthorizationError("Document not found or access denied.")
            return document
    except (AuthenticationRequired, AuthorizationError):
        # The denial audit was committed before raising.
        raise
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def grant_document_permission(session_user_id, document_id,
                               target_user_id, permission):
    """Grant READ or EDIT access; only the current document owner may grant.

    Returns the current permission-row ID. Grant changes and their audit event
    are committed atomically. Regranting a revoked row reactivates it.
    """
    permission = str(permission).strip().upper() if permission is not None else ""
    if permission not in {"READ", "EDIT"}:
        raise ValueError("Permission must be READ or EDIT.")

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            actor = _fetch_user(cursor, session_user_id)
            document = _fetch_document(cursor, document_id)
            if actor is None or document is None or document["owner_id"] != actor["id"]:
                _audit_access(cursor, actor, document["id"] if document else None,
                              "grant", "DENIED", "owner_required")
                connection.commit()
                raise AuthorizationError("Document not found or access denied.")

            cursor.execute("SELECT id FROM users WHERE id = %s", (target_user_id,))
            target = cursor.fetchone()
            if target is None:
                _audit_access(cursor, actor, document["id"], "grant", "DENIED",
                              "target_user_not_found")
                connection.commit()
                raise AuthorizationError("Target user not found.")

            if target["id"] == actor["id"]:
                _audit(cursor, actor["id"], document["id"], target["id"],
                       "PERMISSION_GRANT_ATTEMPT", "GRANT", "DENIED",
                       {"reason": "owner_cannot_grant_permission_to_self"})
                connection.commit()
                raise AuthorizationError("Document owners cannot grant permissions to themselves.")

            cursor.execute(
                """SELECT id FROM document_permissions
                   WHERE document_id = %s AND user_id = %s FOR UPDATE""",
                (document["id"], target["id"]),
            )
            existing = cursor.fetchone()
            if existing:
                cursor.execute(
                    """UPDATE document_permissions
                       SET permission = %s, granted_by = %s,
                           granted_at = CURRENT_TIMESTAMP,
                           revoked_by = NULL, revoked_at = NULL
                       WHERE id = %s""",
                    (permission, actor["id"], existing["id"]),
                )
                permission_id = existing["id"]
            else:
                cursor.execute(
                    """INSERT INTO document_permissions
                       (document_id, user_id, permission, granted_by, granted_at)
                       VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)""",
                    (document["id"], target["id"], permission, actor["id"]),
                )
                permission_id = cursor.lastrowid

            _audit(cursor, actor["id"], document["id"], target["id"],
                   "PERMISSION_GRANTED", "GRANT", "SUCCESS",
                   {"permission": permission})
        connection.commit()
        return permission_id
    except (AuthorizationError, ValueError):
        raise
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def revoke_document_permission(session_user_id, document_id, target_user_id):
    """Revoke a user's active grant; only the current owner may revoke it."""
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            actor = _fetch_user(cursor, session_user_id)
            document = _fetch_document(cursor, document_id)
            if actor is None or document is None or document["owner_id"] != actor["id"]:
                _audit_access(cursor, actor, document["id"] if document else None,
                              "revoke", "DENIED", "owner_required")
                connection.commit()
                raise AuthorizationError("Document not found or access denied.")

            cursor.execute(
                """UPDATE document_permissions
                   SET revoked_by = %s, revoked_at = CURRENT_TIMESTAMP
                   WHERE document_id = %s AND user_id = %s
                     AND revoked_at IS NULL""",
                (actor["id"], document["id"], target_user_id),
            )
            revoked = cursor.rowcount > 0
            if not revoked:
                _audit_access(cursor, actor, document["id"], "revoke", "DENIED",
                              "active_grant_not_found")
                connection.commit()
                raise AuthorizationError("Active permission not found.")

            _audit(cursor, actor["id"], document["id"], target_user_id,
                   "PERMISSION_REVOKED", "REVOKE", "SUCCESS")
        connection.commit()
        return True
    except AuthorizationError:
        raise
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _fetch_user(cursor, user_id):
    if user_id is None:
        return None
    cursor.execute(
        "SELECT id, name, email, role FROM users WHERE id = %s",
        (user_id,),
    )
    return cursor.fetchone()


def _fetch_document(cursor, document_id):
    cursor.execute("SELECT * FROM documents WHERE id = %s", (document_id,))
    return cursor.fetchone()
