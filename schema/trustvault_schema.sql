-- Clean-install schema for TrustVault (MySQL / InnoDB).
-- Do not run incremental migrations after this file: it already includes the
-- audit origin column and cursor index added by those migrations.

CREATE TABLE users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(320) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'viewer',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE documents (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    owner_id BIGINT UNSIGNED NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    stored_filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(1024) NOT NULL,
    category VARCHAR(100) NULL,
    mime_type VARCHAR(255) NULL,
    file_size BIGINT UNSIGNED NOT NULL,
    checksum CHAR(64) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_documents_stored_filename (stored_filename),
    KEY idx_documents_owner_created (owner_id, created_at),
    CONSTRAINT fk_documents_owner
        FOREIGN KEY (owner_id) REFERENCES users (id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE document_permissions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    document_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    permission ENUM('READ', 'EDIT') NOT NULL,
    granted_by BIGINT UNSIGNED NULL,
    granted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_by BIGINT UNSIGNED NULL,
    revoked_at DATETIME NULL DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_document_permission_subject (document_id, user_id),
    KEY idx_document_permissions_user_revoked (user_id, revoked_at),
    KEY idx_document_permissions_granted_by (granted_by),
    KEY idx_document_permissions_revoked_by (revoked_by),
    CONSTRAINT fk_document_permissions_document
        FOREIGN KEY (document_id) REFERENCES documents (id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_document_permissions_user
        FOREIGN KEY (user_id) REFERENCES users (id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_document_permissions_granted_by
        FOREIGN KEY (granted_by) REFERENCES users (id)
        ON UPDATE RESTRICT ON DELETE SET NULL,
    CONSTRAINT fk_document_permissions_revoked_by
        FOREIGN KEY (revoked_by) REFERENCES users (id)
        ON UPDATE RESTRICT ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE audit_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    occurred_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    occurred_at_origin VARCHAR(24) NOT NULL DEFAULT 'UNKNOWN_LEGACY',
    actor_user_id BIGINT UNSIGNED NULL,
    document_id BIGINT UNSIGNED NULL,
    target_user_id BIGINT UNSIGNED NULL,
    event_type VARCHAR(100) NOT NULL,
    action VARCHAR(32) NOT NULL,
    result VARCHAR(16) NOT NULL,
    details JSON NULL,
    PRIMARY KEY (id),
    KEY idx_audit_occurred_id (occurred_at, id),
    KEY idx_audit_actor_time (actor_user_id, occurred_at),
    KEY idx_audit_document_time (document_id, occurred_at),
    KEY idx_audit_target_user (target_user_id),
    KEY idx_audit_event_type_time (event_type, occurred_at),
    KEY idx_audit_action_time (action, occurred_at),
    KEY idx_audit_result_time (result, occurred_at),
    CONSTRAINT fk_audit_actor
        FOREIGN KEY (actor_user_id) REFERENCES users (id)
        ON UPDATE RESTRICT ON DELETE SET NULL,
    CONSTRAINT fk_audit_document
        FOREIGN KEY (document_id) REFERENCES documents (id)
        ON UPDATE RESTRICT ON DELETE SET NULL,
    CONSTRAINT fk_audit_target_user
        FOREIGN KEY (target_user_id) REFERENCES users (id)
        ON UPDATE RESTRICT ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
