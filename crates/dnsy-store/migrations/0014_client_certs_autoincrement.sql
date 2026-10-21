-- Ids must never be reused after a delete: audit and log references stay unambiguous.
CREATE TABLE client_certs_new (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256     BLOB    NOT NULL UNIQUE CHECK (length(sha256) = 32),
    label      TEXT    NOT NULL CHECK (length(label) BETWEEN 1 AND 128),
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    expires_at INTEGER,
    created_at INTEGER NOT NULL
);
INSERT INTO client_certs_new (id, sha256, label, enabled, expires_at, created_at)
    SELECT id, sha256, label, enabled, expires_at, created_at FROM client_certs;
DROP TABLE client_certs;
ALTER TABLE client_certs_new RENAME TO client_certs;
