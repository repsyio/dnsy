CREATE TABLE client_certs (
    id         INTEGER PRIMARY KEY,
    sha256     BLOB    NOT NULL UNIQUE CHECK (length(sha256) = 32),
    label      TEXT    NOT NULL CHECK (length(label) BETWEEN 1 AND 128),
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    expires_at INTEGER,
    created_at INTEGER NOT NULL
);
