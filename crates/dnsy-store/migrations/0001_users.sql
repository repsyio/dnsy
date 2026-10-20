CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL COLLATE NOCASE UNIQUE,
    role          TEXT    NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    password_hash TEXT    NOT NULL,
    created_at    INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at    INTEGER NOT NULL DEFAULT (unixepoch())
);
