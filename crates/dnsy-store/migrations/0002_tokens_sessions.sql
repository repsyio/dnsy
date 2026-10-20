CREATE TABLE api_tokens (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT    NOT NULL,
    scopes        TEXT    NOT NULL,
    secret_sha256 BLOB    NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER,
    last_used_at  INTEGER,
    revoked_at    INTEGER
);
CREATE INDEX api_tokens_user ON api_tokens(user_id);

CREATE TABLE sessions (
    id_sha256    BLOB    PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE login_attempts (
    id       INTEGER PRIMARY KEY,
    username TEXT    NOT NULL COLLATE NOCASE,
    ip       TEXT    NOT NULL,
    at       INTEGER NOT NULL
);
CREATE INDEX login_attempts_key ON login_attempts(username, ip, at);
