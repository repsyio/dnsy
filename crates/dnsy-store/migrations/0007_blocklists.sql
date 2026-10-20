CREATE TABLE blocklists (
    id            INTEGER PRIMARY KEY,
    name          TEXT    NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 128),
    location      TEXT    NOT NULL UNIQUE CHECK (length(location) BETWEEN 1 AND 2048),
    format        TEXT    NOT NULL DEFAULT 'auto' CHECK (format IN ('auto', 'hosts', 'domains', 'adblock')),
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    interval_secs INTEGER NOT NULL CHECK (interval_secs >= 1),
    allow_private INTEGER NOT NULL DEFAULT 0 CHECK (allow_private IN (0, 1)),
    etag          TEXT,
    last_modified TEXT,
    last_fetched  INTEGER,
    last_status   TEXT,
    entries       INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
);

CREATE TABLE custom_rules (
    id         INTEGER PRIMARY KEY,
    kind       TEXT    NOT NULL CHECK (kind IN ('block', 'allow')),
    domain     TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (kind, domain)
);
