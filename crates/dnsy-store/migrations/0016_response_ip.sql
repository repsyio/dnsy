CREATE TABLE response_ip_policy (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    cidrs      TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
);
