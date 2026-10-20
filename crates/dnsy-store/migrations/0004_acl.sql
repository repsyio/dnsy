CREATE TABLE acl_rules (
    id          INTEGER PRIMARY KEY,
    kind        TEXT    NOT NULL CHECK (kind IN ('cidr', 'cert')),
    cidr        TEXT,
    cert_sha256 BLOB,
    action      TEXT    NOT NULL CHECK (action IN ('allow', 'refuse', 'drop')),
    comment     TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    CHECK ((kind = 'cidr' AND cidr IS NOT NULL AND cert_sha256 IS NULL)
        OR (kind = 'cert' AND cert_sha256 IS NOT NULL AND length(cert_sha256) = 32 AND cidr IS NULL))
);
CREATE UNIQUE INDEX acl_rules_cidr ON acl_rules(cidr) WHERE kind = 'cidr';
CREATE UNIQUE INDEX acl_rules_cert ON acl_rules(cert_sha256) WHERE kind = 'cert';

CREATE TABLE rate_limits (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    qps        INTEGER NOT NULL CHECK (qps >= 0),
    updated_at INTEGER NOT NULL
);
