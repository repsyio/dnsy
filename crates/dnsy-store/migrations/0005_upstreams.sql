CREATE TABLE upstream_groups (
    name       TEXT    PRIMARY KEY,
    strategy   TEXT    NOT NULL CHECK (strategy IN ('round_robin', 'weighted', 'lowest_latency', 'failover')),
    is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
    domains    TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX upstream_groups_default ON upstream_groups(is_default) WHERE is_default = 1;

CREATE TABLE upstreams (
    id         INTEGER PRIMARY KEY,
    group_name TEXT    NOT NULL REFERENCES upstream_groups(name) ON DELETE CASCADE,
    url        TEXT    NOT NULL,
    weight     INTEGER NOT NULL DEFAULT 1 CHECK (weight >= 1),
    position   INTEGER NOT NULL,
    UNIQUE (group_name, url),
    UNIQUE (group_name, position)
);
