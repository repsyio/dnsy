-- Query log, per-minute rollups and per-hour top-N rollups (DNSY-10).
CREATE TABLE query_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms         INTEGER NOT NULL,
    client        TEXT    NOT NULL,
    transport     TEXT    NOT NULL,
    principal     TEXT,
    qname         TEXT    NOT NULL,
    qtype         INTEGER NOT NULL,
    rcode         INTEGER NOT NULL,
    source        TEXT    NOT NULL,
    source_detail TEXT,
    dnssec        TEXT    NOT NULL,
    latency_us    INTEGER NOT NULL
);
CREATE INDEX query_log_ts ON query_log (ts_ms, id);

-- dimension is one of total, rcode, source, dnssec; key is '' for total.
CREATE TABLE stats_minute (
    minute         INTEGER NOT NULL,
    dimension      TEXT    NOT NULL,
    key            TEXT    NOT NULL,
    count          INTEGER NOT NULL,
    latency_sum_us INTEGER NOT NULL,
    latency_max_us INTEGER NOT NULL,
    PRIMARY KEY (minute, dimension, key)
) WITHOUT ROWID;

-- kind is one of qname, blocked, client.
CREATE TABLE stats_top_hour (
    hour  INTEGER NOT NULL,
    kind  TEXT    NOT NULL,
    key   TEXT    NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (hour, kind, key)
) WITHOUT ROWID;
