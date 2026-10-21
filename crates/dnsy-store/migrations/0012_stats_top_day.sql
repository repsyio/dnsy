-- Daily top-N rollup (DNSY-87): the top 5000 keys per (day, kind), folded from stats_top_hour by
-- the hourly retention task. day is the unix-second start of a UTC day; kind is qname, blocked
-- or client.
CREATE TABLE stats_top_day (
    day   INTEGER NOT NULL,
    kind  TEXT    NOT NULL,
    key   TEXT    NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (day, kind, key)
) WITHOUT ROWID;
